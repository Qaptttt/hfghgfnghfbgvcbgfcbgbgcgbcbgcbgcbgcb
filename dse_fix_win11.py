"""
dse_fix_win11.py  —  DSE disabler via RTCore64 BYOVD (CVE-2019-16098)
Windows 10 1903 – 11 24H2, all builds.

Usage:
  dse_fix_win11.exe           interactive: disable DSE, wait ENTER, restore
  dse_fix_win11.exe -off      silent: disable DSE, save state to %%TEMP%%
  dse_fix_win11.exe -on       silent: restore DSE from saved state
"""

import ctypes, ctypes.wintypes, sys, os, struct, tempfile, time, subprocess

# ── Windows API setup ────────────────────────────────────────────────────────

k32   = ctypes.windll.kernel32
adv   = ctypes.windll.advapi32
ntdll = ctypes.windll.ntdll

INVALID_HANDLE      = ctypes.wintypes.HANDLE(-1).value
GENERIC_READ_WRITE  = 0xC0000000
OPEN_EXISTING       = 3
CREATE_ALWAYS       = 2
FILE_ATTRIBUTE_NORMAL  = 0x80
FILE_ATTRIBUTE_HIDDEN  = 0x02
SC_MANAGER_ALL_ACCESS  = 0xF003F
SERVICE_ALL_ACCESS     = 0xF01FF
SERVICE_KERNEL_DRIVER  = 1
SERVICE_DEMAND_START   = 3
SERVICE_ERROR_IGNORE   = 0
SERVICE_CONTROL_STOP   = 1
IOCTL_RT_READ          = 0x80002048
IOCTL_RT_WRITE         = 0x8000204C
STATUS_INFO_LENGTH_MISMATCH = 0xC0000004

# ── Test-signing BCD check + clear ───────────────────────────────────────────

def is_testsigning_on():
    try:
        r = subprocess.run(
            ["bcdedit", "/enum", "current"],
            capture_output=True, text=True, timeout=8
        )
        for line in r.stdout.splitlines():
            if "testsigning" in line.lower() and "yes" in line.lower():
                return True
    except Exception:
        pass
    return False

def clear_testsigning():
    """Disable test-signing BCD flag. Takes effect after next reboot."""
    for flag in ("testsigning", "nointegritychecks"):
        subprocess.run(
            ["bcdedit", "/set", flag, "off"],
            capture_output=True, timeout=8
        )

# ── RTCore64.sys location ────────────────────────────────────────────────────

RTCORE_SEARCH_PATHS = [
    r"C:\Program Files (x86)\MSI Afterburner\Legacy\RTCore64.sys",
    r"C:\Program Files (x86)\MSI Afterburner\RTCore64.sys",
    r"C:\Program Files\MSI Afterburner\Legacy\RTCore64.sys",
    r"C:\Program Files\MSI Afterburner\RTCore64.sys",
]

def get_rtcore_bytes():
    if getattr(sys, "frozen", False):
        p = os.path.join(sys._MEIPASS, "RTCore64.sys")
        if os.path.exists(p):
            return open(p, "rb").read()
    for p in RTCORE_SEARCH_PATHS:
        if os.path.exists(p):
            print(f"[*] RTCore64.sys: {p}")
            return open(p, "rb").read()
    print("[!] RTCore64.sys not found.")
    print("    Install MSI Afterburner or place RTCore64.sys in:")
    print("    C:\\Program Files (x86)\\MSI Afterburner\\Legacy\\")
    return None

# ── Driver drop / SCM load ───────────────────────────────────────────────────

g_sys_path = None
g_hScm = g_hSvc = None
g_hDev = INVALID_HANDLE
g_own_svc = False
SVC_NAME = "RTCore64"

def _kill_stale_service():
    try:
        hscm = adv.OpenSCManagerW(None, None, SC_MANAGER_ALL_ACCESS)
        if not hscm: return
        hsvc = adv.OpenServiceW(hscm, SVC_NAME, SERVICE_ALL_ACCESS)
        if hsvc:
            ss = (ctypes.c_byte * 28)()
            adv.ControlService(hsvc, SERVICE_CONTROL_STOP, ss)
            time.sleep(0.6)
            adv.DeleteService(hsvc)
            adv.CloseServiceHandle(hsvc)
        adv.CloseServiceHandle(hscm)
    except Exception:
        pass

def drop_driver(data):
    global g_sys_path
    _kill_stale_service()
    candidates = [
        os.path.join(tempfile.gettempdir(), "hwinfo_helper.sys"),
        os.path.join(os.environ.get("LOCALAPPDATA", tempfile.gettempdir()), "hwinfo_helper.sys"),
    ]
    for path in candidates:
        try:
            if os.path.exists(path): os.remove(path)
        except Exception: pass
        try:
            with open(path, "wb") as f: f.write(data)
            g_sys_path = path
            return path
        except PermissionError:
            continue
    raise OSError("Cannot write driver to temp — run as Admin.")

def _disable_hvci_bcdedit():
    """Apply bcdedit flags to turn off HVCI/VBS. Takes effect after next reboot."""
    for flag, val in [("hypervisorlaunchtype", "off"), ("vsmlaunchtype", "off")]:
        subprocess.run(["bcdedit", "/set", flag, val],
                       capture_output=True, timeout=8)

def _is_hvci_blocking():
    """
    Check registry to see if Memory Integrity / VBS is configured on.
    Returns True if HVCI is likely why the driver load failed.
    """
    import winreg
    keys = [
        (r"SYSTEM\CurrentControlSet\Control\DeviceGuard", "EnableVirtualizationBasedSecurity"),
        (r"SYSTEM\CurrentControlSet\Control\DeviceGuard", "HypervisorEnforcedCodeIntegrity"),
    ]
    for path, name in keys:
        try:
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, path) as k:
                val, _ = winreg.QueryValueEx(k, name)
                if val: return True
        except Exception:
            pass
    return False

def load_driver(sys_path):
    global g_hScm, g_hSvc, g_hDev, g_own_svc
    g_hScm = adv.OpenSCManagerW(None, None, SC_MANAGER_ALL_ACCESS)
    if not g_hScm:
        raise OSError(f"OpenSCManager failed: {ctypes.GetLastError()}")
    g_hSvc = adv.OpenServiceW(g_hScm, SVC_NAME, SERVICE_ALL_ACCESS)
    if not g_hSvc:
        g_hSvc = adv.CreateServiceW(
            g_hScm, SVC_NAME, SVC_NAME, SERVICE_ALL_ACCESS,
            SERVICE_KERNEL_DRIVER, SERVICE_DEMAND_START, SERVICE_ERROR_IGNORE,
            sys_path, None, None, None, None, None)
        if not g_hSvc:
            raise OSError(f"CreateService failed: {ctypes.GetLastError()}")
        g_own_svc = True
    ret = adv.StartServiceW(g_hSvc, 0, None)
    if not ret:
        e = ctypes.GetLastError()
        if e == 1056:   # ERROR_SERVICE_ALREADY_RUNNING
            pass
        elif e in (5, 1275, 577):
            # 5   = ERROR_ACCESS_DENIED        → WDAC/HVCI blocking load
            # 1275= ERROR_DRIVER_BLOCKED       → explicit WDAC block
            # 577 = ERROR_INVALID_IMAGE_HASH   → CI rejected the driver
            print()
            print("=" * 60)
            print("[!] RTCore64 blocked — Memory Integrity (HVCI) is ON.")
            print()
            print("  Win11 23H2/24H2 enables this by default. One-time fix:")
            print()
            print("  Option A (GUI):")
            print("    Windows Security → Device Security")
            print("    → Core Isolation → Memory Integrity → OFF → Reboot")
            print()
            print("  Option B (auto-applied right now, just reboot after):")
            print("    bcdedit /set hypervisorlaunchtype off")
            print("    bcdedit /set vsmlaunchtype off")
            print()
            _disable_hvci_bcdedit()
            print("  [+] bcdedit flags set. REBOOT NOW, then run this again.")
            print("  After one reboot this tool works every session, no reboot needed.")
            print("=" * 60)
            print()
            raise OSError("HVCI_BLOCKED")
        else:
            raise OSError(f"StartService failed: {e}")
    time.sleep(0.5)
    g_hDev = k32.CreateFileW(
        r"\\.\RTCore64", GENERIC_READ_WRITE, 0, None,
        OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, None)
    if g_hDev == INVALID_HANDLE:
        raise OSError(f"Open device failed: {ctypes.GetLastError()}")
    print("[+] RTCore64 device open.")

def unload_driver():
    global g_hScm, g_hSvc, g_hDev, g_own_svc, g_sys_path
    if g_hDev and g_hDev != INVALID_HANDLE:
        k32.CloseHandle(g_hDev); g_hDev = INVALID_HANDLE
    if g_hSvc:
        ss = (ctypes.c_byte * 28)()
        adv.ControlService(g_hSvc, SERVICE_CONTROL_STOP, ss)
        time.sleep(0.4)
        if g_own_svc: adv.DeleteService(g_hSvc)
        adv.CloseServiceHandle(g_hSvc); g_hSvc = None
    if g_hScm:
        adv.CloseServiceHandle(g_hScm); g_hScm = None
    if g_sys_path and os.path.exists(g_sys_path):
        try: os.remove(g_sys_path)
        except: pass
        g_sys_path = None
    g_own_svc = False

# ── RTCore64 IOCTL ───────────────────────────────────────────────────────────

k32.DeviceIoControl.restype  = ctypes.wintypes.BOOL
k32.DeviceIoControl.argtypes = [
    ctypes.wintypes.HANDLE, ctypes.wintypes.DWORD,
    ctypes.c_void_p, ctypes.wintypes.DWORD,
    ctypes.c_void_p, ctypes.wintypes.DWORD,
    ctypes.POINTER(ctypes.wintypes.DWORD), ctypes.c_void_p,
]

def _make_buf(addr, size, value=0):
    return bytearray(
        b'\x00' * 8 +
        struct.pack("<Q", addr) +
        struct.pack("<II", 0, size) +
        struct.pack("<Q", value) +
        b'\x00' * 16
    )

def _ioctl(code, buf):
    cbuf = (ctypes.c_char * len(buf)).from_buffer(buf)
    out_n = ctypes.wintypes.DWORD(0)
    return bool(k32.DeviceIoControl(
        g_hDev, code, cbuf, len(buf), cbuf, len(buf),
        ctypes.byref(out_n), None))

def k_read(addr, size):
    buf = _make_buf(addr, size)
    if not _ioctl(IOCTL_RT_READ, buf): return None
    return struct.unpack_from("<Q", bytes(buf), 24)[0]

def k_write(addr, value, size):
    buf = _make_buf(addr, size, value)
    return bool(_ioctl(IOCTL_RT_WRITE, buf))

# ── Find CI.dll kernel base ───────────────────────────────────────────────────

MODULE_ENTRY_SIZE   = 296
MODULE_ARRAY_OFFSET = 8

def get_ci_base():
    buf_size = 0x10000
    while True:
        buf = (ctypes.c_byte * buf_size)()
        needed = ctypes.c_ulong(0)
        st = ntdll.NtQuerySystemInformation(11, buf, buf_size, ctypes.byref(needed))
        if st == 0: break
        if st == STATUS_INFO_LENGTH_MISMATCH:
            buf_size = needed.value + 0x1000
        else:
            print(f"[!] NtQuerySystemInformation: 0x{st & 0xFFFFFFFF:X}")
            return None
    raw = bytes(buf)
    num = struct.unpack_from("<I", raw, 0)[0]
    for i in range(num):
        off = MODULE_ARRAY_OFFSET + i * MODULE_ENTRY_SIZE
        if off + MODULE_ENTRY_SIZE > len(raw): break
        image_base = struct.unpack_from("<Q",  raw, off + 16)[0]
        image_size = struct.unpack_from("<I",  raw, off + 24)[0]
        name_off   = struct.unpack_from("<H",  raw, off + 38)[0]
        name_start = 40 + name_off
        name = raw[off + name_start: off + name_start + 32].split(b'\x00')[0]
        name = name.decode("ascii", errors="replace").lower()
        if name == "ci.dll":
            print(f"[*] ci.dll  base=0x{image_base:X}  size=0x{image_size:X}")
            return image_base, image_size
    print("[!] ci.dll not found in kernel module list")
    return None

# ── Pattern scan disk CI.dll for g_CiEnabled candidates ──────────────────────
#
# Collects ALL RIP-relative byte-read/write/test patterns from .text,
# then filters out any whose target RVA falls back inside .text (wrong).
# RTCore validates the remaining list — first address with value 1-63 wins.

def _rip_rel_candidates(data, txt_rva, txt_raw, txt_sz, ci_kernel_base, ci_size,
                        all_sections):
    """Return list of (kernel_addr, rva) for all RIP-rel byte-access patterns."""
    txt = data[txt_raw: txt_raw + txt_sz]
    n   = len(txt)
    hits = []
    seen_rvas = set()

    def add(rva, instr_end_offset):
        if rva <= 0 or rva >= ci_size: return
        # reject target that lands in executable sections
        for sname, svaddr, svsz in all_sections:
            if svaddr <= rva < svaddr + svsz:
                low = sname.lower()
                if low in ('.text', 'page', 'init', '.pdata', '.xdata'):
                    return
                break
        if rva not in seen_rvas:
            seen_rvas.add(rva)
            hits.append(ci_kernel_base + rva)

    i = 0
    while i < n - 8:
        b0, b1, b2 = txt[i], txt[i+1], txt[i+2]

        # REX prefix (0x40–0x4F)
        rex = 0
        if 0x40 <= b0 <= 0x4F:
            rex = b0; b0, b1, b2 = b1, b2, txt[i+3] if i+3 < n else 0

        skip = 1 if rex else 0

        # MOVZX r32, byte [rip+d32]:  0F B6 ModRM(mod=00,rm=5) d32  (7 bytes w/o REX, 8 w/ REX)
        if b0 == 0x0F and b1 == 0xB6 and (b2 & 0xC7) == 0x05:
            base = i + skip + 3
            if base + 4 <= n:
                d = struct.unpack_from("<i", txt, base)[0]
                instr_end = base + 4
                add((txt_rva + instr_end + d) & 0xFFFFFFFF, instr_end)
            i += 1; continue

        # MOV r8, [rip+d32]:  8A ModRM(mod=00,rm=5) d32  (6 bytes w/o REX, 7 w/)
        if b0 == 0x8A and (b1 & 0xC7) == 0x05:
            base = i + skip + 2
            if base + 4 <= n:
                d = struct.unpack_from("<i", txt, base)[0]
                instr_end = base + 4
                add((txt_rva + instr_end + d) & 0xFFFFFFFF, instr_end)
            i += 1; continue

        # MOV [rip+d32], r8:  88 ModRM(mod=00,rm=5) d32
        if b0 == 0x88 and (b1 & 0xC7) == 0x05:
            base = i + skip + 2
            if base + 4 <= n:
                d = struct.unpack_from("<i", txt, base)[0]
                instr_end = base + 4
                add((txt_rva + instr_end + d) & 0xFFFFFFFF, instr_end)
            i += 1; continue

        # CMP byte [rip+d32], imm8:  80 3D d32 imm8
        if b0 == 0x80 and b1 == 0x3D and i + skip + 7 <= n:
            base = i + skip + 2
            if base + 4 <= n:
                d = struct.unpack_from("<i", txt, base)[0]
                instr_end = base + 5
                add((txt_rva + instr_end + d) & 0xFFFFFFFF, instr_end)
            i += 1; continue

        # TEST byte [rip+d32], imm8:  F6 05 d32 imm8
        if b0 == 0xF6 and b1 == 0x05 and i + skip + 7 <= n:
            base = i + skip + 2
            if base + 4 <= n:
                d = struct.unpack_from("<i", txt, base)[0]
                instr_end = base + 5
                add((txt_rva + instr_end + d) & 0xFFFFFFFF, instr_end)
            i += 1; continue

        # OR/AND byte [rip+d32], imm8:  80 0D/25 d32 imm8
        if b0 == 0x80 and b1 in (0x0D, 0x25) and i + skip + 7 <= n:
            base = i + skip + 2
            if base + 4 <= n:
                d = struct.unpack_from("<i", txt, base)[0]
                instr_end = base + 5
                add((txt_rva + instr_end + d) & 0xFFFFFFFF, instr_end)
            i += 1; continue

        i += 1

    return hits


def find_g_ci_enabled_candidates(ci_kernel_base, ci_size):
    sys_dir = os.environ.get("SystemRoot", r"C:\Windows")
    ci_path = os.path.join(sys_dir, "System32", "ci.dll")
    if not os.path.exists(ci_path):
        print(f"[!] {ci_path} not found")
        return []

    data = open(ci_path, "rb").read()
    e_lfanew    = struct.unpack_from("<I", data, 0x3C)[0]
    num_sects   = struct.unpack_from("<H", data, e_lfanew + 6)[0]
    opt_hdr_sz  = struct.unpack_from("<H", data, e_lfanew + 20)[0]
    sect_base   = e_lfanew + 24 + opt_hdr_sz

    sections = []
    txt_rva = txt_raw = txt_sz = 0
    for i in range(num_sects):
        so = sect_base + i * 40
        sname   = data[so:so+8].rstrip(b'\x00').decode('ascii', errors='replace')
        v_rva   = struct.unpack_from("<I", data, so + 12)[0]
        v_sz    = struct.unpack_from("<I", data, so +  8)[0]
        raw_off = struct.unpack_from("<I", data, so + 20)[0]
        raw_sz  = struct.unpack_from("<I", data, so + 16)[0]
        sections.append((sname, v_rva, v_sz))
        if sname == ".text":
            txt_rva = v_rva; txt_raw = raw_off; txt_sz = raw_sz

    if not txt_rva:
        print("[!] .text not found in ci.dll")
        return []

    hits = _rip_rel_candidates(data, txt_rva, txt_raw, txt_sz,
                               ci_kernel_base, ci_size, sections)
    print(f"[*] {len(hits)} g_CiEnabled candidate(s) from pattern scan")
    return hits

# ── State persistence for -off / -on ─────────────────────────────────────────

STATE_FILE = os.path.join(tempfile.gettempdir(), "dse_state.bin")

def save_state(addr, orig):
    with open(STATE_FILE, "wb") as f:
        f.write(struct.pack("<QQ", addr, orig))

def load_state():
    try:
        with open(STATE_FILE, "rb") as f:
            addr, orig = struct.unpack("<QQ", f.read(16))
        return addr, orig
    except Exception:
        return None, None

def clear_state():
    try: os.remove(STATE_FILE)
    except: pass

# ── Patch / restore ───────────────────────────────────────────────────────────

def patch_dse():
    """
    Returns (success, ci_addr, ci_orig).
    RTCore must be loaded before calling.
    """
    result = get_ci_base()
    if not result:
        return False, 0, 0
    ci_base, ci_size = result

    candidates = find_g_ci_enabled_candidates(ci_base, ci_size)
    if not candidates:
        return False, 0, 0

    ci_addr = ci_orig = None

    # Pick first candidate whose current value looks like a CI flags byte (1-63)
    for addr in candidates:
        val = k_read(addr, 1)
        if val is not None and 1 <= val <= 63:
            ci_addr, ci_orig = addr, val
            break

    # Fallback: first readable candidate
    if ci_addr is None:
        for addr in candidates:
            val = k_read(addr, 1)
            if val is not None:
                ci_addr, ci_orig = addr, val
                break

    if ci_addr is None:
        print("[!] All candidates unreadable — HVCI still on?")
        return False, 0, 0

    print(f"[*] g_CiEnabled @ 0x{ci_addr:X}  current=0x{ci_orig:X}")

    if not k_write(ci_addr, 0, 1):
        print("[!] KWrite failed")
        return False, 0, 0

    verify = k_read(ci_addr, 1)
    if verify != 0:
        print(f"[!] Verify failed (0x{verify:X}) — HVCI may still be active")
        return False, 0, 0

    return True, ci_addr, ci_orig


def restore_dse(ci_addr, ci_orig):
    if not ci_addr:
        return
    k_write(ci_addr, ci_orig, 1)
    print(f"[*] DSE restored (0x{ci_orig:X})")

# ── Elevation check ───────────────────────────────────────────────────────────

def is_admin():
    try: return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except: return False

# ── Driver bootstrap (shared by -off and interactive) ────────────────────────

def bootstrap(rtcore_data):
    sys_path = drop_driver(rtcore_data)
    print(f"[*] Dropped: {sys_path}")
    try:
        load_driver(sys_path)
    except OSError as e:
        if "HVCI_BLOCKED" in str(e):
            sys.exit(2)   # exit code 2 = needs reboot
        raise

# ── Modes ─────────────────────────────────────────────────────────────────────

def mode_off(rtcore_data):
    """Disable DSE silently, save state for -on. Exit 0 on success."""
    bootstrap(rtcore_data)
    ok, addr, orig = patch_dse()
    if ok:
        save_state(addr, orig)
        unload_driver()
        print("[+] DSE OFF.")
        sys.exit(0)
    else:
        unload_driver()
        sys.exit(1)


def mode_on(rtcore_data):
    """Restore DSE from saved state silently. Exit 0 on success."""
    addr, orig = load_state()
    if not addr:
        print("[!] No saved DSE state — run -off first.")
        sys.exit(1)
    bootstrap(rtcore_data)
    restore_dse(addr, orig)
    unload_driver()
    clear_state()
    print("[+] DSE ON.")
    sys.exit(0)


def mode_interactive(rtcore_data):
    """Disable DSE, wait for ENTER, then restore."""
    bootstrap(rtcore_data)
    ok, addr, orig = patch_dse()
    if not ok:
        restore_dse(addr, orig)
        unload_driver()
        input("Press ENTER to exit...")
        sys.exit(1)

    print("\n[+] DSE is OFF.")
    print("    1. Launch CE as Admin")
    print("    2. Let CE load its driver")
    print("    3. Press ENTER here to re-enable DSE")
    print("    4. Then launch Destiny 2\n")
    input("> ")

    restore_dse(addr, orig)
    unload_driver()
    print("[+] Done.")

# ── Main ──────────────────────────────────────────────────────────────────────

def main():
    flag = sys.argv[1].lower() if len(sys.argv) > 1 else ""

    if flag not in ("-off", "-on"):
        print("=== D2 DSE Fix (BYOVD / RTCore64) ===\n")

    if not is_admin():
        print("[!] Run as Administrator.")
        if flag not in ("-off", "-on"):
            input("Press ENTER to exit...")
        sys.exit(1)

    # ── Test-signing BCD check ────────────────────────────────────────────────
    # Must be OFF or BattlEye won't start regardless of what we do at runtime.
    # Takes effect after reboot — warn the user once.
    if is_testsigning_on():
        print("[!] Test-signing BCD flag is ON — BattlEye will refuse to start.")
        print("    Disabling it now (bcdedit /set testsigning off)...")
        clear_testsigning()
        print("    *** REBOOT REQUIRED to clear the BCD flag. ***")
        print("    After reboot, run this tool again. DSE will be handled at runtime.")
        if flag not in ("-off", "-on"):
            input("Press ENTER to exit...")
        # Still proceed with DSE patch for this session (CE driver load may work)

    rtcore_data = get_rtcore_bytes()
    if not rtcore_data:
        if flag not in ("-off", "-on"):
            input("Press ENTER to exit...")
        sys.exit(1)

    if flag == "-off":
        mode_off(rtcore_data)
    elif flag == "-on":
        mode_on(rtcore_data)
    else:
        mode_interactive(rtcore_data)

if __name__ == "__main__":
    main()
