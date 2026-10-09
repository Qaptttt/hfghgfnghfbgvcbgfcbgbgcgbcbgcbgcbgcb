"""
Probe RTCore64 to find the correct IOCTL buffer size and layout.
Run as Admin.
"""
import ctypes, ctypes.wintypes, struct, os, time, tempfile

k32  = ctypes.windll.kernel32
adv  = ctypes.windll.advapi32
ntdll= ctypes.windll.ntdll

GENERIC_RW   = 0xC0000000
OPEN_EXISTING = 3
FILE_ATTR_NORMAL = 0x80
SC_MANAGER_ALL_ACCESS = 0xF003F
SERVICE_ALL_ACCESS    = 0xF01FF
SERVICE_KERNEL_DRIVER = 1
SERVICE_DEMAND_START  = 3
SERVICE_ERROR_IGNORE  = 0
SERVICE_CONTROL_STOP  = 1
INVALID_HANDLE = ctypes.wintypes.HANDLE(-1).value

k32.DeviceIoControl.restype  = ctypes.wintypes.BOOL
k32.DeviceIoControl.argtypes = [
    ctypes.wintypes.HANDLE,
    ctypes.wintypes.DWORD,
    ctypes.c_void_p, ctypes.wintypes.DWORD,
    ctypes.c_void_p, ctypes.wintypes.DWORD,
    ctypes.POINTER(ctypes.wintypes.DWORD),
    ctypes.c_void_p,
]

SVC = "RTCore64"
SYS = r"C:\Program Files (x86)\MSI Afterburner\Legacy\RTCore64.sys"

# ── load driver ──────────────────────────────────────────────────────────────
tmp = os.path.join(tempfile.gettempdir(), "hwinfo_helper.sys")
# kill stale service
hscm = adv.OpenSCManagerW(None, None, SC_MANAGER_ALL_ACCESS)
hsvc = adv.OpenServiceW(hscm, SVC, SERVICE_ALL_ACCESS)
if hsvc:
    ss = (ctypes.c_byte * 28)()
    adv.ControlService(hsvc, SERVICE_CONTROL_STOP, ss)
    time.sleep(0.5)
    adv.DeleteService(hsvc)
    adv.CloseServiceHandle(hsvc)

try: os.remove(tmp)
except: pass
import shutil; shutil.copy2(SYS, tmp)

hsvc = adv.CreateServiceW(hscm, SVC, SVC, SERVICE_ALL_ACCESS,
    SERVICE_KERNEL_DRIVER, SERVICE_DEMAND_START, SERVICE_ERROR_IGNORE,
    tmp, None, None, None, None, None)
adv.StartServiceW(hsvc, 0, None)
time.sleep(0.5)

hdev = k32.CreateFileW(r"\\.\RTCore64", GENERIC_RW, 0, None, OPEN_EXISTING, FILE_ATTR_NORMAL, None)
print(f"[*] Device handle: 0x{hdev:X}  (invalid={INVALID_HANDLE})")
if hdev == INVALID_HANDLE:
    print("[!] CreateFile failed"); exit(1)

# ── find ci.dll base ─────────────────────────────────────────────────────────
STATUS_INFO_LENGTH_MISMATCH = 0xC0000004
buf_size = 0x40000
while True:
    buf = (ctypes.c_byte * buf_size)()
    needed = ctypes.c_ulong(0)
    st = ntdll.NtQuerySystemInformation(11, buf, buf_size, ctypes.byref(needed))
    if st == 0: break
    if st == STATUS_INFO_LENGTH_MISMATCH: buf_size = needed.value + 0x1000
    else: print(f"NtQSI failed {st:X}"); exit(1)

raw = bytes(buf)
ci_base = 0
num = struct.unpack_from("<I", raw, 0)[0]
for i in range(num):
    off = 8 + i * 296
    ib = struct.unpack_from("<Q", raw, off + 16)[0]
    no = struct.unpack_from("<H", raw, off + 38)[0]
    nm = raw[off + 40 + no: off + 40 + no + 16].split(b'\x00')[0].decode("ascii","replace").lower()
    if nm == "ci.dll":
        ci_base = ib
        print(f"[*] ci.dll base: 0x{ci_base:X}")
        break

if not ci_base:
    print("[!] ci.dll not found"); exit(1)

# ── probe different IOCTL codes and buffer sizes ─────────────────────────────
READ_IOCTLS  = [0x80002048, 0x80002040, 0x80002044, 0x8000204C, 0x80002050]
WRITE_IOCTLS = [0x8000204C, 0x80002050, 0x80002054, 0x80002048]
SIZES = [16, 20, 24, 28, 32, 36, 40, 44, 48, 52, 56, 60, 64, 72, 80]

# use ci.dll base as the target address (safe read — it's mapped kernel memory)
TARGET = ci_base

print("\n── Probing READ IOCTLs ─────────────────────────────────────────")
for ioctl in READ_IOCTLS:
    for sz in SIZES:
        buf = bytearray(sz)
        # write address at various offsets, try to get a non-null result
        for addr_off in [0, 4, 8]:
            b = bytearray(sz)
            if addr_off + 8 <= sz:
                b[addr_off:addr_off+8] = struct.pack("<Q", TARGET)
            # size field guesses
            for size_off in [addr_off+8, addr_off+12, addr_off+16]:
                b2 = bytearray(b)
                if size_off + 4 <= sz:
                    b2[size_off:size_off+4] = struct.pack("<I", 8)
                cbuf = (ctypes.c_char * sz).from_buffer(b2)
                out_n = ctypes.wintypes.DWORD(0)
                ok = k32.DeviceIoControl(hdev, ioctl, cbuf, sz, cbuf, sz,
                                         ctypes.byref(out_n), None)
                if ok:
                    result = struct.unpack_from("<Q", bytes(b2))[0]
                    print(f"[+] IOCTL=0x{ioctl:X}  bufsize={sz}  addr_off={addr_off}  size_off={size_off}  → ok!  first8=0x{result:X}")

# ── tear down ────────────────────────────────────────────────────────────────
k32.CloseHandle(hdev)
ss = (ctypes.c_byte * 28)()
adv.ControlService(hsvc, SERVICE_CONTROL_STOP, ss)
time.sleep(0.4)
adv.DeleteService(hsvc)
adv.CloseServiceHandle(hsvc)
adv.CloseServiceHandle(hscm)
try: os.remove(tmp)
except: pass
print("\n[*] Done.")
