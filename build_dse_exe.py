"""
build_dse_exe.py — builds dse_fix_win11.exe (no C compiler needed)
Run:  python build_dse_exe.py
"""

import subprocess, sys, os, shutil

RTCORE_PATHS = [
    r"C:\Program Files (x86)\MSI Afterburner\Legacy\RTCore64.sys",
    r"C:\Program Files (x86)\MSI Afterburner\RTCore64.sys",
    r"C:\Program Files\MSI Afterburner\Legacy\RTCore64.sys",
]

HERE = os.path.dirname(os.path.abspath(__file__))

def run(args, **kw):
    print(f">>> {' '.join(args)}")
    r = subprocess.run(args, **kw)
    if r.returncode != 0:
        print(f"[!] Command failed (exit {r.returncode})")
        sys.exit(1)
    return r

# ── 1. Ensure PyInstaller ────────────────────────────────────────────────────
try:
    import PyInstaller
    print(f"[*] PyInstaller {PyInstaller.__version__} already installed.")
except ImportError:
    print("[*] Installing PyInstaller...")
    run([sys.executable, "-m", "pip", "install", "pyinstaller", "--quiet"])

# ── 2. Find RTCore64.sys ─────────────────────────────────────────────────────
rtcore = None
for p in RTCORE_PATHS:
    if os.path.exists(p):
        rtcore = p
        break

if not rtcore:
    print("[!] RTCore64.sys not found. Edit RTCORE_PATHS in this script.")
    sys.exit(1)

print(f"[*] Using: {rtcore}")

# ── 3. PyInstaller ───────────────────────────────────────────────────────────
script  = os.path.join(HERE, "dse_fix_win11.py")
out_dir = HERE
tmp_dir = os.path.join(HERE, "build_tmp")

# --add-data src;dst  (Windows separator is ;)
add_data = f"{rtcore};."

run([
    sys.executable, "-m", "PyInstaller",
    "--onefile",
    "--console",
    "--name", "disable DSE",
    "--add-data", add_data,
    "--distpath", out_dir,
    "--workpath", tmp_dir,
    "--specpath", tmp_dir,
    script
])

# ── 4. Confirm ───────────────────────────────────────────────────────────────
out_exe = os.path.join(out_dir, "dse_fix_win11.exe")
if os.path.exists(out_exe):
    size_kb = os.path.getsize(out_exe) // 1024
    print(f"\n[+] Done: {out_exe}  ({size_kb} KB)")
    print("    Send this to your friends — run as Admin before CE.")
else:
    print("[!] Output exe not found. Check PyInstaller output above.")
    sys.exit(1)
