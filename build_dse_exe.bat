@echo off
echo === Build dse_fix_win11.exe (no compiler needed) ===
echo.

REM pip install pyinstaller silently if missing
python -c "import PyInstaller" 2>nul
if errorlevel 1 (
    echo [*] Installing PyInstaller...
    pip install pyinstaller --quiet
    if errorlevel 1 (
        echo [!] pip install failed. Make sure Python is in PATH and you have internet.
        pause & exit /b 1
    )
)

REM bundle RTCore64.sys from MSI Afterburner Legacy folder
set RTCORE=C:\Program Files (x86)\MSI Afterburner\Legacy\RTCore64.sys
if not exist "%RTCORE%" (
    echo [!] RTCore64.sys not found at: %RTCORE%
    echo     Adjust RTCORE variable at top of this bat.
    pause & exit /b 1
)

echo [*] Bundling RTCore64.sys + building .exe...
pyinstaller ^
    --onefile ^
    --noconsole=false ^
    --name "disable DSE" ^
    --add-data "%RTCORE%;." ^
    --distpath . ^
    --workpath build_tmp ^
    --specpath build_tmp ^
    dse_fix_win11.py

if not exist "disable DSE.exe" (
    echo [!] Build failed.
    pause & exit /b 1
)

echo.
echo [+] Built: disable DSE.exe
echo     Send this to your friends — no Python, no MSI Afterburner needed on their end.
echo     They just run it as Admin before launching CE.
echo.
pause
