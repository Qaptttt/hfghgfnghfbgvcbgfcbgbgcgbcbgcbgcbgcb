@echo off
echo === D2 DSE Fix builder ===
echo.

REM Step 1: generate C header from RTCore64.sys
echo [1/3] Generating rtcore64_bytes.h...
python gen_rtcore_header.py
if errorlevel 1 (
    echo [!] gen_rtcore_header.py failed. Make sure Python is installed and MSI Afterburner is present.
    pause & exit /b 1
)
echo.

REM Step 2: try MSVC first, then MinGW
echo [2/3] Compiling...

REM Check for MSVC cl.exe
where cl >nul 2>nul
if %errorlevel%==0 (
    echo     Using MSVC...
    cl /O2 /W3 /nologo dse_fix_win11.c /Fe:dse_fix_win11.exe /link ntdll.lib advapi32.lib
    goto :check
)

REM Check for MinGW
where x86_64-w64-mingw32-gcc >nul 2>nul
if %errorlevel%==0 (
    echo     Using MinGW-w64...
    x86_64-w64-mingw32-gcc -O2 -o dse_fix_win11.exe dse_fix_win11.c -lntdll -ladvapi32
    goto :check
)

REM Check for gcc (may be 64-bit on some setups)
where gcc >nul 2>nul
if %errorlevel%==0 (
    echo     Using gcc...
    gcc -O2 -o dse_fix_win11.exe dse_fix_win11.c -lntdll -ladvapi32
    goto :check
)

echo [!] No compiler found.
echo     Install one of:
echo       - Visual Studio with C++ tools (then run this from a VS x64 Dev Prompt)
echo       - MinGW-w64: https://www.mingw-w64.org/
pause & exit /b 1

:check
if not exist dse_fix_win11.exe (
    echo [!] Compile failed.
    pause & exit /b 1
)

echo.
echo [3/3] Done!
echo     Output: dse_fix_win11.exe
echo.
echo     Run dse_fix_win11.exe as Admin before launching CE on Win11.
echo.
pause
