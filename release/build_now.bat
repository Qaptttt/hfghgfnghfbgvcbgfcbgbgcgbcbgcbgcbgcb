@echo off
setlocal enabledelayedexpansion

:: ============================================================
::  D2 Trainer release packager
::  Run from the repo root — produces release\d2trainer_<date>.exe
::  Requires: 7-Zip installed (7z.exe in PATH or C:\Program Files\7-Zip\)
:: ============================================================

set "ROOT=%~dp0.."
set "OUT=%~dp0"
set "DATE=%date:~10,4%%date:~4,2%%date:~7,2%"
set "ARCHIVE=%OUT%d2trainer_%DATE%.7z"
set "SFX=%OUT%d2trainer_%DATE%.exe"

echo [*] Packaging D2 Trainer release...

:: --- locate 7z ---
set "SZ=7z.exe"
if not exist "%SZ%" (
    if exist "C:\Program Files\7-Zip\7z.exe" set "SZ=C:\Program Files\7-Zip\7z.exe"
    if exist "C:\Program Files (x86)\7-Zip\7z.exe" set "SZ=C:\Program Files (x86)\7-Zip\7z.exe"
)
"%SZ%" i >nul 2>&1
if errorlevel 1 (
    echo [!] 7-Zip not found.  Installing archive to %OUT%d2trainer_files\ instead.
    goto :zip_skip
)

:: --- pack files ---
if exist "%ARCHIVE%" del /f "%ARCHIVE%"

"%SZ%" a -t7z -mx=5 "%ARCHIVE%" ^
    "%ROOT%\Destiny420.ct" ^
    "%ROOT%\dump_patterns.lua" ^
    "%ROOT%\guide_d2_updated.txt" ^
    "%OUT%driver64.dat" ^
    "%OUT%README.txt"

:: --- try SFX (needs 7zSD.sfx next to 7z.exe or in script dir) ---
set "SFX_MOD=%~dp07zSD.sfx"
if not exist "%SFX_MOD%" (
    for %%D in ("%SZ%") do set "SFX_MOD=%%~dpD7zSD.sfx"
)
if exist "%SFX_MOD%" (
    echo [*] Building self-extracting EXE...
    copy /b "%SFX_MOD%" + "%ARCHIVE%" "%SFX%" >nul
    del /f "%ARCHIVE%"
    echo [+] Done: %SFX%
) else (
    echo [+] Done: %ARCHIVE%
    echo     (no 7zSD.sfx found — .7z only; rename if you want .exe)
)
goto :end

:zip_skip
:: fallback: just copy files to a folder the user can zip manually
set "DIR=%OUT%d2trainer_files"
if exist "%DIR%" rd /s /q "%DIR%"
mkdir "%DIR%"
copy "%ROOT%\Destiny420.ct"         "%DIR%\" >nul
copy "%ROOT%\dump_patterns.lua"     "%DIR%\" >nul
copy "%ROOT%\guide_d2_updated.txt"  "%DIR%\" >nul
copy "%OUT%driver64.dat"            "%DIR%\" >nul
copy "%OUT%README.txt"              "%DIR%\" >nul
echo [+] Files copied to: %DIR%
echo     Zip that folder manually and rename to d2trainer.exe if desired.

:end
echo.
echo  Contents:
echo    Destiny420.ct        - cheat table (load in CE)
echo    dump_patterns.lua    - pattern re-scanner (run after D2 patches)
echo    guide_d2_updated.txt - setup guide (read this first)
echo    driver64.dat         - CE driver config (WinDiag64 rename)
echo    README.txt           - quick-start
echo.
pause
