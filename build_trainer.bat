@echo off
setlocal

echo ================================================================
echo  Building D2Trainer.exe
echo ================================================================
echo.

rem Check prerequisites
if not exist "d2\disable DSE.exe" (
    echo [!] d2\disable DSE.exe missing.
    echo     Run build_dse.bat first.
    pause & exit /b 1
)
if not exist "d2\Destiny420.ct" (
    echo [!] d2\Destiny420.ct missing. Put your CT file there.
    pause & exit /b 1
)
if not exist "CE-Working\loader.exe" (
    echo [!] CE-Working\loader.exe missing. Put your CE binary there.
    pause & exit /b 1
)
if not exist "CE-Working\d2drv.sys" (
    echo [!] CE-Working\d2drv.sys missing. Put your driver there.
    pause & exit /b 1
)

rem Build resource
echo [*] Compiling launcher resource...
rc /fo launcher\launcher.res launcher\launcher.rc
if %errorlevel% neq 0 (
    echo [!] rc.exe failed.
    pause & exit /b 1
)

rem Build launcher
echo [*] Compiling launcher...
cl /O2 /W3 /GS- launcher\launcher.c launcher\launcher.res ^
   /link Winhttp.lib Advapi32.lib Shell32.lib ^
   /SUBSYSTEM:WINDOWS /out:D2Trainer.exe
if %errorlevel% neq 0 (
    echo [!] Launcher compile failed.
    pause & exit /b 1
)

echo.
echo [+] Done: D2Trainer.exe
echo.
