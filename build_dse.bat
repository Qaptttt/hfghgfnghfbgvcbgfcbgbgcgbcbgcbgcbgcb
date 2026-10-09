@echo off
setlocal

echo ================================================================
echo  Building disable DSE.exe
echo ================================================================
echo.

set SRC=disable_dse_v2.cpp
set OUT=d2\disable DSE.exe

if not exist "%SRC%" (
    echo [!] %SRC% not found. Run this bat from the repo root.
    pause & exit /b 1
)

if not exist d2 mkdir d2

rem Try MSVC cl.exe first
where cl >nul 2>&1
if %errorlevel%==0 (
    echo [*] Using MSVC cl.exe
    cl /O2 /W3 /D_WIN32_WINNT=0x0A00 /DWINVER=0x0A00 /D_CRT_SECURE_NO_WARNINGS /I. ^
       "%SRC%" /link Advapi32.lib /out:"%OUT%"
    if %errorlevel%==0 goto done
    echo [!] MSVC compile failed.
    pause & exit /b 1
)

rem Fallback: MinGW g++
where g++ >nul 2>&1
if %errorlevel%==0 (
    echo [*] Using MinGW g++
    g++ -O2 -std=c++11 -D_WIN32_WINNT=0x0A00 -DWINVER=0x0A00 -D_CRT_SECURE_NO_WARNINGS ^
        -I. "%SRC%" -ladvapi32 -static -o "%OUT%"
    if %errorlevel%==0 goto done
    echo [!] MinGW compile failed.
    pause & exit /b 1
)

echo [!] No compiler found.
echo     Open "x64 Native Tools Command Prompt for VS" and run this bat from there.
pause & exit /b 1

:done
echo.
echo [+] Built: %OUT%
echo.
