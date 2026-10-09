@echo off
setlocal

set VSROOT=C:\Program Files\Microsoft Visual Studio\18\Community
set WDK=C:\Program Files (x86)\Windows Kits\10

for /f "tokens=*" %%i in ('dir /b /ad /o-n "%VSROOT%\VC\Tools\MSVC\"') do (
    set MSVCVER=%%i
    goto :foundmsvc
)
:foundmsvc

for /f "tokens=*" %%i in ('dir /b /ad /o-n "%WDK%\bin\" ^| findstr /r "^10\."') do (
    set SDKVER=%%i
    goto :foundsdk
)
:foundsdk

set CLEXE=%VSROOT%\VC\Tools\MSVC\%MSVCVER%\bin\Hostx64\x64\cl.exe
set LIB=%VSROOT%\VC\Tools\MSVC\%MSVCVER%\lib\x64
set INC=%VSROOT%\VC\Tools\MSVC\%MSVCVER%\include
set SDKINC=%WDK%\Include\%SDKVER%
set SDKLIB=%WDK%\Lib\%SDKVER%\um\x64
set UCRTLIB=%WDK%\Lib\%SDKVER%\ucrt\x64

echo Using MSVC %MSVCVER%, SDK %SDKVER%

echo Compiling disable_dse_v2.cpp (RTCore64 BYOVD)...
"%CLEXE%" /O2 /W3 /GS- /MT /D_CRT_SECURE_NO_WARNINGS ^
    "disable_dse_v2.cpp" ^
    "/I%INC%" "/I%SDKINC%\um" "/I%SDKINC%\shared" "/I%SDKINC%\ucrt" ^
    /link Advapi32.lib "/LIBPATH:%LIB%" "/LIBPATH:%SDKLIB%" "/LIBPATH:%UCRTLIB%" ^
    /SUBSYSTEM:CONSOLE "/out:disable_dse_v2.exe"
if %ERRORLEVEL% neq 0 ( echo CL failed && exit /b 1 )

echo Copying to d2 dir as "disable DSE.exe"...
copy /y "disable_dse_v2.exe" "..\disable DSE.exe"
if %ERRORLEVEL% neq 0 ( echo COPY failed && exit /b 1 )

echo.
echo SUCCESS -- rebuild the launcher with build_now.bat or build_package.ps1
exit /b 0
