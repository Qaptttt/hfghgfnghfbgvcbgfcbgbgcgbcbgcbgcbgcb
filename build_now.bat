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
set RC=%WDK%\bin\%SDKVER%\x64\rc.exe
set LIB=%VSROOT%\VC\Tools\MSVC\%MSVCVER%\lib\x64
set INC=%VSROOT%\VC\Tools\MSVC\%MSVCVER%\include
set SDKINC=%WDK%\Include\%SDKVER%
set SDKLIB=%WDK%\Lib\%SDKVER%\um\x64
set UCRTLIB=%WDK%\Lib\%SDKVER%\ucrt\x64

echo Using MSVC %MSVCVER%, SDK %SDKVER%

echo Step 1/4: compiling disable_dse_v2.cpp...
"%CLEXE%" /O2 /W3 /GS- /MT /D_CRT_SECURE_NO_WARNINGS ^
    "disable_dse_v2.cpp" ^
    "/I%INC%" "/I%SDKINC%\um" "/I%SDKINC%\shared" "/I%SDKINC%\ucrt" ^
    /link Advapi32.lib "/LIBPATH:%LIB%" "/LIBPATH:%SDKLIB%" "/LIBPATH:%UCRTLIB%" ^
    /SUBSYSTEM:CONSOLE "/out:disable_dse_v2.exe"
if %ERRORLEVEL% neq 0 ( echo disable_dse_v2 compile failed && exit /b 1 )
copy /y "disable_dse_v2.exe" "..\disable DSE.exe" >nul
if %ERRORLEVEL% neq 0 ( echo copy to disable DSE.exe failed && exit /b 1 )
echo   -> copied to ..\disable DSE.exe

echo Step 2/4: compiling resources...
"%RC%" /fo "launcher.res" "launcher.rc"
if %ERRORLEVEL% neq 0 ( echo RC failed && exit /b 1 )

echo Step 3/4: compiling + linking launcher...
"%CLEXE%" /O2 /W3 /GS- /MT /D_CRT_SECURE_NO_WARNINGS ^
    "launcher.c" "launcher.res" ^
    "/I%INC%" "/I%SDKINC%\um" "/I%SDKINC%\shared" "/I%SDKINC%\ucrt" ^
    /link Winhttp.lib Advapi32.lib Shell32.lib User32.lib Gdi32.lib ^
    "/LIBPATH:%LIB%" "/LIBPATH:%SDKLIB%" "/LIBPATH:%UCRTLIB%" ^
    /SUBSYSTEM:WINDOWS "/out:D2Trainer_new.exe"
if %ERRORLEVEL% neq 0 ( echo CL failed && exit /b 1 )

echo Replacing old EXE...
del /f /q "D2Trainer.exe" 2>nul
move /y "D2Trainer_new.exe" "D2Trainer.exe"
if %ERRORLEVEL% neq 0 ( echo RENAME failed - EXE still locked && exit /b 1 )

echo SUCCESS
exit /b 0
