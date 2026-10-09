@echo off
setlocal

set MSBUILD="C:\Program Files\Microsoft Visual Studio\2022\Community\MSBuild\Current\Bin\amd64\MSBuild.exe"
set SLN="C:\Users\Bob\Downloads\d2\cheat-engine-7.5\DBKKernel\DBKKernel.sln"
set OUT=C:\Users\Bob\Downloads\d2\CE-Working

echo === Building WinDiag64.sys ===
echo.

%MSBUILD% %SLN% /p:Configuration="Release without sig" /p:Platform=x64 /t:Build /v:minimal

if %ERRORLEVEL% NEQ 0 (
    echo.
    echo BUILD FAILED. Check errors above.
    pause
    exit /b 1
)

echo.
echo === Build OK ===

if exist "%OUT%\WinDiag64.sys" (
    echo Output: %OUT%\WinDiag64.sys
) else (
    echo WARNING: WinDiag64.sys not found in CE-Working.
)

echo.
echo Next steps:
echo  1. Copy a CE 7.5 exe to CE-Working\ as memtools64.exe
echo  2. Run: python patch_ce_strings.py CE-Working\memtools64.exe
echo  3. Run disable DSE.exe as Admin
echo  4. Run CE-Working\memtools64.exe as Admin
echo  5. Run disable DSE.exe again to RE-ENABLE DSE
echo  6. Launch Destiny 2
echo.
pause
