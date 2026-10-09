# build_package.ps1 — rebuild D2Trainer.exe
# Run this from the launcher\ directory after making any updates.
#
# WHAT TO UPDATE:
#   CE binary    -> copy new memtools64.exe over stage\loader.exe, then run this script
#   Trainer CT   -> just edit ..\Destiny420.ct, then run this script
#   Driver       -> copy new .sys over ..\CE-Working\WinDiag64.sys, then run this script
#   CE DLLs      -> run the "rebuild deps zip" section below, then run this script

$ErrorActionPreference = "Stop"
$ldir = Split-Path -Parent $MyInvocation.MyCommand.Definition

# ---- Rebuild ce_deps.zip (only needed when DLLs change) ----
# Uncomment the block below if you updated any DLLs in CE-Working:
<#
$ceWorking = "$ldir\..\CE-Working"
$zipStage  = "$env:TEMP\ce_deps_stage_rebuild"
$zipDest   = "$ldir\stage\ce_deps.zip"
$exclude   = @("memtools64.exe","WinDiag64.sys","Destiny420*.ct","ExceptionAutoSave*",
               "CLAUDE.md","guide*","patch_ce*","scan_results*","trainer_icon*",
               "build_driver*","driver64.dat.template","*.exe")
if (Test-Path $zipStage) { Remove-Item $zipStage -Recurse -Force }
New-Item -ItemType Directory $zipStage | Out-Null
Get-ChildItem $ceWorking -File | Where-Object {
    $n = $_.Name
    -not ($exclude | Where-Object { $n -like $_ })
} | ForEach-Object { Copy-Item $_.FullName "$zipStage\$($_.Name)" }
if (Test-Path $zipDest) { Remove-Item $zipDest -Force }
Add-Type -AN System.IO.Compression.FileSystem
[IO.Compression.ZipFile]::CreateFromDirectory($zipStage, $zipDest, 'Optimal', $false)
Remove-Item $zipStage -Recurse -Force
Write-Host "ce_deps.zip rebuilt: $([math]::Round((Get-Item $zipDest).Length/1MB,1)) MB"
#>

# ---- Find VS2019 tools ----
$vsRoot  = "C:\Program Files\Microsoft Visual Studio\18\Community"
$msvcVer = (Get-ChildItem "$vsRoot\VC\Tools\MSVC\" -Directory | Sort-Object Name -Descending | Select-Object -First 1).Name
$wdk     = "C:\Program Files (x86)\Windows Kits\10"
$sdkVer  = (Get-ChildItem "$wdk\bin" -Directory | Sort-Object Name -Descending | Where-Object {$_.Name -like "10.*"} | Select-Object -First 1).Name

$cl      = "$vsRoot\VC\Tools\MSVC\$msvcVer\bin\Hostx64\x64\cl.exe"
$rc      = "$wdk\bin\$sdkVer\x64\rc.exe"
$lib     = "$vsRoot\VC\Tools\MSVC\$msvcVer\lib\x64"
$inc     = "$vsRoot\VC\Tools\MSVC\$msvcVer\include"
$sdkInc  = "$wdk\Include\$sdkVer"
$sdkLib  = "$wdk\Lib\$sdkVer\um\x64"
$ucrtLib = "$wdk\Lib\$sdkVer\ucrt\x64"

Write-Host "Using MSVC $msvcVer, SDK $sdkVer"

# ---- Step 1: RC ----
Write-Host "Step 1/2: compiling resources..."
& $rc /fo "$ldir\launcher.res" "$ldir\launcher.rc"
if ($LASTEXITCODE -ne 0) { throw "rc.exe failed" }

# ---- Step 2: CL ----
Write-Host "Step 2/2: compiling + linking..."
& $cl /O2 /W3 /GS- /D_CRT_SECURE_NO_WARNINGS `
    "$ldir\launcher.c" "$ldir\launcher.res" `
    "/I$inc" "/I$sdkInc\um" "/I$sdkInc\shared" "/I$sdkInc\ucrt" `
    /link Winhttp.lib Advapi32.lib Shell32.lib User32.lib `
    "/LIBPATH:$lib" "/LIBPATH:$sdkLib" "/LIBPATH:$ucrtLib" `
    /SUBSYSTEM:WINDOWS "/out:$ldir\D2Trainer.exe"

if ($LASTEXITCODE -ne 0) { throw "cl.exe failed" }

$sz = [math]::Round((Get-Item "$ldir\D2Trainer.exe").Length / 1MB, 1)
Write-Host ""
Write-Host "Done: D2Trainer.exe ($sz MB)"
