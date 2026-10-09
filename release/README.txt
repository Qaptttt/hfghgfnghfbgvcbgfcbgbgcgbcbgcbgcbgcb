====================================================================
 D2 TRAINER — QUICK START
====================================================================

FILES IN THIS RELEASE
  Destiny420.ct        — cheat table, load in CE
  dump_patterns.lua    — re-scanner: run after every D2 patch
  guide_d2_updated.txt — full setup guide (read this first)
  driver64.dat         — CE driver name config (WinDiag64)
  disable DSE.exe      — compile from source (see guide Part 1-2)
  WinDiag64.sys        — compile from source (see guide Part 1)

SETUP (all steps in guide_d2_updated.txt — this is just the summary)
  1. Compile WinDiag64.sys + custom CE.exe  (guide Part 1 + 2)
  2. Copy driver64.dat next to your CE.exe and WinDiag64.sys
  3. Compile disable_dse_v2.cpp into "disable DSE.exe"  (VS x64 Release)

LOAD ORDER (critical for BattleEye — wrong order = ban)
  1. Run "disable DSE.exe" as Admin
  2. Run custom CE.exe as Admin  (driver loads: WinDiag64 LOADED)
  3. Run "disable DSE.exe" as Admin again  (re-enables DSE)
  4. Launch Destiny 2 normally
  5. In CE: attach to destiny2.exe
  6. Load Destiny420.ct

FIRST-TIME CT ENABLE ORDER
  Enable in this order to avoid conflicts:
    [1] ODS Mute          — kills BattleEye debug monitoring
    [2] Driver Stealth    — unlinks CE driver from PsLoadedModuleList
    [3] HWID Spoofer      — IAT patch + volume/GUID spoof
    [4] Stealth Hardener  — RWX→RX page hardening
    [5] LocalPlayer       — base pointer (wait for green)
    [6] ViewAngles        — needed by Aimbot
    [7] Chams             — wall ESP (set CHAMS_GLOW_OFF if no visual)
    [8] Aimbot            — RMB=aim, LT=aim, F7=toggle ctrl/mouse, F8=rescan

AIMBOT SETTINGS (in the CT script, edit globals at top of [ENABLE])
  SMOOTH      = 0.10   -- 0.05=slow+smooth, 0.25=fast
  MAX_TURN    = 0.09   -- max turn per 8ms tick
  AIMBOT_FOV  = 180    -- degrees (180=disabled, 45=tight headshot cone)
  AIMBOT_RAD  = 400    -- scan radius world-units

CHAMS TUNING (if enemies don't glow)
  In the Chams script set CHAMS_GLOW_OFF to the correct entity offset.
  Default: 0x230.  Common alternatives: 0x1E0, 0x238, 0x260.
  Set ChamsDbgLog=true to print entity addresses to CE Lua output,
  then browse that address in CE → watch what changes when you mark an
  enemy with an in-game ability → that's your offset.

AFTER D2 PATCHES (patterns go dead)
  1. Run dump_patterns.lua in CE Lua engine
  2. Wait ~10-15 min for full scan
  3. Check %TEMP%\d2_dump.txt for new offsets
  4. Update AOBs in Destiny420.ct accordingly

COMPATIBILITY
  Win10 1903+         supported (all builds)
  Win11 22H2          supported
  Win11 23H2/24H2     supported (CI\Policy fix applied in disable DSE.exe)
  Win11 25H2          supported (CI\Protected fix applied in disable DSE.exe)

====================================================================
