--[[
  dump_patterns.lua  v2.0  — Full D2 pattern dump (all CT features)
  Run in CE Lua engine while Destiny 2 is attached.
  Scans destiny2.exe for EVERY cheat-table feature AOB.
  Writes full context report to %TEMP%\d2_dump.txt

  USAGE:
    1. Attach CE to destiny2.exe
    2. Lua engine → paste or dofile() this script
    3. Wait ~10-15 minutes  (full module scan is slow — normal)
    4. Output file: %TEMP%\d2_dump.txt

  OUTPUT per feature:
    FOUND(N):  N hits — context hex dump with [XX] on matched bytes
    MISS:      pattern dead — needs manual rescan
    All offsets shown as both absolute addr and d2+OFFSET for easy CT update.
--]]

local OUT = os.getenv("TEMP") .. "\\d2_dump.txt"
local f = io.open(OUT, "w")
if not f then error("cannot open output: " .. OUT) end

local d2base = 0  -- set after module check below

local function log(s) f:write(s .. "\n"); io.flush(f) end
local function logf(...) log(string.format(...)) end

log("=== D2 Pattern Dump v2.0 ===")
log("Timestamp: " .. os.date())
log("")
log("NOTE: Full-module scans take 10-15 minutes on a 200 MB exe.")
log("      FOUND/MISS per pattern.  Confirmed patterns marked [OK] — still re-scanned.")
log("")

-- ── helpers ──────────────────────────────────────────────────────────────────

local function hexbytes(addr, count)
  local ok, bytes = pcall(readBytes, addr, count, true)
  if not ok or not bytes then return nil end
  local t = {}
  for i = 1, #bytes do t[i] = string.format("%02X", bytes[i]) end
  return table.concat(t, " ")
end

local function dumpctx(label, addr, before, after)
  local start = addr - before
  local hex   = hexbytes(start, before + after)
  if not hex then
    logf("  [%s] @%X  <unreadable memory>", label, addr)
    return
  end
  logf("  [%s] hit @ %X  (d2+%X)", label, addr, addr - d2base)
  local bytes = {}
  for b in hex:gmatch("%S+") do bytes[#bytes+1] = tonumber(b, 16) end
  for row = 0, math.floor((#bytes - 1) / 16) do
    local ra = start + row * 16
    local parts = {}
    for col = 0, 15 do
      local idx = row * 16 + col + 1
      if bytes[idx] then
        local abs = start + row * 16 + col
        if abs >= addr and abs < addr + 8 then
          parts[#parts + 1] = string.format("[%02X]", bytes[idx])
        else
          parts[#parts + 1] = string.format(" %02X ", bytes[idx])
        end
      end
    end
    logf("    %X: %s", ra, table.concat(parts))
  end
end

local function make_pattern(hex_str)
  local p = {}
  for tok in hex_str:gmatch("%S+") do
    p[#p + 1] = (tok == "??" or tok == "?") and -1 or tonumber(tok, 16)
  end
  return p
end

local function scan_module(mod_name, pattern_hex, max_hits)
  max_hits = max_hits or 10
  local mi = getModuleInfo(mod_name)
  if not mi then return nil, "module not found: " .. mod_name end
  local base, size = mi.Address, mi.Size
  local pat  = make_pattern(pattern_hex)
  local plen = #pat
  local hits = {}
  local CHUNK = 0x10000
  local pos = base
  while pos < base + size and #hits < max_hits do
    local csz = math.min(CHUNK, base + size - pos)
    local ok, bytes = pcall(readBytes, pos, csz, true)
    if ok and bytes then
      for i = 1, #bytes - plen + 1 do
        local match = true
        for j = 1, plen do
          if pat[j] ~= -1 and bytes[i + j - 1] ~= pat[j] then
            match = false; break
          end
        end
        if match then hits[#hits + 1] = pos + i - 1 end
      end
    end
    pos = pos + csz
  end
  return hits
end

-- scanFeat: runs 1..N patterns for a feature, logs everything.
--   entries = { {label, hex, max_hits?}, ... }
local function scanFeat(title, entries)
  log("--- " .. title .. " ---")
  local anyFound = false
  for _, e in ipairs(entries) do
    local lbl, hex, mx = e[1], e[2], e[3] or 5
    local hits, err = scan_module("destiny2.exe", hex, mx)
    if err then
      logf("  ERROR: %s", err)
    elseif #hits == 0 then
      logf("  [%s] MISS: %s", lbl, hex)
    else
      logf("  [%s] FOUND(%d)  pat: %s", lbl, #hits, hex)
      for _, h in ipairs(hits) do dumpctx(lbl, h, 0x20, 0x40) end
      anyFound = true
    end
  end
  if not anyFound then
    log("  *** ALL PATTERNS DEAD — dump context from old offset below ***")
  end
  log("")
end

-- ── module base ──────────────────────────────────────────────────────────────

local d2mi = getModuleInfo("destiny2.exe")
if not d2mi then
  log("ERROR: destiny2.exe not found — attach CE to D2 first")
  f:close(); return
end
d2base = d2mi.Address
logf("destiny2.exe  base=%X  size=%X  (%.1f MB)", d2base, d2mi.Size, d2mi.Size / 1048576)
log("")

-- ── FEATURE SCANS ────────────────────────────────────────────────────────────

-- 1. LocalPlayer (ID 2741)
scanFeat("01. LocalPlayer [ID 2741]  [OK - captures rcx on load]", {
  {"EXACT",  "0F 10 89 C0 01 00 00 0F 54 0D E7",  3},
  {"WIDE",   "0F 10 89 C0 01 00 00 0F 54 0D",      8},
  {"WIDER",  "0F 10 89 C0 01 00 00 0F 54",         10},
})

-- 2. ViewAngles hook (ID 2977) [OK]
scanFeat("02. ViewAngles hook [ID 2977]  [OK - rdi+0x1C=yaw, rdi+0x18=pitch]", {
  {"EXACT",  "F3 0F 11 47 1C 7A",  3},
  {"WIDE",   "F3 0F 11 47 1C",     5},
})

-- 3. NoRecoil (ID 275)
scanFeat("03. NoRecoil [ID 275]", {
  {"EXACT",  "0F 11 8B C4 01 00 00 8B 87 30 01 00 00",  5},
  {"WIDE",   "0F 11 8B C4 01 00 00 8B 87",              8},
  {"WIDER",  "0F 11 8B C4 01 00 00",                    10},
})

-- 4. AbilityRegen (ID 350)
scanFeat("04. AbilityRegen [ID 350]", {
  {"EXACT",  "0F 28 C1 F3 41 0F 5C C3 0F 2F C6 73",  5},
  {"WIDE",   "0F 28 C1 F3 41 0F 5C C3 0F 2F",        8},
  {"WIDER",  "0F 28 C1 F3 41 0F 5C C3",              10},
})

-- 5. RapidFire (ID 311)
scanFeat("05. RapidFire [ID 311]", {
  {"EXACT",  "F3 0F 11 86 1C 03 00 00 49 8B CF",  5},
  {"WIDE",   "F3 0F 11 86 1C 03 00 00",           8},
  {"WIDER",  "F3 0F 11 86 ?? ?? 00 00 49 8B CF",  8},
})

-- 6. IcarusDash (ID 346)
scanFeat("06. IcarusDash [ID 346]", {
  {"EXACT",  "89 46 34 89 6E 3C",  5},
  {"WIDE",   "89 46 34 89 6E",     8},
  {"WIDER",  "89 46 34",          10},
})

-- 7. InstantRespawn (ID 285)
scanFeat("07. InstantRespawn [ID 285]", {
  {"EXACT",  "48 89 86 48 08 00 00 72",  5},
  {"WIDE",   "48 89 86 48 08 00 00",     8},
  {"WIDER",  "48 89 86 ?? ?? 00 00 72",  8},
})

-- 8. OPK / AluraOPK (ID 463)
scanFeat("08. OPK / AluraOPK [ID 463]", {
  {"EXACT",  "0F 11 47 70 41 8B 41 0C",  5},
  {"WIDE",   "0F 11 47 70 41 8B",        8},
  {"WIDER",  "0F 11 47 70",             10},
})

-- 9. GenerateOrbs (ID 2260)
scanFeat("09. GenerateOrbs [ID 2260]", {
  {"EXACT",  "89 51 48 48 8B D1",   5},
  {"WIDE",   "89 51 48 48 8B",      8},
  {"WIDER",  "89 51 48",           10},
})

-- 10. Godmode 1.0 (ID 348)
scanFeat("10. Godmode 1.0 [ID 348]", {
  {"EXACT",  "F3 0F 11 4C 24 38 B9",  5},
  {"WIDE",   "F3 0F 11 4C 24 38",     8},
})

-- 11. Godmode 2.0 (ID 271/4014)
scanFeat("11. Godmode 2.0 [ID 271/4014]", {
  {"EXACT",  "C3 89 07 48 8B 5C 24 30",  5},
  {"WIDE",   "C3 89 07 48 8B 5C",        8},
})

-- 12. Godmode 3.0 (ID 1891)
scanFeat("12. Godmode 3.0 [ID 1891]", {
  {"EXACT",  "33 DA C1 C3 10 E8 ?? ?? ?? ?? 48",  5},
  {"WIDE",   "33 DA C1 C3 10 E8",                  8},
})

-- 13. Stacks 1.0 (ID 2215)
scanFeat("13. Stacks 1.0 [ID 2215]", {
  {"EXACT",  "89 5F 30 74 08",  5},
  {"WIDE",   "89 5F 30",        8},
})

-- 14. Stacks 2.0 (ID 2092)
scanFeat("14. Stacks 2.0 [ID 2092]", {
  {"EXACT",  "F3 0F 10 C8 0F 11 0A C3 48 8D 64 24 F8 E9",  5},
  {"WIDE",   "F3 0F 10 C8 0F 11 0A C3",                    8},
})

-- 15. TurboCrasher (ID 2217)
scanFeat("15. TurboCrasher [ID 2217]", {
  {"EXACT",  "C7 43 04 FF FF FF FF C6 03 01 48 83 C4 20 5B C3",  5},
  {"WIDE",   "C7 43 04 FF FF FF FF C6 03 01",                    8},
})

-- 16. Timers (ID 2271)
scanFeat("16. Timers [ID 2271]", {
  {"EXACT",  "48 89 8B A0 00 00 00 48 8D 4C 24 30",  5},
  {"WIDE",   "48 89 8B A0 00 00 00 48 8D 4C",        8},
})

-- 17. FoV (ID 283)
scanFeat("17. FoV [ID 283]", {
  {"EXACT",  "48 8B 00 49 89 47 50",  5},
  {"WIDE",   "48 8B 00 49 89 47",     8},
})

-- 18. ViewmodelFoV (ID 2335)
scanFeat("18. ViewmodelFoV [ID 2335]", {
  {"EXACT",  "0F 11 53 10 0F 10 4E 20 40",  5},
  {"WIDE",   "0F 11 53 10 0F 10 4E",        8},
})

-- 19. ViewmodelFoV 2.0 (ID 4005)
scanFeat("19. ViewmodelFoV 2.0 [ID 4005]", {
  {"EXACT",  "F3 0F 10 4B 10 F3 0F 10 43",  5},
  {"WIDE",   "F3 0F 10 4B 10 F3 0F 10",     8},
})

-- 20. ViewmodelFoV 3.0 (ID 4010)
scanFeat("20. ViewmodelFoV 3.0 [ID 4010]", {
  {"EXACT",  "F3 0F 11 43 08 F3 0F 10 87",  5},
  {"WIDE",   "F3 0F 11 43 08 F3 0F 10",     8},
  {"WIDER",  "F3 0F 11 43 08 F3 0F",       10},
})

-- 21. OneHitKill (ID 4012)
scanFeat("21. OneHitKill [ID 4012]", {
  {"EXACT",  "F3 0F 11 44 24 50 33 C0 8B",  5},
  {"WIDE",   "F3 0F 11 44 24 50 33 C0",     8},
})

-- 22. DamageScaling 1.0 (ID 2674)
scanFeat("22. DamageScaling 1.0 [ID 2674]", {
  {"EXACT",  "0F 10 80 00 01 00 00 0F 29 85",  5},
  {"WIDE",   "0F 10 80 00 01 00 00 0F 29",     8},
})

-- 23. DamageScaling 2.0 (ID 2065)
--     offset changed between builds: try both 0x08 and 0x24 variants
scanFeat("23. DamageScaling 2.0 [ID 2065]", {
  {"OFF_08",  "F3 44 0F 10 61 08 44 0F 29 A8 68 FF FF FF 45 0F 57 ED",  5},
  {"OFF_24",  "F3 44 0F 10 61 24 44 0F 29 A8",                          5},
  {"WILD",    "F3 44 0F 10 61 ?? 44 0F 29 A8",                          8},
})

-- 24. InteractAnywhere (ID 2747)
scanFeat("24. InteractAnywhere [ID 2747]", {
  {"EXACT",  "8B 54 01 6C 8B 4F 24",  5},
  {"WIDE",   "8B 54 01 6C 8B",        8},
})

-- 25. InteractSpeed (ID 3982)
scanFeat("25. InteractSpeed [ID 3982]", {
  {"EXACT",  "F3 0F 11 43 08 48 83 C4 30 5B C3 49",  5},
  {"WIDE",   "F3 0F 11 43 08 48 83 C4 30 5B C3",     8},
})

-- 26. InteractAura 2.0 (ID 2094/interact)  [OK]
scanFeat("26. InteractAura 2.0 [ID 2094]  [OK]", {
  {"EXACT",  "F3 42 0F 10 74 1A 6C",     5},
  {"WIDE",   "F3 42 0F 10 74 ?? ??",     8},
  {"WIDER",  "F3 42 0F 10 74",          10},
})

-- 27. KillAura 3.0 (ID 2094/killaura) — may be dead; try several variants
scanFeat("27. KillAura 3.0 [ID 2094 dead?] — trying all variants", {
  {"V1",     "F3 0F 10 41 20 32 C0",  5},
  {"V2",     "F3 0F 10 41 20 32",     8},
  {"V3",     "33 DA C1 C3 10 E8",    10},
  {"V4",     "?? F3 0F 10 41 20 32",  8},
})

-- 28. NoClip 1 (ID 272)
scanFeat("28. NoClip 1 [ID 272]", {
  {"EXACT",  "89 47 7C 0F B6 87 CB 00 00 00 44 0F 10 32",  5},
  {"WIDE",   "89 47 7C 0F B6 87 CB 00 00 00",              8},
})

-- 29. NoClip 2 (ID 272b)
scanFeat("29. NoClip 2 [ID 272b]", {
  {"EXACT",  "89 43 7C 0F B6 83 CB 00 00 00 44 0F 10 12",  5},
  {"WIDE",   "89 43 7C 0F B6 83 CB 00 00 00",              8},
})

-- 30. InfTokens (ID 288)
scanFeat("30. InfTokens [ID 288]", {
  {"EXACT",  "89 08 48 83 C4 38 C3 CC BB",  5},
  {"WIDE",   "89 08 48 83 C4 38 C3",        8},
})

-- 31. Freecam (ID 2735)
scanFeat("31. Freecam [ID 2735]", {
  {"EXACT",  "89 01 48 8D 49 04 49 83 E8 01 75 F1 EB 2E",  5},
  {"WIDE",   "89 01 48 8D 49 04 49 83 E8 01 75 F1",        8},
})

-- 32. pStickyBase (ID 2700)  [OK]
scanFeat("32. pStickyBase [ID 2700]  [OK]", {
  {"EXACT",  "90 95 80 80 00 00 00 00 50 CD",  5},
  {"ALT",    "90 95 80 80 00 00 00 00",        8},
  {"WIDE",   "?? 95 80 80 00 00 00 00",       15},
})

-- 33. ChamsBase / EntNearCS (ID 2717)  [OK]
scanFeat("33. ChamsBase [ID 2717]  [OK]", {
  {"EXACT",  "A6 95 80 80 00 00 00 00 10 BF",  5},
  {"ALT",    "A6 95 80 80 00 00 00 00",         8},
  {"WIDE",   "?? 95 80 80 00 00 00 00",        15},
})

-- ── BONUS: dump old CT injection sites by fixed offset ────────────────────────
-- useful when all patterns are dead and you need surrounding context to derive new AOB

log("--- OLD INJECTION SITE CONTEXT (by stored offset, may be wrong after patch) ---")
local sites = {
  {"pStickyBase",   0x287F1A8},
  {"ChamsBase",     0x287EAB8},
  {"ViewAngles",    0x1234567},  -- placeholder: update from last working scan
  {"LocalPlayer",   0x0},
  {"KillAura3",     0x142CB40},
  {"InteractAura",  0x14E015B},
}
for _, s in ipairs(sites) do
  if s[2] ~= 0 then
    local addr = d2base + s[2]
    logf("  %-20s  d2+%X  @%X", s[1], s[2], addr)
    dumpctx(s[1], addr, 0x20, 0x40)
  end
end
log("")

-- ── done ─────────────────────────────────────────────────────────────────────

log("=== DONE ===")
logf("d2base = %X", d2base)
f:close()
print("[dump_patterns] done → " .. OUT)
