--[[
  dump_patterns.lua
  Run this in CE's Lua engine (Ctrl+Alt+L) while Destiny 2 is attached.
  Scans for pStickyBase, ChamsBase, Kill Aura, and Interact Aura patterns.
  Writes report to %TEMP%\d2_dump.txt

  USAGE:
    1. Attach CE to Destiny 2
    2. Open Lua engine (Ctrl+Alt+L or Cheat Engine -> Tools -> Lua engine)
    3. Paste or dofile() this script
    4. Wait ~30 seconds for scans to finish
    5. Send Fox the file: %TEMP%\d2_dump.txt
--]]

local OUT = os.getenv("TEMP") .. "\\d2_dump.txt"
local f = io.open(OUT, "w")
if not f then error("cannot open output: " .. OUT) end

local function log(s) f:write(s .. "\n") io.flush(f) end
local function logfmt(...) log(string.format(...)) end

log("=== D2 Pattern Dump ===")
log("Time: " .. os.date())
log("")

-- ---- helpers ----------------------------------------------------------------

local function hexbytes(addr, count)
  local ok, bytes = pcall(readBytes, addr, count, true)
  if not ok or not bytes then return nil end
  local t = {}
  for i = 1, #bytes do t[i] = string.format("%02X", bytes[i]) end
  return table.concat(t, " ")
end

local function dumpctx(label, addr, before, after)
  local start = addr - before
  local hex = hexbytes(start, before + after)
  if not hex then
    logfmt("  [%s] addr=%X  context unreadable", label, addr)
    return
  end
  logfmt("  [%s] hit @ %X", label, addr)
  -- print in 16-byte rows
  local bytes = {}
  for b in hex:gmatch("%S+") do bytes[#bytes+1] = tonumber(b,16) end
  for row = 0, math.floor((#bytes-1)/16) do
    local rowaddr = start + row*16
    local parts = {}
    for col = 0, 15 do
      local i = row*16 + col + 1
      if bytes[i] then
        -- mark the hit byte(s)
        local abs = start + row*16 + col
        if abs >= addr and abs < addr + 8 then
          parts[#parts+1] = string.format("[%02X]", bytes[i])
        else
          parts[#parts+1] = string.format(" %02X ", bytes[i])
        end
      end
    end
    logfmt("    %X: %s", rowaddr, table.concat(parts))
  end
end

-- ---- AOB scanner (page-by-page) --------------------------------------------
-- pattern: array of numbers or -1 for wildcard
local function make_pattern(hex_str)
  local p = {}
  for tok in hex_str:gmatch("%S+") do
    if tok == "??" or tok == "?" then
      p[#p+1] = -1
    else
      p[#p+1] = tonumber(tok, 16)
    end
  end
  return p
end

local function scan_module(mod_name, pattern_hex, max_hits)
  max_hits = max_hits or 20
  local mi = getModuleInfo(mod_name)
  if not mi then
    return nil, "module not found: " .. mod_name
  end
  local base  = mi.Address
  local size  = mi.Size
  local pat   = make_pattern(pattern_hex)
  local plen  = #pat
  local hits  = {}

  local CHUNK = 0x10000  -- 64KB at a time
  local pos = base
  while pos < base + size and #hits < max_hits do
    local chunk_sz = math.min(CHUNK, base + size - pos)
    local ok, bytes = pcall(readBytes, pos, chunk_sz, true)
    if ok and bytes then
      for i = 1, #bytes - plen + 1 do
        local match = true
        for j = 1, plen do
          if pat[j] ~= -1 and bytes[i+j-1] ~= pat[j] then
            match = false
            break
          end
        end
        if match then
          hits[#hits+1] = pos + i - 1
        end
      end
    end
    pos = pos + chunk_sz
  end
  return hits
end

-- ---- get D2 module info -----------------------------------------------------
local d2 = getModuleInfo("destiny2.exe")
if not d2 then
  log("ERROR: destiny2.exe not found -- is D2 running and attached?")
  f:close()
  print("destiny2.exe not found")
  return
end
logfmt("destiny2.exe  base=%X  size=%X (%.1f MB)", d2.Address, d2.Size, d2.Size/1048576)
log("")

-- ---- 1. pStickyBase --------------------------------------------------------
log("=== 1. pStickyBase scan ===")
log("Old exact pattern: 90 95 80 80 00 00 00 00")
log("")

-- exact old
local hits, err = scan_module("destiny2.exe", "90 95 80 80 00 00 00 00", 5)
if err then log("SCAN ERROR: "..err)
elseif #hits == 0 then
  log("  exact pattern: NO HITS")
else
  logfmt("  exact pattern: %d hit(s)", #hits)
  for _, h in ipairs(hits) do dumpctx("EXACT", h, 0x20, 0x40) end
end
log("")

-- broader: any byte before 95 80 80 00 00 00 00 (covers 90 95... and nearby)
log("Wider: ?? 95 80 80 00 00 00 00")
hits = scan_module("destiny2.exe", "?? 95 80 80 00 00 00 00", 30)
if hits and #hits > 0 then
  logfmt("  %d hit(s)", #hits)
  for _, h in ipairs(hits) do dumpctx("WIDE", h, 0x20, 0x40) end
else
  log("  no hits")
end
log("")

-- even looser: 95 80 80 with any tail
log("Loose: ?? 95 80 80 ?? ?? 00 00")
hits = scan_module("destiny2.exe", "?? 95 80 80 ?? ?? 00 00", 30)
if hits and #hits > 0 then
  logfmt("  %d hit(s)", #hits)
  for i, h in ipairs(hits) do
    if i <= 10 then dumpctx("LOOSE", h, 0x10, 0x30) end
  end
else
  log("  no hits")
end
log("")

-- ---- 2. ChamsBase ----------------------------------------------------------
log("=== 2. ChamsBase scan ===")
log("Old exact pattern: A6 95 80 80 00 00 00 00")
log("")

hits = scan_module("destiny2.exe", "A6 95 80 80 00 00 00 00", 5)
if hits and #hits == 0 then
  log("  exact pattern: NO HITS")
else
  logfmt("  exact pattern: %d hit(s)", #hits and #hits or 0)
  if hits then for _, h in ipairs(hits) do dumpctx("EXACT", h, 0x20, 0x40) end end
end
log("")

-- check nearby: A? 95 80 80 family
log("Wider: A? 95 80 80 00 00 00 00  (A0..AF)")
for first = 0xA0, 0xAF do
  local pat = string.format("%02X 95 80 80 00 00 00 00", first)
  hits = scan_module("destiny2.exe", pat, 5)
  if hits and #hits > 0 then
    logfmt("  first_byte=%02X: %d hit(s)", first, #hits)
    for _, h in ipairs(hits) do dumpctx(string.format("%02X_95", first), h, 0x20, 0x40) end
  end
end
log("")

-- ---- 3. Kill Aura 3.0 ------------------------------------------------------
log("=== 3. Kill Aura 3.0 scan ===")
log("Old inject: destiny2.exe+142CB40  pattern: ?? F3 0F 10 41 20 32")
log("")

-- exact code sequence
hits = scan_module("destiny2.exe", "F3 0F 10 41 20 32 C0", 5)
if hits and #hits > 0 then
  logfmt("  F3 0F 10 41 20 32 C0: %d hit(s)", #hits)
  for _, h in ipairs(hits) do dumpctx("KILLAURA", h, 0x20, 0x40) end
else
  log("  F3 0F 10 41 20 32 C0: no hits")
  -- try without the C0 xor al,al
  hits = scan_module("destiny2.exe", "F3 0F 10 41 20 32", 10)
  if hits and #hits > 0 then
    logfmt("  F3 0F 10 41 20 32: %d hit(s)", #hits)
    for _, h in ipairs(hits) do dumpctx("KILLAURA_WIDE", h, 0x20, 0x40) end
  else
    log("  F3 0F 10 41 20 32: no hits")
    -- check old offset +0x142CB40 directly
    local old_addr = d2.Address + 0x142CB40
    logfmt("  Old offset addr: %X", old_addr)
    dumpctx("OLD_OFFSET", old_addr, 0x20, 0x40)
  end
end
log("")

-- ---- 4. Interact Aura 2.0 --------------------------------------------------
log("=== 4. Interact Aura 2.0 scan ===")
log("Old inject: destiny2.exe+14E015B  pattern: F3 42 0F 10 74 1A 6C")
log("")

hits = scan_module("destiny2.exe", "F3 42 0F 10 74 1A 6C", 5)
if hits and #hits > 0 then
  logfmt("  exact: %d hit(s)", #hits)
  for _, h in ipairs(hits) do dumpctx("INTAURA", h, 0x20, 0x40) end
else
  log("  exact: no hits")
  -- relax: F3 42 0F 10 74 with any tail
  hits = scan_module("destiny2.exe", "F3 42 0F 10 74 ?? ??", 10)
  if hits and #hits > 0 then
    logfmt("  F3 42 0F 10 74 ?? ??: %d hit(s)", #hits)
    for _, h in ipairs(hits) do dumpctx("INTAURA_WIDE", h, 0x20, 0x40) end
  else
    log("  F3 42 0F 10 74 ?? ??: no hits")
    local old_addr = d2.Address + 0x14E015B
    logfmt("  Old offset addr: %X", old_addr)
    dumpctx("OLD_OFFSET", old_addr, 0x20, 0x40)
  end
end
log("")

-- ---- done ------------------------------------------------------------------
log("=== DONE ===")
f:close()
print("Dump written to: " .. OUT)
