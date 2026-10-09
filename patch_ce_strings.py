#!/usr/bin/env python3
"""
Patch "Cheat Engine" strings in a CE binary.
Usage: python patch_ce_strings.py <input.exe> [output.exe]
If output is omitted, overwrites the input file.
"""
import sys
import os

REPLACEMENTS = [
    # (search_bytes, replace_bytes) — must be same length
    # ANSI variants
    (b"Cheat Engine", b"Memory Tools"),  # 12 bytes - WAIT "Cheat Engine" is 12, "Memory Tools" is 12 ✓
    (b"cheat engine", b"memory tools"),
    (b"CheatEngine",  b"MemoryTools "),  # 11->12, pad with space won't work — need same len
    (b"cheatengine",  b"memorytools"),   # 11 bytes each ✓
    (b"CHEATENGINE",  b"MEMORYTOOLS"),
    # UTF-16LE variants (each char is 2 bytes)
    ("Cheat Engine".encode("utf-16-le"), "Memory Tools".encode("utf-16-le")),
    ("cheat engine".encode("utf-16-le"), "memory tools".encode("utf-16-le")),
    ("CheatEngine".encode("utf-16-le"),  "MemoryTools".encode("utf-16-le")),
    ("cheatengine".encode("utf-16-le"),  "memorytools".encode("utf-16-le")),
    ("CHEATENGINE".encode("utf-16-le"),  "MEMORYTOOLS".encode("utf-16-le")),
]

# Fix CheatEngine -> MemoryTools_ (same length 11 chars)
REPLACEMENTS[2] = (b"CheatEngine", b"MemoryTools")  # 11 bytes each ✓

def patch(data: bytes) -> tuple[bytes, int]:
    count = 0
    for search, replace in REPLACEMENTS:
        assert len(search) == len(replace), f"Length mismatch: {search!r} vs {replace!r}"
        idx = 0
        while True:
            pos = data.find(search, idx)
            if pos == -1:
                break
            data = data[:pos] + replace + data[pos+len(replace):]
            idx = pos + len(replace)
            count += 1
    return data, count

def main():
    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} <input.exe> [output.exe]")
        sys.exit(1)

    infile = sys.argv[1]
    outfile = sys.argv[2] if len(sys.argv) > 2 else infile

    with open(infile, "rb") as f:
        data = bytearray(f.read())

    patched, n = patch(data)

    with open(outfile, "wb") as f:
        f.write(patched)

    print(f"Done. {n} replacements. Output: {outfile}")

if __name__ == "__main__":
    main()
