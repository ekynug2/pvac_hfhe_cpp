#!/usr/bin/env python3
import struct

def find_small_integers(path, max_val=1000):
    with open(path, "rb") as f:
        data = f.read()

    candidates = set()
    for i in range(len(data) - 7):  # need 8 bytes for uint64
        # Try 4-byte and 8-byte little-endian
        if i + 4 <= len(data):
            val32 = struct.unpack('<I', data[i:i+4])[0]
            if val32 < max_val:
                candidates.add((i, 4, val32))
        if i + 8 <= len(data):
            val64 = struct.unpack('<Q', data[i:i+8])[0]
            if val64 < max_val:
                candidates.add((i, 8, val64))

    # Sort by offset
    for offset, width, val in sorted(candidates):
        print(f"Offset 0x{offset:04x} ({width}-byte LE): {val}")

if __name__ == "__main__":
    find_small_integers("bounty3_data/seed.ct", max_val=100)
