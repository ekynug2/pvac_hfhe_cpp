# analyze.py
import struct

with open("bounty3_data/seed.ct", "rb") as f:
    data = f.read()

print("🔍 Scanning for small integers in first 64 bytes...\n")

for i in range(0, min(64, len(data) - 8)):
    # Try 4-byte and 8-byte little-endian
    if i + 4 <= len(data):
        val32 = struct.unpack('<I', data[i:i+4])[0]
        if val32 < 100:
            print(f"Offset 0x{i:02x} (4B LE): {val32}")
    if i + 8 <= len(data):
        val64 = struct.unpack('<Q', data[i:i+8])[0]
        if val64 < 100:
            print(f"Offset 0x{i:02x} (8B LE): {val64}")
