# brute_candidates.py
import struct

def get_small_ints(path, max_val=1000):
    with open(path, "rb") as f:
        data = f.read()
    candidates = set()

    # Scan every offset for 4-byte and 8-byte LE integers
    for i in range(len(data) - 7):
        if i + 4 <= len(data):
            v32 = struct.unpack('<I', data[i:i+4])[0]
            if 0 <= v32 <= max_val:
                candidates.add(v32)
        if i + 8 <= len(data):
            v64 = struct.unpack('<Q', data[i:i+8])[0]
            if 0 <= v64 <= max_val:
                candidates.add(v64)
    return sorted(candidates)

candidates = get_small_ints("bounty3_data/seed.ct", max_val=100)
print("🔍 Candidate numbers (≤100):")
for n in candidates:
    print(n)
