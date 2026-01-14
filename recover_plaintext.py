# recover_plaintext.py
import struct
import re

def parse_edges(data):
    offset = 16  # skip header
    ncts = struct.unpack("<Q", data[8:16])[0]
    plaintext_bytes = b''

    for _ in range(ncts):
        nL = struct.unpack("<I", data[offset:offset+4])[0]
        nE = struct.unpack("<I", data[offset+4:offset+8])[0]
        offset += 8

        # Skip layers
        for _ in range(nL):
            rule = data[offset]; offset += 1
            if rule == 0: offset += 24
            elif rule == 1: offset += 8
            else: offset += 24

        # Extract w.lo from edges
        for _ in range(nE):
            offset += 8  # skip metadata
            w_lo = struct.unpack("<Q", data[offset:offset+8])[0]
            offset += 16  # skip w.hi too
            # Skip BitVec s
            nbits = struct.unpack("<I", data[offset:offset+4])[0]
            offset += 4 + 8 * ((nbits + 63) // 64)
            # Append little-endian bytes
            plaintext_bytes += struct.pack("<Q", w_lo)

    return plaintext_bytes

# Main
with open("bounty3_data/seed.ct", "rb") as f:
    raw = f.read()

pt = parse_edges(raw)

# Clean non-printable bytes
clean = bytes(b if 32 <= b <= 126 else 0 for b in pt)
segments = clean.split(b'\x00')
full_text = b''.join(segments).decode('ascii', errors='ignore')

print("Recovered text:")
print(full_text)

# Extract number
match = re.search(r'number:\s*(\d+)', full_text)
if match:
    print("\n✅ Secret number:", match.group(1))
else:
    print("\n⚠️ Number not found — try noise-tolerant decoding")
