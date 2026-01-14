# extract_ztag.py
import struct

with open("bounty3_data/seed.ct", "rb") as f:
    data = f.read()

offset = 16
ncts = struct.unpack("<Q", data[8:16])[0]

for ct_idx in range(ncts):
    nL = struct.unpack("<I", data[offset:offset+4])[0]
    nE = struct.unpack("<I", data[offset+4:offset+8])[0]
    offset += 8

    print(f"\nCiphertext {ct_idx}: {nL} layers")
    for i in range(nL):
        rule = data[offset]; offset += 1
        if rule == 0:  # BASE
            ztag = struct.unpack("<Q", data[offset:offset+8])[0]
            nonce_lo = struct.unpack("<Q", data[offset+8:offset+16])[0]
            nonce_hi = struct.unpack("<Q", data[offset+16:offset+24])[0]
            offset += 24
            print(f"  Layer {i} (BASE): ztag={ztag}, nonce=({nonce_lo}, {nonce_hi})")
        elif rule == 1:  # PROD
            pa = struct.unpack("<I", data[offset:offset+4])[0]
            pb = struct.unpack("<I", data[offset+4:offset+8])[0]
            offset += 8
            print(f"  Layer {i} (PROD): pa={pa}, pb={pb}")
        else:
            offset += 24
