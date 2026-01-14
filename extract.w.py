#!/usr/bin/env python3
import struct

def parse_seed_ct(path):
    with open(path, "rb") as f:
        data = f.read()

    # Skip global header: magic(4) + ver(4) + ncts(8)
    offset = 16
    ncts = struct.unpack("<Q", data[8:16])[0]
    print(f"[+] Found {ncts} ciphertexts")

    all_bytes = b''

    for ct_idx in range(ncts):
        if offset + 8 > len(data):
            break
        nL = struct.unpack("<I", data[offset:offset+4])[0]
        nE = struct.unpack("<I", data[offset+4:offset+8])[0]
        offset += 8
        print(f"  CT {ct_idx}: {nL} layers, {nE} edges")

        # Skip Layers: each Layer is 1 + 24 = 25 bytes? But aligned.
        # From putLayer: rule(1) + padding(7?) + seed or prod
        # In practice, Layer is 25 bytes but often padded to 32.
        # Instead, skip based on known structure from ser::putLayer
        for _ in range(nL):
            if offset + 1 > len(data):
                break
            rule = data[offset]
            offset += 1
            if rule == 0:  # RRule::BASE
                offset += 24  # 3×uint64
            elif rule == 1:  # RRule::PROD
                offset += 8   # 2×uint32
            else:
                offset += 24  # padding

        # Parse Edges
        for e in range(nE):
            if offset + 32 > len(data):
                break
            # layer_id (4), idx (2), ch (1), pad (1) → 8 bytes
            offset += 8
            # w: Fp = lo (8) + hi (8)
            w_lo = struct.unpack("<Q", data[offset:offset+8])[0]
            w_hi = struct.unpack("<Q", data[offset+8:offset+16])[0]
            offset += 16
            # s: BitVec — read nbits (4 bytes)
            if offset + 4 > len(data):
                break
            nbits = struct.unpack("<I", data[offset:offset+4])[0]
            offset += 4
            nwords = (nbits + 63) // 64
            offset += 8 * nwords  # skip s words

            # Append w_lo as 8 little-endian bytes
            all_bytes += struct.pack("<Q", w_lo)

    return all_bytes

if __name__ == "__main__":
    raw = parse_seed_ct("bounty3_data/seed.ct")
    print("\n[+] Extracted raw bytes from w.lo:")
    print(raw[:200])  # first 200 bytes

    # Try to find BIP-39 words
    try:
        text = raw.decode('ascii', errors='ignore')
        print("\n[+] ASCII interpretation:")
        print(text)
    except:
        pass

    # Save full raw for analysis
    with open("extracted_raw.bin", "wb") as f:
        f.write(raw)
    print("\n[+] Raw bytes saved to extracted_raw.bin")
