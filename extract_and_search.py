#!/usr/bin/env python3
import struct
import re

# Load BIP-39 wordlist
def load_bip39():
    url = "https://raw.githubusercontent.com/bitcoin/bips/master/bip-0039/english.txt"
    try:
        with open("english.txt") as f:
            return [line.strip() for line in f.readlines()]
    except:
        import urllib.request
        print("[*] Downloading BIP-39 wordlist...")
        urllib.request.urlretrieve(url, "english.txt")
        with open("english.txt") as f:
            return [line.strip() for line in f.readlines()]

BIP39_WORDS = set(load_bip39())

def parse_edges_from_ct(data):
    offset = 16  # skip global header
    ncts = struct.unpack("<Q", data[8:16])[0]
    all_lo_le = b''
    all_lo_be = b''
    all_hi_le = b''
    all_hi_be = b''

    for _ in range(ncts):
        if offset + 8 > len(data):
            break
        nL = struct.unpack("<I", data[offset:offset+4])[0]
        nE = struct.unpack("<I", data[offset+4:offset+8])[0]
        offset += 8

        # Skip Layers
        for _ in range(nL):
            if offset >= len(data):
                break
            rule = data[offset]
            offset += 1
            if rule == 0:  # BASE
                offset += 24
            elif rule == 1:  # PROD
                offset += 8
            else:
                offset += 24

        # Parse Edges
        for _ in range(nE):
            if offset + 32 > len(data):
                break
            offset += 8  # layer_id(4) + idx(2) + ch(1) + pad(1)
            w_lo = struct.unpack("<Q", data[offset:offset+8])[0]
            w_hi = struct.unpack("<Q", data[offset+8:offset+16])[0]
            offset += 16
            # Skip BitVec s
            if offset + 4 > len(data):
                break
            nbits = struct.unpack("<I", data[offset:offset+4])[0]
            offset += 4
            nwords = (nbits + 63) // 64
            offset += 8 * nwords

            all_lo_le += struct.pack("<Q", w_lo)
            all_lo_be += struct.pack(">Q", w_lo)
            all_hi_le += struct.pack("<Q", w_hi)
            all_hi_be += struct.pack(">Q", w_hi)

    return [all_lo_le, all_lo_be, all_hi_le, all_hi_be]

def find_mnemonic_candidates(data_bytes):
    # Extract printable ASCII regions (min 4 chars)
    ascii_str = ''.join(chr(b) if 32 <= b <= 126 else '\x00' for b in data_bytes)
    segments = [s for s in ascii_str.split('\x00') if len(s) >= 20]
    candidates = []
    for seg in segments:
        words = seg.split()
        # Look for sequences of 12+ valid BIP-39 words
        for i in range(len(words) - 11):
            phrase = words[i:i+12]
            if all(w in BIP39_WORDS for w in phrase):
                full = ' '.join(phrase)
                # Try to extract number after
                rest = ' '.join(words[i+12:])
                num_match = re.search(r'number:\s*(\d+)', ' '.join(words[i:]))
                num = num_match.group(1) if num_match else '???'
                candidates.append((full, num, seg))
    return candidates

def main():
    with open("bounty3_data/seed.ct", "rb") as f:
        data = f.read()

    streams = parse_edges_from_ct(data)
    labels = ["w.lo (little-endian)", "w.lo (big-endian)", "w.hi (little-endian)", "w.hi (big-endian)"]

    found = False
    for label, raw in zip(labels, streams):
        print(f"\n[+] Analyzing: {label}")
        candidates = find_mnemonic_candidates(raw)
        if candidates:
            found = True
            for mnemonic, number, context in candidates:
                print("\n✅ POSSIBLE MNEMONIC FOUND!")
                print(f"Mnemonic: {mnemonic}")
                print(f"Number: {number}")
                print(f"Context: ...{context[:100]}...")
        else:
            print("  → No valid BIP-39 sequence found.")

    if not found:
        print("\n❌ No valid 12-word BIP-39 phrase detected in any stream.")
        print("Try: checking for partial matches, or analyzing noise structure.")

if __name__ == "__main__":
    main()
