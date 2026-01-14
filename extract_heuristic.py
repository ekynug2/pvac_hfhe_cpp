import struct
import re
import sys

# ==========================================
# Helper Functions
# ==========================================
def read_u32(f):
    return struct.unpack('<I', f.read(4))[0]

def read_u64(f):
    return struct.unpack('<Q', f.read(8))[0]

def read_bytes(f, n):
    d = f.read(n)
    if len(d) != n: raise EOFError
    return d

# ==========================================
# Ciphertext Parsing (Memory Efficient)
# ==========================================
def extract_ascii_from_ct(path):
    edges_data = []
    
    with open(path, 'rb') as f:
        # Check Magic
        if read_u32(f) != 0x66699666 or read_u32(f) != 1:
            print("[-] Invalid CT Magic")
            return

        ncts = read_u64(f)
        print(f"[*] Parsing {ncts} ciphertext blocks...")

        all_candidates = []

        for _ in range(ncts):
            nL = read_u32(f)
            nE = read_u32(f)
            
            # Skip Layers (Base/Prod rules)
            for _ in range(nL):
                rule = read_bytes(f, 1)[0]
                if rule == 0: read_bytes(f, 24)
                elif rule == 1: read_bytes(f, 8)
                else: read_bytes(f, 24)
            
            # Read Edges
            for _ in range(nE):
                read_bytes(f, 8) # layer_id(4) + idx(2) + ch(1) + pad(1)
                
                # Read w (Fp: lo + hi)
                w_lo = read_u64(f)
                w_hi = read_u64(f)
                
                # Read BitVec s (skip)
                nbits = read_u32(f)
                read_bytes(f, 4 + 8 * ((nbits + 63) // 64))

                # --- HEURISTIC CHECK ---
                # If w_lo is purely printable ASCII, it might be the plaintext
                try:
                    # Interpret w_lo as 8 bytes (Little Endian)
                    raw_bytes = struct.pack('<Q', w_lo)
                    
                    # Check if all bytes are printable ASCII
                    if all(32 <= b <= 126 for b in raw_bytes):
                        decoded = raw_bytes.decode('ascii')
                        all_candidates.append(decoded)
                except:
                    pass

        return all_candidates

# ==========================================
# Analysis
# ==========================================
def main():
    DATA_DIR = "bounty3_data"
    candidates = extract_ascii_from_ct(f"{DATA_DIR}/seed.ct")

    print(f"\n[*] Found {len(candidates)} potential ASCII chunks in Edge weights.")
    
    # Join them to try and form sentences
    full_text = "".join(candidates)
    
    # Try to clean up spacing caused by null bytes if we had them, 
    # but here we only kept valid chunks.
    
    print("[*] Searching for mnemonic patterns...")
    
    # Look for the word "mnemonic"
    if "mnemonic" in full_text.lower():
        print("\n✅ FOUND 'mnemonic' IN DATA!")
        # Find context
        idx = full_text.lower().find("mnemonic")
        print("Context:", full_text[max(0, idx-10):idx+50])
    
    # Look for numbers (the secret code)
    numbers = re.findall(r'\d{4,}', full_text)
    if numbers:
        print("\n✅ FOUND POTENTIAL NUMBERS:", numbers)

    # Dump all readable chunks for manual inspection
    print("\n[*] All extracted readable chunks (potential plaintext):")
    for i, chunk in enumerate(candidates):
        if len(chunk) > 3: # Ignore short noise
            print(f"{i}: {chunk}")

if __name__ == "__main__":
    main()
