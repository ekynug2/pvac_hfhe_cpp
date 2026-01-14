import struct
import re

def read_u32(f):
    data = f.read(4)
    if not data: raise EOFError
    return struct.unpack('<I', data)[0]

def read_u64(f):
    data = f.read(8)
    if not data: raise EOFError
    return struct.unpack('<Q', data)[0]

def read_bytes(f, n):
    data = f.read(n)
    if len(data) != n: raise EOFError
    return data

def check_ascii_chunks(num, lo, hi):
    candidates = []
    
    # Check w_lo (first 64 bits)
    try:
        raw_lo = struct.pack('<Q', lo)
        if all(32 <= b <= 126 for b in raw_lo):
            candidates.append(('lo', raw_lo.decode('ascii')))
    except: pass

    # Check w_hi (second 64 bits)
    try:
        raw_hi = struct.pack('<Q', hi)
        if all(32 <= b <= 126 for b in raw_hi):
            candidates.append(('hi', raw_hi.decode('ascii')))
    except: pass

    return candidates

def main():
    DATA_DIR = "bounty3_data"
    path = f"{DATA_DIR}/seed.ct"
    
    recovered_strings = []
    
    print("[*] Starting extraction...")
    
    with open(path, 'rb') as f:
        # Header
        if read_u32(f) != 0x66699666 or read_u32(f) != 1:
            print("[-] Bad Magic")
            return
        
        ncts = read_u64(f)
        print(f"[*] Found {ncts} cipher blocks.")

        for ct_idx in range(ncts):
            nL = read_u32(f)
            nE = read_u32(f)
            print(f"[*] Block {ct_idx}: {nL} Layers, {nE} Edges")

            # Skip Layers
            for _ in range(nL):
                rule = read_bytes(f, 1)[0]
                if rule == 0: read_bytes(f, 24)
                elif rule == 1: read_bytes(f, 8)
                else: read_bytes(f, 24)
            
            # Read Edges
            for edge_idx in range(nE):
                try:
                    # Metadata
                    read_bytes(f, 8) # layer_id + idx + ch + pad
                    
                    # Read Weight (Fp)
                    w_lo = read_u64(f)
                    w_hi = read_u64(f)
                    
                    # Read BitVec s (Skip efficiently)
                    nbits = read_u32(f)
                    num_words = (nbits + 63) // 64
                    read_bytes(f, 8 * num_words) # <--- FIX: Removed the +4 here
                    
                    # Heuristic check
                    chunks = check_ascii_chunks(edge_idx, w_lo, w_hi)
                    if chunks:
                        recovered_strings.extend([txt for _, txt in chunks])

                except EOFError:
                    print(f"[!] EOF reached at Edge {edge_idx} in Block {ct_idx}")
                    break
                except Exception as e:
                    print(f"[!] Error at Edge {edge_idx}: {e}")
                    # Try to recover by seeking or breaking? 
                    # Better to break to avoid infinite loop of garbage
                    break

    print(f"\n[*] Extracted {len(recovered_strings)} ASCII chunks.")
    
    # Join and search
    full_text = "".join(recovered_strings)
    
    if "mnemonic" in full_text.lower():
        print("\n✅ SUCCESS: Found 'mnemonic' in the data!")
        # Print surrounding context
        idx = full_text.lower().find("mnemonic")
        start = max(0, idx - 20)
        end = min(len(full_text), idx + 200)
        print(f"Fragment: ...{full_text[start:end]}...")
    
    # Search for number patterns
    matches = re.findall(r'\d{5,}', full_text)
    if matches:
        print(f"\n✅ Found Numbers: {matches}")

    # If nothing found, dump raw data for analysis
    if not "mnemonic" in full_text.lower() and not matches:
        print("\n[*] No clear matches found. Dumping all readable chunks:")
        for i, s in enumerate(recovered_strings):
            print(f"{i}: {s}")

if __name__ == "__main__":
    main()
