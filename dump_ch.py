import struct

def read_u32(f):
    return struct.unpack('<I', f.read(4))[0]

def read_u64(f):
    return struct.unpack('<Q', f.read(8))[0]

def read_bytes(f, n):
    return f.read(n)

def main():
    path = "bounty3_data/seed.ct"
    
    edges = []

    with open(path, 'rb') as f:
        # Header
        if read_u32(f) != 0x66699666: return
        f.read(4) # Ver
        ncts = read_u64(f)

        for ct_idx in range(ncts):
            nL = read_u32(f)
            nE = read_u32(f)
            
            # Skip Layers
            for _ in range(nL):
                rule = read_bytes(f, 1)[0]
                if rule == 0: read_bytes(f, 24)
                elif rule == 1: read_bytes(f, 8)
                else: read_bytes(f, 24)
            
            # Read Edges
            for _ in range(nE):
                layer_id = read_u32(f)
                idx = struct.unpack('<H', f.read(2))[0]
                ch = read_bytes(f, 1)[0]
                pad = read_bytes(f, 1)[0]
                
                # Skip w (Fp) and s (BitVec)
                read_u64(f); read_u64(f) # w.lo, w.hi
                nbits = read_u32(f)
                read_bytes(f, 8 * ((nbits + 63) // 64))

                edges.append({
                    "block": ct_idx,
                    "layer": layer_id,
                    "idx": idx,
                    "ch": ch,
                    "char": chr(ch) if 32 <= ch <= 126 else f"0x{ch:02x}"
                })

    # Strategy 1: Concatenate all 'ch' bytes in file order
    print("[*] Attempt 1: Concatenating all 'ch' bytes (File Order)...")
    file_order_str = "".join([e['char'] for e in edges if e['ch'] >= 32])
    print(file_order_str)

    # Strategy 2: Sort by Layer, then Index
    # Perhaps the plaintext is reconstructed by sorting these edges
    print("\n[*] Attempt 2: Sorting by (Layer, idx)...")
    sorted_edges = sorted(edges, key=lambda x: (x['layer'], x['idx']))
    sorted_str = "".join([e['char'] for e in sorted_edges if e['ch'] >= 32])
    print(sorted_str)

    # Strategy 3: Just print raw hex of 'ch' for debugging
    print("\n[*] Attempt 3: Raw 'ch' hex stream:")
    hex_str = " ".join([f"{e['ch']:02x}" for e in edges])
    print(hex_str)

if __name__ == "__main__":
    main()
