import struct
import re

# ==========================================
# Loaders
# ==========================================

def load_sk(path):
    """Loads the Secret Key (64 words, 4096 bits)."""
    with open(path, 'rb') as f:
        # Check Magic
        if struct.unpack('<I', f.read(4))[0] != 0x66666999:
            raise Exception("Bad SK Magic")
        f.read(4) # Ver
        
        # Skip PRF Key (4 * 8 bytes)
        f.read(32)
        
        # Read LPN Secret Vector
        s_size = struct.unpack('<Q', f.read(8))[0] # Should be 64
        s_words = [struct.unpack('<Q', f.read(8))[0] for _ in range(s_size)]
        return s_words

# ==========================================
# PK Seeker (Memory Efficient)
# ==========================================

class PKSparseLookup:
    def __init__(self, path):
        self.f = open(path, 'rb')
        # Header size calculation (Magic + Ver + Params + CanonTag + HDigest)
        # Params: 9 ints (36) + 1 u64 (tuple2) + 1 int (edge_budget) = 36 + 8 + 4 = 48
        # CanonTag: 8
        # HDigest: 32
        # Magic/Ver: 8
        self.header_size = 8 + 48 + 8 + 32 # = 96 bytes
        self.sk_nbits = 8192 # From params.json lpn_n (assuming H vectors match secret size)
        
        # Calculate size of one H vector in file
        # Structure: nbits(4) + data
        # data size = (8192 + 63) // 64 * 8 = 128 * 8 = 1024 bytes
        self.vec_bytes = 4 + 1024

    def get_h_vector(self, idx):
        """Reads a specific H vector from disk without loading the whole file."""
        # Offset = Header + (Index * VectorSize)
        offset = self.header_size + (idx * self.vec_bytes)
        
        self.f.seek(offset)
        
        # Read header to be sure
        nbits = struct.unpack('<I', self.f.read(4))[0]
        if nbits != self.sk_nbits:
            # Fallback: If size differs, we can't easily seek. 
            # Assuming uniform size for performance in this challenge.
            pass
            
        # Read 128 words
        words = [struct.unpack('<Q', self.f.read(8))[0] for _ in range(128)]
        return words

    def close(self):
        self.f.close()

# ==========================================
# LPN Math
# ==========================================

def calc_lpnp_parity(h_vec, s_vec):
    """Calculates dot product of H and S (mod 2)."""
    acc = 0
    for h, s in zip(h_vec, s_vec):
        # XOR the parity of (h & s)
        # .bit_count() is fast in Python 3.8+
        acc ^= (h & s).bit_count() & 1
    return acc

# ==========================================
# Main
# ==========================================

def main():
    DATA_DIR = "bounty3_data"
    
    print("[*] Loading Secret Key...")
    sk = load_sk(f"{DATA_DIR}/sk.bin")
    print(f"    Loaded {len(sk)} words (4096 bits).")

    print("[*] Initializing Sparse PK Lookup...")
    pk = PKSparseLookup(f"{DATA_DIR}/pk.bin")

    print("[*] Parsing Ciphertext and Decrypting...")
    
    recovered_candidates = {
        "w_lo_raw": [],
        "w_lo_xor_parity": [],
        "w_hi_raw": [],
        "w_hi_xor_parity": [],
        "parity_stream": []
    }

    with open(f"{DATA_DIR}/seed.ct", 'rb') as f:
        # CT Header
        if struct.unpack('<I', f.read(4))[0] != 0x66699666: return
        f.read(4) # Ver
        ncts = struct.unpack('<Q', f.read(8))[0]

        for ct_idx in range(ncts):
            nL = struct.unpack('<I', f.read(4))[0]
            nE = struct.unpack('<I', f.read(4))[0]
            
            # Skip Layers
            for _ in range(nL):
                rule = f.read(1)[0]
                if rule == 0: f.read(24)
                elif rule == 1: f.read(8)
                else: f.read(24)
            
            # Process Edges
            for edge_idx in range(nE):
                f.read(8) # meta
                
                w_lo = struct.unpack('<Q', f.read(8))[0]
                w_hi = struct.unpack('<Q', f.read(8))[0]
                
                # Read s (Skip)
                nbits = struct.unpack('<I', f.read(4))[0]
                f.read(8 * ((nbits + 63) // 64))
                
                # DECRYPTION STEP
                # We need the idx of the H vector. 
                # WAIT: In Edge struct: u32 layer_id, u16 idx...
                # The metadata we skipped was layer_id(4) + idx(2) + ch(1) + pad(1) = 8 bytes.
                # We need to RE-READ that to get idx.
                # Let's adjust the reading to get idx.
                
    # RE-DOING PARSING TO CAPTURE IDX
    print("[*] Re-parsing with Index Capture...")
    
    with open(f"{DATA_DIR}/seed.ct", 'rb') as f:
        f.read(8) # Magic, Ver
        ncts = struct.unpack('<Q', f.read(8))[0]

        for _ in range(ncts):
            nL = struct.unpack('<I', f.read(4))[0]
            nE = struct.unpack('<I', f.read(4))[0]
            
            # Skip Layers
            for _ in range(nL):
                rule = f.read(1)[0]
                if rule == 0: f.read(24)
                elif rule == 1: f.read(8)
                else: f.read(24)
            
            for _ in range(nE):
                layer_id = struct.unpack('<I', f.read(4))[0]
                idx = struct.unpack('<H', f.read(2))[0]
                f.read(2) # ch, pad
                
                w_lo = struct.unpack('<Q', f.read(8))[0]
                w_hi = struct.unpack('<Q', f.read(8))[0]
                
                # Skip s
                nbits = struct.unpack('<I', f.read(4))[0]
                f.read(8 * ((nbits + 63) // 64))

                # Get H vector and Compute Parity
                try:
                    h_vec = pk.get_h_vector(idx)
                    parity = calc_lpnp_parity(h_vec, sk)
                    
                    # Collect Data
                    recovered_candidates["w_lo_raw"].append(w_lo & 0xFF)
                    recovered_candidates["w_lo_xor_parity"].append((w_lo & 0xFF) ^ parity)
                    
                    recovered_candidates["w_hi_raw"].append(w_hi & 0xFF)
                    recovered_candidates["w_hi_xor_parity"].append((w_hi & 0xFF) ^ parity)
                    
                    recovered_candidates["parity_stream"].append(parity)
                    
                except Exception as e:
                    print(f"Error decrypting edge idx {idx}: {e}")

    pk.close()

    # ==========================================
    # Analysis
    # ==========================================
    print("\n[*] Analysis of Recovered Streams...")
    
    # Helper to check ASCII
    def check_stream(name, byte_list):
        # Filter for printable ASCII
        # If 70%+ of bytes are printable, it's a candidate
        printable_count = sum(1 for b in byte_list if 32 <= b <= 126)
        ratio = printable_count / len(byte_list)
        
        if ratio > 0.5:
            try:
                text = "".join(chr(b) for b in byte_list)
                print(f"\n✅ CANDIDATE STREAM: {name} (Printable Ratio: {ratio:.2%})")
                
                # Search for words
                if "mnemonic" in text.lower():
                    print(">>> FOUND 'mnemonic'")
                    idx = text.lower().find("mnemonic")
                    print(f"...{text[max(0, idx-10):idx+60]}...")
                
                # Regex for number
                nums = re.findall(r'number:\s*(\d+)', text, re.IGNORECASE)
                if nums: print(f">>> FOUND NUMBER: {nums}")
                
            except: pass

    for key, val in recovered_candidates.items():
        check_stream(key, val)

    # Also check stream of parity bits reassembled
    # Parity stream is a list of 0s and 1s. Pack them into bytes.
    bits = recovered_candidates["parity_stream"]
    bytes_from_bits = []
    for i in range(0, len(bits) - 7, 8):
        byte = 0
        for j in range(8):
            byte |= (bits[i+j] << j)
        bytes_from_bits.append(byte)
    
    check_stream("Parity_Bits_Repacked", bytes_from_bits)

if __name__ == "__main__":
    main()
