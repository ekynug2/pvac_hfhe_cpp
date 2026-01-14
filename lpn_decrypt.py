import struct
import hashlib

# ==========================================
# Helper Functions (Reused from analysis)
# ==========================================
def read_u32(f):
    return struct.unpack('<I', f.read(4))[0]

def read_u64(f):
    return struct.unpack('<Q', f.read(8))[0]

def read_bytes(f, n):
    d = f.read(n)
    if len(d) != n: raise EOFError
    return d

class BitVec:
    def __init__(self, nbits, words):
        self.nbits = nbits
        self.words = words

    @staticmethod
    def read(f):
        nbits = read_u32(f)
        num_words = (nbits + 63) // 64
        words = [read_u64(f) for _ in range(num_words)]
        return BitVec(nbits, words)

    def get_bit(self, idx):
        """Get bit at index idx (0 = MSB of first word? No, usually 0 is LSB of word 0 in this context)"""
        word_idx = idx // 64
        bit_idx = idx % 64
        return (self.words[word_idx] >> bit_idx) & 1

    def dot_product(self, other):
        """Dot product (mod 2) of two BitVecs. Assumes they are same size."""
        # XOR accumulates parity
        res = 0
        # Simple loop, optimize if needed (Python is slow for this)
        # But we only do it for a few edges to test or all of them if patient
        min_len = min(len(self.words), len(other.words))
        for i in range(min_len):
            res ^= bin(self.words[i] & other.words[i]).count('1')
        return res % 2

class Fp:
    def __init__(self, lo, hi):
        self.lo = lo
        self.hi = hi

    @staticmethod
    def read(f):
        return Fp(read_u64(f), read_u64(f))

# ==========================================
# Loaders
# ==========================================
MAGIC_PK = 0x06660666
MAGIC_CT = 0x66699666
MAGIC_SK = 0x66666999
VER = 1

def load_sk(path):
    with open(path, 'rb') as f:
        if read_u32(f) != MAGIC_SK or read_u32(f) != VER:
            raise Exception("Bad SK")
        prf_k = [read_u64(f) for _ in range(4)]
        s_size = read_u64(f)
        lpn_s = [read_u64(f) for _ in range(s_size)]
        return lpn_s

def load_pk(path):
    with open(path, 'rb') as f:
        if read_u32(f) != MAGIC_PK or read_u32(f) != VER:
            raise Exception("Bad PK")
        # Skip Params
        read_u32(f); read_u32(f); read_u32(f); read_u32(f); read_u32(f)
        read_u32(f); read_u32(f); read_u32(f); read_u32(f); read_u32(f)
        read_u64(f) # canon_tag
        read_bytes(f, 32) # h_digest
        
        # Load H vectors (The Matrix A)
        h_count = read_u64(f)
        print(f"[*] Loading {h_count} H vectors from PK...")
        H = []
        for _ in range(h_count):
            H.append(BitVec.read(f))
        
        # Skip UBK and others for now (we only need H for LPN)
        # But we must skip bytes to be safe
        # ... logic to skip remaining PK bytes if needed ...
        # For this attack, we just need H and the secret s.
        return H

def parse_ct_edges(path):
    edges = []
    with open(path, 'rb') as f:
        if read_u32(f) != MAGIC_CT or read_u32(f) != VER:
            raise Exception("Bad CT")
        ncts = read_u64(f)
        
        for _ in range(ncts):
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
                read_bytes(f, 8) # layer_id + idx + ch + pad
                w = Fp.read(f)
                s = BitVec.read(f) # We might not need s for decryption if w contains the message
                edges.append(w)
    return edges

# ==========================================
# Main Decryption Logic
# ==========================================

def main():
    DATA_DIR = "bounty3_data"
    
    print("[*] Loading Secret Key...")
    sk_words = load_sk(f"{DATA_DIR}/sk.bin")
    sk_bits = BitVec(len(sk_words) * 64, sk_words)
    
    print("[*] Loading Public Key (H vectors)...")
    # Warning: This is memory intensive. 
    # If OOM, we can't do full LPN in Python easily without optimization.
    try:
        H_vecs = load_pk(f"{DATA_DIR}/pk.bin")
    except MemoryError:
        print("[-] Cannot load full PK in Python (Too much RAM).")
        print("[!] Fallback: Trying heuristic extraction from raw edges...")
        # Fallback to extract_and_search.py logic if we can't hold PK
        return

    print("[*] Parsing Ciphertext Edges...")
    # We need to map edges to their H indices.
    # We need to parse CT more carefully to get `idx`.
    # Let's re-implement parsing to get `idx`.
    
    edges_data = []
    with open(f"{DATA_DIR}/seed.ct", 'rb') as f:
        read_u32(f); read_u32(f) # magic, ver
        ncts = read_u64(f)
        for _ in range(ncts):
            nL = read_u32(f)
            nE = read_u32(f)
            for _ in range(nL):
                rule = read_bytes(f, 1)[0]
                if rule == 0: read_bytes(f, 24)
                elif rule == 1: read_bytes(f, 8)
                else: read_bytes(f, 24)
            
            for _ in range(nE):
                layer_id = read_u32(f)
                idx_bytes = read_bytes(f, 2)
                idx = struct.unpack('<H', idx_bytes)[0]
                read_bytes(f, 2) # ch + pad
                w = Fp.read(f)
                s_vec = BitVec.read(f)
                
                # In PVAC, the LPN sample is usually H[idx] . s + e
                # The Plaintext is embedded in this.
                edges_data.append({'idx': idx, 'w': w})

    print(f"[*] Recovering bits from {len(edges_data)} edges...")
    
    recovered_bits = []
    
    # This loop is computationally heavy in Python. 
    # We limit to first few edges to demonstrate.
    # If this works, the plaintext is recoverable.
    
    # Optimization: We are looking for ASCII. 
    # If `w` is small, it might be the plaintext directly? 
    # No, w is usually modulo 2^128 or similar.
    
    # Let's try checking if `w.lo` contains ASCII directly (Known Plaintext Attack assumption)
    print("\n[*] Heuristic: Checking Edge weights for ASCII...")
    ascii_buffer = ""
    
    for i, e in enumerate(edges_data):
        # Check if low 64-bits look like ASCII
        lo = e['w'].lo
        # Extract 8 chars from the 64-bit integer (Little Endian)
        try:
            chars = struct.unpack('<8c', struct.pack('<Q', lo))
            decoded = "".join([c.decode('ascii', errors='ignore') for c in chars])
            
            # Filter for printable
            if all(32 <= ord(c) <= 126 for c in decoded):
                ascii_buffer += decoded
            else:
                # If non-printable, insert newline to separate segments
                if ascii_buffer and ascii_buffer[-1] != '\n':
                    ascii_buffer += "\n"
        except:
            pass
            
        if i > 1000: break # Check first 1000 edges

    print("[*] Extracted ASCII snippets:")
    for line in ascii_buffer.split('\n'):
        if len(line) > 4:
            print(line)

if __name__ == "__main__":
    main()
