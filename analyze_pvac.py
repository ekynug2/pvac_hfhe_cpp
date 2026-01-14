import struct
import json
from pathlib import Path

# === Constants from Magic namespace ===
MAGIC_CT = 0x66699666
MAGIC_SK = 0x66666999
MAGIC_PK = 0x06660666
VER = 1

# === Helper Functions ===
def read_u32(f):
    data = f.read(4)
    if len(data) != 4:
        raise EOFError
    return struct.unpack('<I', data)[0]

def read_u64(f):
    data = f.read(8)
    if len(data) != 8:
        raise EOFError
    return struct.unpack('<Q', data)[0]

def read_bytes(f, n):
    data = f.read(n)
    if len(data) != n:
        raise EOFError
    return data

# === Structs ===

class BitVec:
    def __init__(self, nbits, words):
        self.nbits = nbits
        self.words = words  # list of uint64

    @staticmethod
    def read(f):
        nbits = read_u32(f)
        num_words = (nbits + 63) // 64
        words = [read_u64(f) for _ in range(num_words)]
        return BitVec(nbits, words)

    def to_hex(self):
        return ''.join(f'{w:016x}' for w in self.words)

    def __str__(self):
        return f"BitVec(n={self.nbits}, words={len(self.words)})"

class Fp:
    def __init__(self, lo, hi):
        self.lo = lo
        self.hi = hi

    @staticmethod
    def read(f):
        lo = read_u64(f)
        hi = read_u64(f)
        return Fp(lo, hi)

    def to_hex(self):
        return f"{self.lo:016x}{self.hi:016x}"

    def __str__(self):
        return f"Fp({self.to_hex()})"

class Edge:
    def __init__(self, layer_id, idx, ch, w, s):
        self.layer_id = layer_id
        self.idx = idx
        self.ch = ch
        self.w = w
        self.s = s

    @staticmethod
    def read(f):
        layer_id = read_u32(f)
        idx_bytes = read_bytes(f, 2)
        idx = struct.unpack('<H', idx_bytes)[0]
        ch = read_bytes(f, 1)[0]
        pad = read_bytes(f, 1) # padding
        w = Fp.read(f)
        s = BitVec.read(f)
        return Edge(layer_id, idx, ch, w, s)

    def __str__(self):
        return f"Edge(layer={self.layer_id}, idx={self.idx}, ch={chr(self.ch) if 32<self.ch<127 else '?'}, w={self.w.to_hex()[:8]}..., s={self.s.to_hex()[:8]}...)"

class Layer:
    RULE_BASE = 0
    RULE_PROD = 1
    RULE_SUM = 2 # implied

    def __init__(self, rule, ztag=None, nonce=None, pa=None, pb=None):
        self.rule = rule
        self.ztag = ztag
        self.nonce = nonce
        self.pa = pa
        self.pb = pb

    @staticmethod
    def read(f):
        rule_val = read_bytes(f, 1)[0]
        # Assuming RRule enum matches these integers
        
        if rule_val == Layer.RULE_BASE:
            ztag = read_u64(f)
            nonce = Fp.read(f)
            return Layer(rule_val, ztag=ztag, nonce=nonce)
        elif rule_val == Layer.RULE_PROD:
            pa = read_u32(f)
            pb = read_u32(f)
            return Layer(rule_val, pa=pa, pb=pb)
        else:
            # Default/Other
            read_u64(f); read_u64(f); read_u64(f) # consume 24 bytes
            return Layer(rule_val)

    def __str__(self):
        if self.rule == self.RULE_BASE:
            # This 'nonce' is likely the "R" parameter mentioned in the challenge
            return f"Layer(BASE, ztag={self.ztag}, nonce={self.nonce.to_hex()})"
        elif self.rule == self.RULE_PROD:
            return f"Layer(PROD, pa={self.pa}, pb={self.pb})"
        return f"Layer(Unknown)"

class Cipher:
    def __init__(self, layers, edges):
        self.layers = layers
        self.edges = edges

    @staticmethod
    def read(f):
        nL = read_u32(f)
        nE = read_u32(f)
        layers = [Layer.read(f) for _ in range(nL)]
        edges = [Edge.read(f) for _ in range(nE)]
        return Cipher(layers, edges)

# === Main Parsing Logic ===

def parse_seed_ct(filepath):
    print(f"[*] Parsing Ciphertext: {filepath}")
    with open(filepath, 'rb') as f:
        magic = read_u32(f)
        ver = read_u32(f)
        
        if magic != MAGIC_CT:
            print(f"[-] Invalid Magic: {hex(magic)} (expected {hex(MAGIC_CT)})")
            return None
            
        if ver != VER:
            print(f"[-] Invalid Version: {ver}")
            return None

        count = read_u64(f)
        print(f"[+] Ciphertext Count: {count}")

        cts = []
        for i in range(count):
            print(f"\n--- Cipher #{i} ---")
            ct = Cipher.read(f)
            
            # Check for "R" (Nonce) in Layers
            for j, layer in enumerate(ct.layers):
                print(f"  Layer {j}: {layer}")
                if layer.rule == Layer.RULE_BASE:
                    print(f"  >>> POTENTIAL 'R' FOUND: Nonce = {layer.nonce.to_hex()}, ZTag = {layer.ztag}")

            # Show some edges
            for j, edge in enumerate(ct.edges):
                if j < 3: 
                    print(f"  Edge {j}: {edge}")
                else:
                    print(f"  ... and {len(ct.edges)-3} more edges")
                    break
            cts.append(ct)
    
    return cts

def parse_pk_bin(filepath):
    print(f"\n[*] Parsing Public Key: {filepath}")
    with open(filepath, 'rb') as f:
        magic = read_u32(f)
        ver = read_u32(f)
        if magic != MAGIC_PK:
            print(f"[-] Invalid PK Magic")
            return

        # Params
        m_bits = read_u32(f)
        B = read_u32(f)
        lpn_t = read_u32(f)
        lpn_n = read_u32(f)
        lpn_tau_num = read_u32(f)
        lpn_tau_den = read_u32(f)
        noise_entropy = read_u32(f)
        depth_slope = read_u32(f)
        tuple2_frac = read_u64(f)
        edge_budget = read_u32(f)
        
        print(f"[+] Parameters:")
        print(f"    m_bits: {m_bits}")
        print(f"    B: {B}")
        print(f"    lpn_n (secret dimension): {lpn_n}")
        print(f"    lpn_t (samples?): {lpn_t}")
        print(f"    edge_budget: {edge_budget}")

        canon_tag = read_u64(f)
        h_digest = read_bytes(f, 32).hex()
        print(f"    canon_tag: {canon_tag}")
        print(f"    h_digest: {h_digest}")

        # Skip H vectors (Hashes) - can be large
        h_size = read_u64(f)
        print(f"    H vector count: {h_size}")
        for _ in range(h_size):
            BitVec.read(f)

        # Skip ubk
        perm_size = read_u64(f)
        for _ in range(perm_size): read_u32(f)
        inv_size = read_u64(f)
        for _ in range(inv_size): read_u32(f)

        omega_B = Fp.read(f)
        print(f"    omega_B: {omega_B.to_hex()}")

        # Skip powg_B
        powg_size = read_u64(f)
        print(f"    powg_B count: {powg_size}")
        for _ in range(powg_size):
            Fp.read(f)

def load_params(filepath):
    try:
        with open(filepath, 'r') as f:
            return json.load(f)
    except:
        return {}

# === Execution ===
if __name__ == "__main__":
    DATA_DIR = "bounty3_data"
    
    # 1. Load Params
    params = load_params(f"{DATA_DIR}/params.json")
    print("[*] Loaded params.json:", json.dumps(params, indent=2))

    # 2. Parse Seed Ciphertext
    parse_seed_ct(f"{DATA_DIR}/seed.ct")

    # 3. Parse Public Key
    # Note: pk.bin is large (16MB), this script handles it but might take a second
    parse_pk_bin(f"{DATA_DIR}/pk.bin")

    print("\n[+] Analysis Complete.")
# ... (Previous imports and classes) ...

def parse_sk_bin(filepath):
    print(f"\n[*] Parsing Secret Key: {filepath}")
    with open(filepath, 'rb') as f:
        magic = read_u32(f)
        ver = read_u32(f)
        
        if magic != MAGIC_SK:
            print(f"[-] Invalid SK Magic: {hex(magic)}")
            return None
        if ver != VER:
            print(f"[-] Invalid SK Version")
            return None

        # Read PRF Key (4 x uint64)
        prf_k = [read_u64(f) for _ in range(4)]
        print(f"[+] PRF Key: {' '.join(f'{k:016x}' for k in prf_k)}")

        # Read LPN Secret Vector (lpn_s_bits)
        s_size = read_u64(f)
        print(f"[+] LPN Secret Vector Size: {s_size} words ({s_size*64} bits)")
        
        # We won't print all words, but we verify structure
        lpn_s_bits = [read_u64(f) for _ in range(s_size)]
        
        # Just print the first few words to show we extracted it
        print(f"[+] LPN Prefix: {' '.join(f'{w:016x}' for w in lpn_s_bits[:3])} ...")
        
        return {"prf_k": prf_k, "lpn_s": lpn_s_bits}

# ... Update the execution block at the bottom ...
if __name__ == "__main__":
    DATA_DIR = "bounty3_data"
    
    # ... (Load Params) ...
    
    # ... (Parse Seed Ciphertext) ...
    # ... (Parse Public Key) ...

    # NEW: Parse Secret Key
    sk_data = parse_sk_bin(f"{DATA_DIR}/sk.bin")

    print("\n[+] Analysis Complete.")
    if sk_data:
        print("[!] Secret Key extracted. You can now theoretically decrypt the cipher.")
