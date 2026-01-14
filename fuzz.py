#!/usr/bin/env python3
import os
import hashlib
import itertools
import subprocess
import sys
from pathlib import Path

# === CONFIG ===
PK_PATH = "bounty3_data/pk.bin"
SEED_CT_PATH = "bounty3_data/seed.ct"
ENCRYPT_BIN = "./build/encrypt_custom"
TEMP_CT = "/tmp/candidate.ct"

# Known prefix/suffix from challenge description
PREFIX = "mnemonic: "
SUFFIX = ", number: "

# Use a sample BIP-39 wordlist (first 16 words for testing; replace with full list if needed)
BIP39_WORDLIST_URL = "https://raw.githubusercontent.com/bitcoin/bips/master/bip-0039/english.txt"
WORDLIST_PATH = "english.txt"

if not Path(WORDLIST_PATH).exists():
    print("[*] Downloading BIP-39 wordlist...")
    import urllib.request
    urllib.request.urlretrieve(BIP39_WORDLIST_URL, WORDLIST_PATH)

with open(WORDLIST_PATH) as f:
    WORDS = [line.strip() for line in f.readlines()]

assert len(WORDS) == 2048, "Invalid BIP-39 wordlist"

# Compute target hash of real ciphertext
with open(SEED_CT_PATH, "rb") as f:
    TARGET_BYTES = f.read()
TARGET_HASH = hashlib.sha256(TARGET_BYTES).hexdigest()

print(f"[+] Target ciphertext hash: {TARGET_HASH}")
print(f"[+] Public key size: {os.path.getsize(PK_PATH)} bytes")
print(f"[+] Using encrypter: {ENCRYPT_BIN}")

# === Helper: generate candidate plaintexts ===
def generate_candidates(max_number=1000000):
    # For efficiency, assume number is small (e.g., < 1M)
    # In real attack, you might reverse-engineer range from params.json
    for num in range(1, max_number + 1):
        # Try a fixed mnemonic first (e.g., all "abandon") to test determinism
        # Later expand to real combinations if needed
        mnemonic = " ".join(["abandon"] * 11 + ["zone"])  # valid 12-word combo
        plaintext = f"{PREFIX}{mnemonic}{SUFFIX}{num}"
        yield plaintext, num

# === Main brute-force loop ===
def main():
    print("[*] Starting deterministic R detection...")
    for plaintext, num in generate_candidates(max_number=10000):
        # Encrypt candidate
        try:
            result = subprocess.run(
                [ENCRYPT_BIN, PK_PATH, plaintext, TEMP_CT],
                capture_output=True, text=True, timeout=5
            )
            if result.returncode != 0:
                print(f"[!] Encryption failed: {result.stderr}")
                continue
        except subprocess.TimeoutExpired:
            continue

        # Compare ciphertext
        with open(TEMP_CT, "rb") as f:
            cand_bytes = f.read()

        if hashlib.sha256(cand_bytes).hexdigest() == TARGET_HASH:
            print("\n✅ MATCH FOUND!")
            print(f"Plaintext: {plaintext}")
            print(f"Number: {num}")
            with open("RECOVERED_SEED.txt", "w") as out:
                out.write(plaintext)
            return

    print("❌ No match found. Consider:")
    print(" - Expanding number range")
    print(" - Trying real mnemonic combinations")
    print(" - Checking if R depends on time/process ID")

if __name__ == "__main__":
    main()
