# A brief, basic example that demonstrates the reality of MUPs (Multiple Use Pads) - OTPs that can be reused endlessly.
# © Copyright CORA Cyber Security Inc. (CORAcsi.com) All rights reserved 2025
#!/usr/bin/env python3
# demo_mup_pipelines_ctr_b_ctr.py
# Requires: pip install pycryptodome

from Crypto.Cipher import AES
from Crypto.Hash import HMAC, SHA256
from Crypto.Random import get_random_bytes
import os
import secrets
import binascii

# Utilities
def xor_bytes(a: bytes, b: bytes) -> bytes:
    return bytes(x ^ y for x, y in zip(a, b))

def pretty(b: bytes) -> str:
    return binascii.hexlify(b).decode()

# Crib-dragging helper: attempt to find crib occurrences when two ciphertexts were XORed (i.e., pad reused)
def crib_drag(xored: bytes, crib: bytes) -> list:
    hits = []
    n = len(xored) - len(crib) + 1
    for i in range(max(0, n)):
        segment = xored[i:i+len(crib)]
        candidate = xor_bytes(segment, crib)
        # Heuristic: printable ASCII fraction
        printable = sum(32 <= c < 127 for c in candidate)
        if printable / len(candidate) > 0.9:
            hits.append((i, candidate))
    return hits

# Sample plaintexts with repeated phrases to demonstrate pattern attacks
plaintexts = [
    b"Attack at dawn. Attack at dawn.",
    b"Attack at dawn. Retreat at noon."
]

# Pipeline A: OTP-style XOR with a reused pad (vulnerable)
def pipeline_a(pts):
    max_len = max(len(p) for p in pts)
    pad = secrets.token_bytes(max_len)  # reused pad (bad)
    cts = []
    for p in pts:
        ct = xor_bytes(p.ljust(max_len, b'\x00'), pad)
        cts.append(ct)
    return pad, cts

# Pipeline B: AES-CTR preprocessing (ephemeral key per message) then XOR with reused MUP fragment
def pipeline_b(pts):
    # Create a reused MUP fragment (same length as maximal AES-CTR ciphertext length)
    # For demonstration, we use random bytes to stand in for MUP fragments
    # In practice, MUP fragments are assembled contextually and ephemeral in memory
    max_len = 0
    aes_cts = []
    for p in pts:
        key = get_random_bytes(16)      # ephemeral AES-128 key per message
        cipher = AES.new(key, AES.MODE_CTR)  # CTR will generate a random nonce
        nonce = cipher.nonce
        ct = nonce + cipher.encrypt(p)  # store nonce || ciphertext
        aes_cts.append(ct)
        max_len = max(max_len, len(ct))
        # wipe key variable intentionally (best-effort)
        del key
    mup_fragment = secrets.token_bytes(max_len)  # reused fragment (MUP reuse demonstration)
    final_cts = []
    for ct in aes_cts:
        ct_padded = ct.ljust(max_len, b'\x00')
        final_cts.append(xor_bytes(ct_padded, mup_fragment))
    return mup_fragment, aes_cts, final_cts

# Run demos
pad_a, cts_a = pipeline_a(plaintexts)
mup_frag, aes_cts_c, final_cts_c = pipeline_b(plaintexts)

# Print concise outputs
print("=== Pipeline A: Reused OTP-style pad ===")
print("Pad (hex, first 32 bytes):", pretty(pad_a[:32]))
for i, ct in enumerate(cts_a):
    print(f"CT[{i}] (hex):", pretty(ct[:48]), " len:", len(ct))

print("\n=== Pipeline B: AES-CTR preprocess + MUP XOR (reused fragment) ===")
print("MUP fragment (hex, first 32 bytes):", pretty(mup_frag[:32]))
for i, fct in enumerate(final_cts_c):
    print(f"Final CT[{i}] (hex):", pretty(fct[:48]), " len:", len(fct))

# Crib-drag demonstration on Pipeline A (vulnerable)
print("\n--- Crib-drag test: pipeline A ---")
# XOR CT0 ^ CT1 = PT0 ^ PT1 (because same pad reused)
x01 = xor_bytes(cts_a[0], cts_a[1])
crib = b"Attack at dawn"
hits = crib_drag(x01, crib)
print("XOR(CT0,CT1) hex (first 64):", pretty(x01[:64]))
print("Crib attempts for:", crib)
if hits:
    for pos, cand in hits:
        print("Hit at pos", pos, "candidate plaintext fragment (utf-8):", cand.decode('utf-8', errors='replace'))
else:
    print("No high-confidence hits found for crib in pipeline A")

# Crib-drag demonstration on Pipeline B (should be ineffective)
print("\n--- Crib-drag test: pipeline B ---")
# For pipeline B, final_cts_c are AES-CTR(ct) XOR mup_fragment; XORing two final_cts cancels mup_fragment leaving AES-CTR(ct1)^AES-CTR(ct2)
xc01 = xor_bytes(final_cts_c[0], final_cts_c[1])
hits_c = crib_drag(xc01, crib)
print("XOR(finalCT0,finalCT1) hex (first 64):", pretty(xc01[:64]))
print("Crib attempts for:", crib)
if hits_c:
    for pos, cand in hits_c:
        print("Unexpected hit at pos", pos, "candidate (likely false positive):", cand.decode('utf-8', errors='replace'))
else:
    print("No high-confidence hits found for crib in pipeline B (expected)")

