#!/usr/bin/env python3
from Crypto.Util.number import inverse, long_to_bytes
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad
import hashlib

MASK64 = (1 << 64) - 1

def rotl(x, k):
    return ((x << k) | (x >> (64 - k))) & MASK64

def next_raw(state):
    s0, s1, s2, s3 = state
    t = (s1 << 17) & MASK64
    s2 ^= s0
    s3 ^= s1
    s1 ^= s2
    s0 ^= s3
    s2 ^= t
    s3 = rotl(s3, 45)
    return [s0 & MASK64, s1 & MASK64, s2 & MASK64, s3 & MASK64]

def temper(x):
    return (rotl((x * 5) & MASK64, 7) * 9) & MASK64

# Given data (from output.txt)
leaks = [
    0x785a1cb672480875,
    0x91c1748fec1dd008,
    0x5c52ec3a5931f942,
    0xac4a414750cd93d7
]
# Public key (not actually needed to compute d, but for verification)
Qx = 108364470534029284279984867862312730656321584938782311710100671041229823956830
Qy = 13364418211739203431596186134046538294475878411857932896543303792197679964862
# Signature and message hash (H)
r = 54809455810753652852551513610089439557885757561953942958061085530360106094036
s = 42603888460883531054964904523904896098962762092412438324944171394799397690539
H = 9529442011748664341738996529750340456157809966093480864347661556347262857832209689182090159309916943522134394915152900655982067042469766622239675961581701969877932734729317939525310618663767439074719450934795911313281256406574646718593855471365539861693353445695
cipher_hex = "404e9a7bbdac8d3912d881914ab2bdb924d85338fbd1a6d62a88d793b4b9438400489766e8e9fb157c961075ad4421fc"

# 1. Recover the PRNG state via linear algebra (Gaussian elimination).
# Build the matrix M and vector v over GF(2).
M = [[0]*256 for _ in range(256)]
v = [0]*256
for basis in range(256):
    s0 = s1 = s2 = s3 = 0
    if basis < 64:
        s0 = 1 << basis
    elif basis < 128:
        s1 = 1 << (basis - 64)
    elif basis < 192:
        s2 = 1 << (basis - 128)
    else:
        s3 = 1 << (basis - 192)
    state = [s0, s1, s2, s3]
    # simulate 4 outputs
    for i in range(4):
        state = next_raw(state)
        out = state[1]
        for bit in range(64):
            row = i*64 + bit
            M[row][basis] = (out >> bit) & 1

# Fill the output vector with actual leaked bits
for i in range(4):
    out = leaks[i]
    for bit in range(64):
        row = i*64 + bit
        v[row] = (out >> bit) & 1

# Solve M * x = v mod 2
# Gaussian elimination
aug = [row[:] + [v_val] for row, v_val in zip(M, v)]
# Forward elimination
for col in range(256):
    pivot = None
    for row in range(col, 256):
        if aug[row][col] == 1:
            pivot = row
            break
    if pivot is None:
        continue
    # Swap rows
    aug[col], aug[pivot] = aug[pivot], aug[col]
    # Eliminate below
    for row in range(col+1, 256):
        if aug[row][col] == 1:
            for c in range(col, 257):
                aug[row][c] ^= aug[col][c]
# Back substitution
x = [0]*256
for row in range(255, -1, -1):
    # find first 1 in row
    first_one = next((c for c in range(256) if aug[row][c] == 1), None)
    if first_one is None:
        continue
    val = aug[row][256]
    for c in range(first_one+1, 256):
        if aug[row][c] == 1:
            val ^= x[c]
    x[first_one] = val

# Extract initial state words from bits x
s0_0 = s1_0 = s2_0 = s3_0 = 0
for i in range(256):
    if x[i] == 1:
        if i < 64:
            s0_0 |= (1 << i)
        elif i < 128:
            s1_0 |= (1 << (i-64))
        elif i < 192:
            s2_0 |= (1 << (i-128))
        else:
            s3_0 |= (1 << (i-192))

print("[+] Recovered PRNG state:")
print(f"    s0 = {hex(s0_0)}")
print(f"    s1 = {hex(s1_0)}")
print(f"    s2 = {hex(s2_0)}")
print(f"    s3 = {hex(s3_0)}")

# 2. Advance PRNG to get the ECDSA nonce k
state = [s0_0, s1_0, s2_0, s3_0]
# Skip the four outputs we already have:
for _ in range(4):
    state = next_raw(state)
# Next raw output:
state = next_raw(state)
raw_s1 = state[1]
k_raw = temper(raw_s1)
n = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
k = k_raw % n
print(f"[+] Predicted nonce k (hex): {hex(k)}")

# 3. Recover ECDSA private key d
inv_r = pow(r, -1, n)
d = ((s * k - H) * inv_r) % n
print(f"[+] Recovered private key d (hex): {hex(d)}")

# 4. Decrypt the flag
iv = bytes.fromhex(cipher_hex[:32])
ciphertext = bytes.fromhex(cipher_hex[32:])
key = hashlib.sha256(long_to_bytes(d)).digest()
cipher = AES.new(key, AES.MODE_CBC, iv)
flag = unpad(cipher.decrypt(ciphertext), 16)
print("[+] Decrypted flag:", flag.decode())
