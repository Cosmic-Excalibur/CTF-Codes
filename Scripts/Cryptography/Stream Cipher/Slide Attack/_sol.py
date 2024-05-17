# About 63% success rate :(

from pwn import *
from Cipher_1KSAf import *
from Crypto.Util.number import *
from colorify import *
from tqdm import tqdm
import random

ip = '127.0.0.1'
port = 6677

r = remote(ip, port)

r.recvuntil(b'iv  = ')
iv  = bytes.fromhex(r.recvline().strip().decode())
r.recvuntil(b'enc = ')
enc = bytes.fromhex(r.recvline().strip().decode())

print("Retrieved:")
print("iv  = " + iv.hex())
print("enc = " + enc.hex())
print()

def getct(pt):
    r.sendlineafter(b'>>> ', pt.hex().encode())
    r.recvuntil(b'ct  =')
    return bytes.fromhex(r.recvline().strip().decode())

n = 4
table = dict()
pairs = set()

dummy = Cipher_1KSAf(bytes(n))
K = lambda *args: dummy.K(*args)
S = lambda *args: dummy.S(*args)
A = lambda *args: dummy.A(*args)
K_inv = lambda *args: dummy.K(*args)
S_inv = lambda *args: dummy.S_inv(*args)
A_inv = lambda *args: dummy.A_inv(*args)

tilde = lambda Q: S_inv(A_inv(Q))
bar   = lambda C: A(S(C))

for i in tqdm(random.sample(range(2**(n*8)), 2**(n*4))):    # Beware OOM!!
    pt = long_to_bytes(i, n)
    ct = getct(pt)[:n]
    pt = xor(pt, iv)
    table.update({xor(pt, bar(ct)): pt})
    pairs.add((pt, ct))

print()
for pt, ct in tqdm(pairs):
    tpt = tilde(pt)
    t = xor(tpt, ct)
    if t in table:
        k = xor(table[t], tpt)
        print()
        print("[\x1b[32;1m+\x1b[0m] Key candidate: " + colorify(k.hex()))
        try:
            cipher = Cipher_1KSAf(k, iv=iv)
            dec = cipher.decrypt(enc)
            print("[\x1b[32;1m+\x1b[0m] Flag: " + colorify(bytes_to_printable_string(dec)))
        except:
            print("[\x1b[31;1m-\x1b[0m] Decryption failed.")
        print()