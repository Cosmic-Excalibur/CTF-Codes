from secret import flag
from Crypto.Util.number import *
from random import randint as ri

pad = lambda s, l: s + bytes([ri(0,31) * bool(i) for i in range(l - len(s))])
unpad = lambda s: s[:s.index(b'\x00')] if b'\x00' in s else s

flag = pad(flag, 42)

a = 25214903917
b = 11
q = 2**48

class Rand:
    def __init__(self, seed, a, b, q):
        self.a = a
        self.b = b
        self.q = q
        self.seed = seed
    
    def randFloat(self):
        self.seed = (self.a * self.seed + self.b) % self.q
        return int(self.seed >> 24) / 2**24

enc = []
for i in range(0, len(flag), 6):
    block = flag[i:i+6]
    rand = Rand(bytes_to_long(block), a, b, q)
    enc.append([rand.randFloat() for _ in range(3)])

with open("data.txt", "w") as f:
    f.write(str(enc))