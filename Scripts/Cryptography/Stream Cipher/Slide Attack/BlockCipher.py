from Crypto.Util.Padding import pad, unpad
from Crypto.Util.number import bytes_to_long as b2l, long_to_bytes as l2b
from enum import Enum
from functools import reduce

bitsum = lambda data: reduce((lambda _a, _b: (_a^_b)&1), data)
bitpack = lambda data: reduce((lambda _a, _b: _a<<1|_b), data)

def chunks(g, n):
    tmp = []
    for i, j in enumerate(g):
        tmp.append(j)
        if n == 0 or (i+1) % n == 0:
            yield (_ for _ in tmp)
            tmp = []
    if tmp:
        yield (_ for _ in tmp)

class Mode(Enum):
    ECB = 0x01
    CBC = 0x02

class BlockCipher:
    def __init__(self, BLOCK_SIZE, iv = None):
        self.BLOCK_SIZE = BLOCK_SIZE    # in bits, meaning that an 8-byte block corresponds to an 64-blocksized block
        self.IV = iv
        if self.IV:
            self.mode = Mode.CBC
        else:
            self.mode = Mode.ECB
    
    def _xor(self, *args):
        return bytes(reduce((lambda _a, _b: _a ^ _b), z) for z in zip(*args))

    def _affine(self, A, v, b = None):
        # A * v + b
        # A: l x l matrix, therefore l**2/8 bytes
        # v, b: l vector, therefore l/8 bytes
        l = len(v) * 8
        b = b if b else bytes(l>>3)
        return bytes(bitpack(bitsum(A[i*l>>3|j>>3]>>(j&7)&v[j>>3]>>(j&7) for j in range(l)) for i in range(k+7, k-1, -1))^b[k>>3] for k in range(0, l, 8))
    
    def encrypt(self, msg):
        msg = pad(msg, self.BLOCK_SIZE//8)
        blocks = [msg[i:i+self.BLOCK_SIZE//8] for i in range(0, len(msg), self.BLOCK_SIZE//8)]
        
        ct = b''
        if self.mode == Mode.ECB:
            for pt in blocks:
                ct += self.encrypt_block(pt)
        elif self.mode == Mode.CBC:
            X = self.IV
            for pt in blocks:
                enc_block = self.encrypt_block(self._xor(X, pt))
                ct += enc_block
                X = enc_block
        return ct
    
    def decrypt(self, msg):
        blocks = [msg[i:i+self.BLOCK_SIZE//8] for i in range(0, len(msg), self.BLOCK_SIZE//8)]
        
        pt = b''
        if self.mode == Mode.ECB:
            for ct in blocks:
                pt += self.decrypt_block(ct)
        elif self.mode == Mode.CBC:
            for idx, ct in enumerate(blocks[::-1]):
                X = (blocks[::-1] + [self.IV])[idx + 1]
                dec_block = self._xor(X, self.decrypt_block(ct))
                pt = dec_block + pt
        return unpad(pt, self.BLOCK_SIZE//8)