from BlockCipher import *

class Cipher_1KSAf(BlockCipher):
    n = 4
    SBOX = [0xc, 0x5, 0x6, 0xb, 0x9, 0x0, 0xa, 0xd,
     0x3, 0xe, 0xf, 0x8, 0x4, 0x7, 0x1, 0x2]
    P = [0, 8, 16, 24, 1, 9, 17, 25, 2, 10, 18, 26, 3, 11, 19, 27,
     4, 12, 20, 28, 5, 13, 21, 29, 6, 14, 22, 30, 7, 15, 23, 31]
    
    def __init__(self, key, rounds = 5, iv = None):
        BLOCK_SIZE = 8 * self.n
        self.key = key
        self.rounds = rounds
        self.init_tables()
        super().__init__(BLOCK_SIZE, iv)
    
    def init_tables(self):
        self.SBOX_INVERSE = bytes(self.SBOX.index(i) for i in range(len(self.SBOX)))
        self.P_INVERSE = [self.P.index(i) for i in range(len(self.P))]
        schedule = self.key_schedule(self.key)
        for r in range(self.rounds+1):
            key = next(schedule)
        self.last_key = key
    
    def K(self, state, k):
        return self._xor(state, k)
        
    def S(self, state):
        return bytes(self.SBOX[state[i]&0xf]|self.SBOX[state[i]>>4&0xf]<<4 for i in range(4))
    
    def S_inv(self, state):
        return bytes(self.SBOX_INVERSE[state[i]&0xf]|self.SBOX_INVERSE[state[i]>>4&0xf]<<4 for i in range(4))
    
    def A(self, state):
        s = b2l(state)
        res = l2b(bitpack(s>>i&1 for i in self.P), self.n)
        return res
        
    def A_inv(self, state):
        s = b2l(state)
        res = l2b(bitpack(s>>i&1 for i in self.P_INVERSE), self.n)
        return res
        
    def key_schedule(self, key0):
        key = key0
        while 1:
            #key = bytes([((key[3]<<7&0xff)+(key[3]<<6&0xff)+key[0])&0xff, key[1], key[2], key[3]])
            yield key
    
    def key_schedule_reversed(self, key0):
        key = key0
        while 1:
            #key = bytes([(-(key[3]<<7&0xff)-(key[3]<<6&0xff)+key[0])&0xff, key[1], key[2], key[3]])
            yield key
        
    def encrypt_block(self, block):
        enc = block[:]
        schedule = self.key_schedule(self.key)
        for r in range(self.rounds):
            key = next(schedule)
            enc = self.K(enc, key)
            enc = self.S(enc)
            enc = self.A(enc)
        key = next(schedule)
        enc = self.K(enc, key)
        return enc
    
    def decrypt_block(self, block):
        dec = block[:]
        schedule = self.key_schedule_reversed(self.last_key)
        dec = self.K(dec, self.last_key)
        key = next(schedule)
        for r in range(self.rounds):
            dec = self.A_inv(dec)
            dec = self.S_inv(dec)
            dec = self.K(dec, key)
            key = next(schedule)
        return dec