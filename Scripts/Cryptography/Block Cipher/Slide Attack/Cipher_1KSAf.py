from BlockCipher import *

class Cipher_1KSAf(BlockCipher):
    n = 4
    SBOX = [64, 128, 192, 1, 65, 129, 193, 2, 66, 130, 194, 3, 67, 131, 195, 4, 68, 132, 196, 5, 69, 133, 197, 6, 70, 134, 198, 7, 71, 135, 199, 8, 72, 136, 200, 9, 73, 137, 201, 10, 74, 138, 202, 11, 75, 139, 203, 12, 76, 140, 204, 13, 77, 141, 205, 14, 78, 142, 206, 15, 79, 143, 207, 16, 80, 144, 208, 17, 81, 145, 209, 18, 82, 146, 210, 19, 83, 147, 211, 20, 84, 148, 212, 21, 85, 149, 213, 22, 86, 150, 214, 23, 87, 151, 215, 24, 88, 152, 216, 25, 89, 153, 217, 26, 90, 154, 218, 27, 91, 155, 219, 28, 92, 156, 220, 29, 93, 157, 221, 30, 94, 158, 222, 31, 95, 159, 223, 32, 96, 160, 224, 33, 97, 161, 225, 34, 98, 162, 226, 35, 99, 163, 227, 36, 100, 164, 228, 37, 101, 165, 229, 38, 102, 166, 230, 39, 103, 167, 231, 40, 104, 168, 232, 41, 105, 169, 233, 42, 106, 170, 234, 43, 107, 171, 235, 44, 108, 172, 236, 45, 109, 173, 237, 46, 110, 174, 238, 47, 111, 175, 239, 48, 112, 176, 240, 49, 113, 177, 241, 50, 114, 178, 242, 51, 115, 179, 243, 52, 116, 180, 244, 53, 117, 181, 245, 54, 118, 182, 246, 55, 119, 183, 247, 56, 120, 184, 248, 57, 121, 185, 249, 58, 122, 186, 250, 59, 123, 187, 251, 60, 124, 188, 252, 61, 125, 189, 253, 62, 126, 190, 254, 63, 127, 191, 255, 0]
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