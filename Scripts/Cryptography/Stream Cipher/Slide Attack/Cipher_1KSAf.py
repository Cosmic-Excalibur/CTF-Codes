from BlockCipher import *

# Toy implementation, quite slow due to the bulky matrix multiplication in the A step :D
# In reality, the A step can be replaced with some easily done operations like column mixing or stuff...
class Cipher_1KSAf(BlockCipher):
    n = 4
    SBOX = b'c|w{\xf2ko\xc50\x01g+\xfe\xd7\xabv\xca\x82\xc9}\xfaYG\xf0\xad\xd4\xa2\xaf\x9c\xa4r\xc0\xb7\xfd\x93&6?\xf7\xcc4\xa5\xe5\xf1q\xd81\x15\x04\xc7#\xc3\x18\x96\x05\x9a\x07\x12\x80\xe2\xeb\'\xb2u\t\x83,\x1a\x1bnZ\xa0R;\xd6\xb3)\xe3/\x84S\xd1\x00\xed \xfc\xb1[j\xcb\xbe9JLX\xcf\xd0\xef\xaa\xfbCM3\x85E\xf9\x02\x7fP<\x9f\xa8Q\xa3@\x8f\x92\x9d8\xf5\xbc\xb6\xda!\x10\xff\xf3\xd2\xcd\x0c\x13\xec_\x97D\x17\xc4\xa7~=d]\x19s`\x81O\xdc"*\x90\x88F\xee\xb8\x14\xde^\x0b\xdb\xe02:\nI\x06$\\\xc2\xd3\xacb\x91\x95\xe4y\xe7\xc87m\x8d\xd5N\xa9lV\xf4\xeaez\xae\x08\xbax%.\x1c\xa6\xb4\xc6\xe8\xddt\x1fK\xbd\x8b\x8ap>\xb5fH\x03\xf6\x0ea5W\xb9\x86\xc1\x1d\x9e\xe1\xf8\x98\x11i\xd9\x8e\x94\x9b\x1e\x87\xe9\xceU(\xdf\x8c\xa1\x89\r\xbf\xe6BhA\x99-\x0f\xb0T\xbb\x16'
    
    # Chosen at random :)    for A(x) = A_MATRIX * x + b_VECTOR
    A_MATRIX = b'\x8a\x83~\xcd\x04\xd3\xe4\xa9\xb9N\xdf\x81\x98\xe7\xe8 O\x91\xcdY\x84\x9f2\xbb\x882S\xecj\xe3>S\xc9\xe6\x0c\x8e\x9b\x94^\x8e\xf6 &xj\xee\x9e@[.\xdb\xad\x88\xa1\xd8\xeb\\\x8c\x8f\xa8\xe0lU\xa4\x01\x1c<\xf0\xb5\x88\x89\x02C\xd8\xf9\x128q\x97\n\\\xa8\x1f\x94\xac\xf9Q7\xe1\xd4R\xcc\xd5\xd4\xc3&\xcd\xbe\xd1\xf9\x94\x89)GjWsB+\xa6[}-\xa1%\xe9\xeb\xf5\x99/\x19\xac\xb7Y\x9e\x8cV\\'
    A_MATRIX_INVERSE = b'ao\x8e\x8fXw\xb2\tFx\x96cE\xef\xf1\rL\t\xdb\x06\x1c\xaeU\xc3l}\xf0\xb8\x87\xe8\xc7\xbf\x06\xe6&\xb9\x8d\xae\xb8l@\\\xbcj\x98"\xa7\xc5\xf2I\xb4;1Fe"O\xebCm,\x9f\xd2\xd5\x81\xec&qb\x1bk,\xc7V\xc8ln5\xec\xdd\xcd-\x084$\x93\xbc\xe9\xd6|\xd0\xb7\x89\x8d\xf7\x06\xf6beA"\xb1\x1b,\xc5"\xd0\xd0\xdd\xfa\xa2*\']\x08\x94\n\x7fL\x14\xe5y\x01\x89\xc3\xde\xf5~'
    b_VECTOR = b'NM$L'
    
    def __init__(self, key, rounds = 5, iv = None):
        BLOCK_SIZE = 8 * self.n
        self.key = key
        self.rounds = rounds
        self.init_tables()
        super().__init__(BLOCK_SIZE, iv)
    
    def init_tables(self):
        self.SBOX_INVERSE = bytes(self.SBOX.index(i) for i in range(len(self.SBOX)))
        self.Ainv_b_VECTOR = self._affine(self.A_MATRIX_INVERSE, self.b_VECTOR)
        schedule = self.key_schedule(self.key)
        for r in range(self.rounds+1):
            key = next(schedule)
        self.last_key = key
    
    def K(self, state, k):
        return self._xor(state, k)
        
    def S(self, state):
        return bytes(self.SBOX[i] for i in state)
    
    def S_inv(self, state):
        return bytes(self.SBOX_INVERSE[i] for i in state)
    
    def A(self, state):
        return self._affine(self.A_MATRIX, state, self.b_VECTOR)
        
    def A_inv(self, state):
        return self._affine(self.A_MATRIX_INVERSE, state, self.Ainv_b_VECTOR)
        
    def key_schedule(self, key):
        while 1:
            yield key
    
    def key_schedule_reversed(self, key):
        while 1:
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