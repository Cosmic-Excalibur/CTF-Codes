# Definitely a toy implementation :)
# Coded on the old-fashioned obsolete antique SageMath 9.3
# https://tanglee.top/2023/03/26/Cryptography-Topic-Multivariate-Quadratic-Cryptography/


from Crypto.Util.number import long_to_bytes, bytes_to_long
from Crypto.Util.Padding import pad, unpad
from enum import Enum

DEFAULT_A = 8
DEFAULT_N = 23
DEFAULT_G = [37, 8, 161, 225, 12, 115, 45, 68, 146, 239, 18, 247, 239, 75, 169, 223, 38, 236, 238, 93, 201, 56, 248, 1]

l2b = lambda l: long_to_bytes(int(l))
b2l = lambda b: ZZ(bytes_to_long(b))

class Mode(Enum):
    ECB = 0x01
    CBC = 0x02

class Cipher:
    def __init__(self, a = DEFAULT_A, n = DEFAULT_N, g = DEFAULT_G):
        self.a = a
        self.n = n
        self.g = g
        self.q = 2**self.a
        self.Fk = GF(self.q)
        self.Fkn = self.Fk[','.join(['x'] + [f'x{i+1}' for i in range(self.n)])]
        self.g = self.Fk['x']([self.Fk.fetch_int(i) for i in self.g])
        self.FK = self.Fkn.quotient(self.Fkn.ideal([self.g] + [xi**self.q-xi for xi in self.Fkn.gens()[1:]]))

    def phi(self, poly):
        tmp = [poly.lift().coefficient(self.Fkn.gen(0)**i) for i in range(1,self.n)]
        return vector([poly.lift()-sum(self.Fkn.gen(0)**i*tmp[i-1] for i in range(1,self.n))] + tmp).change_ring(self.FK)

    def phi_1(self, v):
        return sum(self.FK.gen(0)**i*x for i,x in enumerate(v))

    def F_tilde(self, X, theta):
        return X**(1+self.q**theta)

    def F_tilde_1(self, X, theta):
        return X**(inverse_mod(1+self.q**theta, self.q**self.n-1))

    def F(self, v, theta):
        return self.phi(self.F_tilde(self.phi_1(v), theta))

    def F_1(self, v, theta):
        return self.phi(self.F_tilde_1(self.phi_1(v), theta))

    def affine_factory(self, A, b):
        return lambda x: A*x+b

    def affine_1_factory(self, A, b):
        return lambda x: A**-1*(x-b)

    def invertible_matrix(self, R, n):
        A = random_matrix(R, n, n)
        while A.rank() < n:
            A = random_matrix(R, n, n)
        return A

    def F_bar_factory(self, L1, L2, theta):
        return lambda v: L1(self.F(L2(v), theta))

    def F_bar_1_factory(self, L1_1, L2_1, theta):
        return lambda v: L2_1(self.F_1(L1_1(v), theta))

    def f_bar_factory(self, poly):
        return lambda *params: poly.lift().subs(dict(zip(self.Fkn.gens()[1:], params)))
    
    def _xor(self, a, b):
        return b''.join(bytes([_a ^^ _b]) for _a, _b in zip(a, b))
        
    def encode_msg(self, msg):
        assert len(msg) <= self.n
        return vector(self.Fk.fetch_int(b2l(msg)//self.q**i%self.q) for i in range(self.n)).change_ring(self.FK)

    def decode_msg(self, msg):
        return l2b(sum(self.Fk(m.lift()).integer_representation()*self.q**i for i,m in enumerate(msg)))

    def keygen(self):
        A1, A2 = (self.invertible_matrix(self.Fk, self.n) for _ in '12')
        b1, b2 = (random_vector(self.Fk, self.n).change_ring(self.FK) for _ in '12')
        L1 = self.affine_factory(A1, b1)
        L2 = self.affine_factory(A2, b2)
        theta = randrange(1, self.n)
        while gcd(self.q**theta+1, self.q**self.n-1) != 1:
            theta = randrange(1, self.n)
        F_bar = self.F_bar_factory(L1, L2, theta)
        return tuple(map(self.f_bar_factory, F_bar(vector(self.FK.gens()[1:])))), ((A1, b1), (A2, b2), theta)
        # pk, sk

class Encrypt(Cipher):
    def __init__(self, pk, iv = None, a = DEFAULT_A, n = DEFAULT_N, g = DEFAULT_G):
        super(Encrypt, self).__init__(a, n, g)
        self.pk = pk
        self.IV = iv
        if self.IV:
            self.mode = Mode.CBC
            assert len(self.IV) == self.n
        else:
            self.mode = Mode.ECB

    def _encipher(self, msg):
        encoded = self.encode_msg(msg)
        return self.decode_msg(f_bar(*encoded) for f_bar in self.pk)

    def encrypt(self, msg):
        ct = b''
        padded = pad(msg, self.n)
        blocks = [padded[i:i+self.n] for i in range(0, len(padded), self.n)]
        if self.mode == Mode.ECB:
            for pt in blocks:
                ct += self._encipher(pt)
        elif self.mode == Mode.CBC:
            X = self.IV
            for pt in blocks:
                enc_block = self._encipher(self._xor(X, pt))
                ct += enc_block
                X = enc_block
        return ct

class Decrypt(Cipher):
    def __init__(self, sk, iv = None, a = DEFAULT_A, n = DEFAULT_N, g = DEFAULT_G):
        super(Decrypt, self).__init__(a, n, g)
        self.sk = sk
        self.IV = iv
        if self.IV:
            self.mode = Mode.CBC
            assert len(self.IV) == self.n
        else:
            self.mode = Mode.ECB

    def _decipher(self, enc):
        ct = self.encode_msg(enc)
        L1_1 = self.affine_1_factory(*self.sk[0])
        L2_1 = self.affine_1_factory(*self.sk[1])
        F_bar_1 = self.F_bar_1_factory(L1_1, L2_1, self.sk[2])
        return self.decode_msg(F_bar_1(ct))

    def decrypt(self, enc):
        assert len(enc)%self.n == 0
        blocks = [enc[i:i+self.n] for i in range(0, len(enc), self.n)]
        
        pt = b''
        if self.mode == Mode.ECB:
            for ct in blocks:
                pt += self._decipher(ct)
        elif self.mode == Mode.CBC:
            for idx, ct in enumerate(blocks[::-1]):
                X = (blocks[::-1] + [self.IV])[idx + 1]
                dec_block = self._xor(X, self._decipher(ct))
                pt = dec_block + pt
        return unpad(pt, self.n)
