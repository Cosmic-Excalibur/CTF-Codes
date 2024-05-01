from MI import *
import os, itertools

# Linearization Equations Attack / Chosen Plaintext Attack
class CPA_Attack(Cipher):
    kernel = None
    
    def __init__(self, pk, a = DEFAULT_A, n = DEFAULT_N, g = DEFAULT_G):
        Cipher.__init__(self, a, n, g)
        self.pk = pk
    
    def _lineq(self, msg):
        pt = self.encode_msg(msg).lift().change_ring(self.Fk)
        ct = vector(f_bar(*pt) for f_bar in self.pk).lift().change_ring(self.Fk)
        eq = vector([pt[i]*ct[j] for i in range(self.n) for j in range(self.n)] + list(pt) + list(ct) + [1])
        return eq
    
    def _genkernel(self):
        while not self.kernel:
            h = (self.n+1)**2
            w = (self.n+1)**2
            A = matrix(self.Fk, h, w)
            for i in range(h):
                eq = self._lineq(os.urandom(self.n))
                A[i] = eq
            self.kernel = A.right_kernel().matrix()
    
    def _ctkernel(self, ct):
        self._genkernel()
        A = matrix(self.Fk, self.kernel.dimensions()[0], self.n+1)
        for i in range(A.dimensions()[0]):
            for j in range(self.n):
                A[i,j] = self.kernel[i][self.n*j:self.n*(j+1)]*ct + self.kernel[i,self.n**2+j]
                A[i,self.n] = self.kernel[i][-self.n-1:-1]*ct + self.kernel[i,-1]
        return A.right_kernel().matrix()
    
    def attack(self, enc):
        ct = self.encode_msg(enc).lift().change_ring(self.Fk)
        AK = self._ctkernel(ct)
        for coeffs in itertools.product(range(self.q), repeat = AK.dimensions()[0]):
            tmp = vector(self.Fk.fetch_int(x) for x in coeffs)
            if (AK.column(-1)*tmp).integer_representation() != 1: continue
            yield self.decode_msg((tmp*AK)[:-1].change_ring(self.FK))