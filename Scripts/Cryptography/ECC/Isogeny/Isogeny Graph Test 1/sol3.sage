from tqdm import tqdm

hashes = load('data.sobj')

pad = lambda s, l: s + bytes(bool(i)*randrange(1,256) for i in range(l-len(s)))
unpad = lambda s: s[:s.index(0)] if 0 in s else s

blocksize = 3

def ji(R, invs):
    # E: y^2 + a_1 xy + a_3 y = x^3 + a_2 x^2 + a_4 x + a_6
    a1, a2, a3, a4, a6 = [R(x) for x in invs]
    b2, b4, b6, b8 = (a1*a1 + 4*a2, a1*a3 + 2*a4, a3**2 + 4*a6, a1**2 * a6 + 4*a2*a6 - a1*a3*a4 + a2*a3**2 - a4**2)
    c4, c6 = (b2**2 - 24*b4, -b2**3 + 36*b2*b4 - 216*b6)
    disc = -b2**2*b8 - 8*b4**3 - 27*b6**2 + 9*b2*b4*b6
    return c4**3 / disc

class ECC_Hash_Cracker:
    def __init__(self, a, b, blocksize):
        self.a = a
        self.b = b
        self.bs = blocksize * 8
        self.l = 2
        self.p = 2**a*3**b-1
        try:
            self.Fp2 = GF(self.p**2, modulus=x**2+1, name='i')
        except AttributeError:
            self.Fp2 = GF(self.p**2, modulus=x**2+1, name='i')
        self.Fp2xy = self.Fp2['x,y']
        self.Fp2x = self.Fp2['x']
        self.modpoly = self.Fp2xy.gen(0)^3+self.Fp2xy.gen(1)^3-self.Fp2xy.gen(0)^2*self.Fp2xy.gen(1)^2+1488*(self.Fp2xy.gen(0)^2*self.Fp2xy.gen(1)+self.Fp2xy.gen(0)*self.Fp2xy.gen(1)^2)-162000*(self.Fp2xy.gen(0)^2+self.Fp2xy.gen(1)^2)+40773375*self.Fp2xy.gen(0)*self.Fp2xy.gen(1)+8748000000*(self.Fp2xy.gen(0)+self.Fp2xy.gen(1))-157464000000000
        self.j0 = ji(self.Fp2, [0,6,0,1,0])
        
    def next_j(self, j, i, exclude = None, mode = 0):
        # mode: 0 = Return next j-invariant, 1 = Get j-invariant index
        Ej = EllipticCurve(self.Fp2,j=j)
        candidates = [Ej.isogeny_codomain(e).j_invariant() for e in Ej(0).division_points(2) if e != Ej(0)]
        assert len(candidates) == 3
        if exclude != None:
            candidates = [jj for jj in candidates if jj != exclude]
            assert len(candidates) == 2, (candidates, exclude)
        candidates.sort()
        return candidates[i] if mode == 0 else candidates.index(i)
    
    def _translate_route(self, route, h):
        head, crossroad, rev = route
        j_route_tail_reversed = [h]
        jinv = h
        last = h
        jinv = self.next_j(jinv, crossroad)
        for step in range(self.bs//2-1):
            t = (rev >> int(step)) & int(0x1)
            last, jinv = jinv, self.next_j(jinv, t, last)
            j_route_tail_reversed.append(last)
        jinv = self.j0
        last = 1728
        for step in range(self.bs//2):
            t = (head >> int(step)) & int(0x1)
            last, jinv = jinv, self.next_j(jinv, t, last)
        tail = ''
        for j in j_route_tail_reversed[::-1]:
            idx = self.next_j(jinv, j, last, 1)
            last, jinv = jinv, j
            tail += str(idx)
        data = (bin(head)[2:].zfill(self.bs//2)[::-1]+tail)[::-1]
        return bytes((int(data, 2) >> (int(self.bs) - int(i*8) - 8)) & int(0xff) for i in range(self.bs//8))[::-1]

    def crack(self, h):
        table = dict()
        for curr in tqdm(range(2**(self.bs//2))):
            jinv = self.j0
            last = 1728
            for step in range(self.bs//2):
                t = (curr >> int(step)) & int(0x1)
                last, jinv = jinv, self.next_j(jinv, t, last)
            table.update({str(jinv): curr})
        for curr in tqdm(range(2**(self.bs//2-1))):
            for first_step in range(3):
                last = h
                jinv = self.next_j(h, first_step)
                for step in range(self.bs//2-1):
                    t = (curr >> int(step)) & int(0x1)
                    last, jinv = jinv, self.next_j(jinv, t, last)
                if str(jinv) in table:
                    yield self._translate_route([table[str(jinv)], first_step, curr], h)

a = 18
b = 13

cracker = ECC_Hash_Cracker(a, b, blocksize)
mt = b''
for i, h in enumerate(hashes):
    print(f'[\x1b[34;1m*\x1b[0m] Progress: \x1b[1m%{len(str(len(hashes)))+1}d\x1b[0m / %{len(str(len(hashes)))+1}d' % (i+1, len(hashes)))
    cand = b'\0' * blocksize
    for mt_block in cracker.crack(h):
        cand = mt_block
        if all(c in range(32, 127) for c in mt_block):
            print()
            print('[\x1b[32;1m+\x1b[0m] Found: %s' % str(mt_block))
            break
    mt += cand
    print()
print('\n[\x1b[32;1m+\x1b[0m] Flag:\n"\x1b[33;1m%s\x1b[0m"' % ''.join(chr(c) if c in range(32, 127) else '\x1b[31;1m·\x1b[33;1m' for c in mt))