from tqdm import tqdm

hashes = load('data.sobj')

pad = lambda s, l: s + bytes(bool(i)*randrange(1,256) for i in range(l-len(s)))
unpad = lambda s: s[:s.index(0)] if 0 in s else s

blocksize = 3

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
        self.E = EllipticCurve(self.Fp2, [0,6,0,1,0])
        self.E.set_order((self.p+1)**2, num_checks=0)
    def _translate_route(self, route, h):
        head, crossroad, rev = route
        j_route_tail_reversed = [h]
        E = EllipticCurve(self.Fp2, j = h)
        roots = E.torsion_polynomial(self.l).roots()
        last = E.j_invariant()
        E = E.isogeny_codomain(E.lift_x(roots[crossroad][0]))
        for step in range(self.bs//2-1):
            t = (rev >> int(step)) & int(0x1)
            roots = E.torsion_polynomial(self.l).roots()
            candidates = [E.isogeny_codomain(E.lift_x(r[0])) for r in roots]
            candidates = [e for e in candidates if e.j_invariant() != last]
            candidates.sort(key = lambda e: e.j_invariant())
            last = E.j_invariant()
            E = candidates[t]
            j_route_tail_reversed.append(last)
        E = self.E
        last = 1728
        for step in range(self.bs//2):
            t = (head >> int(step)) & int(0x1)
            roots = E.torsion_polynomial(self.l).roots()
            candidates = [E.isogeny_codomain(E.lift_x(r[0])) for r in roots]
            candidates = [e for e in candidates if e.j_invariant() != last]
            candidates.sort(key = lambda e: e.j_invariant())
            last = E.j_invariant()
            E = candidates[t]
        tail = ''
        for j in j_route_tail_reversed[::-1]:
            roots = E.torsion_polynomial(self.l).roots()
            candidates = [E.isogeny_codomain(E.lift_x(r[0])) for r in roots]
            candidates = [e for e in candidates if e.j_invariant() != last]
            candidates.sort(key = lambda e: e.j_invariant())
            idx = [e.j_invariant() for e in candidates].index(j)
            last = E.j_invariant()
            E = candidates[idx]
            tail += str(idx)
        data = (bin(head)[2:].zfill(self.bs//2)[::-1]+tail)[::-1]
        return bytes((int(data, 2) >> (int(self.bs) - int(i*8) - 8)) & int(0xff) for i in range(self.bs//8))[::-1]
    def crack(self, h):
        table = dict()
        for curr in tqdm(range(2**(self.bs//2))):
            E = self.E
            last = 1728
            for step in range(self.bs//2):
                t = (curr >> int(step)) & int(0x1)
                roots = E.torsion_polynomial(self.l).roots()
                assert len(roots) == self.l+1 and all(r[1] == 1 for r in roots)
                candidates = [E.isogeny_codomain(E.lift_x(r[0])) for r in roots]
                candidates = [e for e in candidates if e.j_invariant() != last]
                candidates.sort(key = lambda e: e.j_invariant())
                assert len(candidates) == self.l
                last = E.j_invariant()
                E = candidates[t]
            table.update({str(E.j_invariant()): curr})
        for curr in tqdm(range(2**(self.bs//2-1))):
            E = EllipticCurve(self.Fp2, j = h)
            roots = E.torsion_polynomial(self.l).roots()
            assert len(roots) == self.l+1 and all(r[1] == 1 for r in roots)
            candidates0 = [E.isogeny_codomain(E.lift_x(r[0])) for r in roots]
            last0 = E.j_invariant()
            for first_step in range(3):
                last = last0
                E = candidates0[first_step]
                for step in range(self.bs//2-1):
                    t = (curr >> int(step)) & int(0x1)
                    roots = E.torsion_polynomial(self.l).roots()
                    assert len(roots) == self.l+1 and all(r[1] == 1 for r in roots)
                    candidates = [E.isogeny_codomain(E.lift_x(r[0])) for r in roots]
                    candidates = [e for e in candidates if e.j_invariant() != last]
                    candidates.sort(key = lambda e: e.j_invariant())
                    assert len(candidates) == self.l
                    last = E.j_invariant()
                    E = candidates[t]
                if str(E.j_invariant()) in table:
                    yield self._translate_route([table[str(E.j_invariant())], first_step, curr], h)

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