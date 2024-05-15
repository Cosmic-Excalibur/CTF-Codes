from Crypto.Util.number import *

def solve(dx, dy, dz):
    a = 25214903917
    b = 11
    q = 2**48
    x1bar, x2bar, x3bar = (int(x*2**24)*2**24 for x in (dx, dy, dz))
    A = matrix(ZZ, [
    [    1,    a, a**2],
    [    0,    q,    0],
    [    0,    0,    q]
    ])
    A_ = A.LLL()
    t = vector([x1bar + 2**23, x2bar + 2*23, x3bar + 2**23])
    t -= vector([0, b, a*b+b])
    v = vector(round(x) for x in t*A_.change_ring(RR)**-1)
    v = v * A_
    return (v[0]-b)*pow(a,-1,q)%q

mt = b''
enc = eval(open("data.txt", "r").read())
for ct in enc:
    mt += long_to_bytes(int(solve(*ct)))
print(mt)