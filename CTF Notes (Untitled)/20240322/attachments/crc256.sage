def i2b_256(n):
    ret = [0] * 32
    n = int(n)
    for i in range(32):
        ret[i] = n & 0xff
        n >>= 8
    return bytes(ret[::-1])

def b2i_256(b):
    return int.from_bytes(b, 'big') % 2**256

def b2v_256(b):
    return vector(bin(b2i_256(b))[2:].zfill(256), GF(2))

def v2b_256(v):
    return i2b_256(int(''.join(map(str, list(v))), 2))

def poly2b_256(poly):
    return v2b_256(poly.list())

def b2poly_256(b, P):
    return P(list(b2v_256(b)))

def random_poly(n = 256):
    return randrange(2**n)

def crc256(msg, IN, OUT, POLY):
    msg = msg[:32].rjust(32, b'\x00')
    c = IN
    for b in msg:
        c ^^= b
        for _ in range(8):
            c = (c >> 1) ^^ (POLY & -(c & 1))
    return int(c ^^ OUT).to_bytes(32,'big')

def crc256_reverse(msgcrc, IN, OUT, POLY, crcfunc = crc256, algorithm = 'polynomial'):
    global A, c, B, G, P, PR, x
    if algorithm == 'affine':
        b = b2v_256(crcfunc(b'\x00' * 32, IN, OUT, POLY))
        A = matrix(GF(2), [b2v_256(crcfunc(i2b_256(1 << 255 - i), IN, OUT, POLY)) - b for i in range(256)]).T
        c = b2v_256(msgcrc)
        return v2b_256(A.solve_right(c - b))
    elif algorithm == 'polynomial':
        P.<x_> = GF(2)[]
        G = b2poly_256(i2b_256(poly), P) + x_ ** 256
        PR.<x> = P.quo(G)
        c = b2poly_256(msgcrc, PR)
        A = b2poly_256(i2b_256(IN), PR)
        B = b2poly_256(i2b_256(OUT), PR)
        return poly2b_256((c - B) / x ** 256 - A)[::-1]
    else:
        raise TypeError("Algorithms applicable: 'affine', 'polynomial'")