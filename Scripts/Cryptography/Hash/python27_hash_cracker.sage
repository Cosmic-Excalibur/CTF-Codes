# SageMath 10.2
# Only for bytes with length 7 :p

P = 1000003
mask = 0xffffffffffffffff

def hash_27(x):
    l = len(x)
    y = x[0] << 7 & mask
    for i in range(l):
        y = (P * y) & mask ^^ x[i]
    y ^^= l & mask
    return y

def crack_27(hash_, l):
    h = (hash_ ^^ l) & mask
    b = [P**i for i in range(l+1)]
    b = b[:l-1] + [2**l*b[l]+b[l-1]] + [-h]
    L = matrix(ZZ, l + 2)
    beta = 2**20
    for i in range(l + 1):
        L[i,0] = b[i] * beta
        L[i,i+1] = 1
    L[-2,-1] = 2**8
    L[-1,0] = (mask + 1) * beta
    L_ = L.LLL()
    for v in L_:
        if abs(v[-1]) != 2**8: continue
        res = []
        c = v[1:-1] * sgn(v[-1])
        for i in c:
            h_ = (h-i)*pow(P,-1,mask+1)%(mask+1)
            res.append(h^^(h_*P)%(mask+1))
            h = h_
        try:
            candidate = bytes(res[::-1])
            assert hash_27(candidate) == hash_
            yield candidate
        except (ValueError, AssertionError):
            continue