from subprocess import check_output
from re import findall

def flatter(M, flatter = 1):
    if flatter:
        # compile https://github.com/keeganryan/flatter and put it in $PATH
        z = "[[" + "]\n[".join(" ".join(map(str, row)) for row in M) + "]]"
        ret = check_output(["flatter"], input=z.encode())
        return matrix(M.nrows(), M.ncols(), map(ZZ, findall(b"-?\\d+", ret)))
    else:
        return M.LLL()

def random_lwe_uniform(nrows, ncols, p, Abits, xbits, ebits):
    Zp = Zmod(p)
    A = matrix(Zp, nrows, ncols, [randrange(2**Abits) for _ in range(nrows * ncols)])
    x = vector(randrange(2**xbits) for _ in range(ncols)).change_ring(Zp)
    e = vector(randrange(2**ebits) for _ in range(nrows)).change_ring(Zp)
    return (A, A * x + e), (x, e)

def err_oracle(v, ebits):
    return max([min(ZZ(x).nbits(), ZZ(-x).nbits()) for x in v]) <= ebits

def primal_attack(p, A, b, ebits):
    nrows, ncols = A.dimensions()
    L = block_matrix([
        [matrix(Zmod(p), A).T.echelon_form().change_ring(ZZ), 0],
        [matrix.zero(nrows - ncols, ncols).augment(matrix.identity(nrows - ncols) * p), 0],
        [matrix(ZZ, b), 1],
    ])
    bounds = [2**ebits] * nrows + [1]
    K = p**2
    P = diagonal_matrix([K // x for x in bounds])
    L *= P
    print("\033[32m\033[1mFlattering %s :)\033[0m"%str(L.dimensions()))
    L_ = flatter(L)
    L_ /= P
    try:
        e = vector(Zmod(p), next(v[-1] * v for v in L_ if abs(v[-1]) == 1)[:-1])
    except StopIteration:
        print("\033[31m\033[1mFailed to solve LWE :(\033[0m")
        return
    return e