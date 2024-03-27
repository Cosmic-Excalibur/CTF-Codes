from Crypto.Util.number import *
from subprocess import check_output
from re import findall
from functools import partial
from tqdm import tqdm
import random

def flatter(M):
    # compile https://github.com/keeganryan/flatter and put it in $PATH
    z = "[[" + "]\n[".join(" ".join(map(str, row)) for row in M) + "]]"
    ret = check_output(["flatter"], input=z.encode())
    return matrix(M.nrows(), M.ncols(), map(ZZ, findall(b"-?\\d+", ret)))

_green = lambda s: '\033[32m\033[1m%s\033[0m' % s
_red = lambda s: '\033[31m\033[1m%s\033[0m' % s
_yellow = lambda s: '\033[33m\033[1m%s\033[0m' % s
_blue = lambda s: '\033[34m\033[1m%s\033[0m' % s

def gen_task(pbits, leakbits):
    p = getPrime(int(pbits))
    q = getPrime(int(pbits))
    pbar = p >> pbits - leakbits << pbits - leakbits
    return p, q, pbar

def highbits_leakage(N, pbar, epsilon, beta):
    d = 1
    h = ceil(beta**2/epsilon/d)
    k = ceil(d*h/beta)
    X = ceil((N^(beta^2/d-epsilon)))
    P.<x> = ZZ[]
    f = pbar + x
    L = matrix(ZZ, k + 1, k + 1)
    print(f'{_blue("β = ")}%s\n{_blue("ε = ")}%s\n{_blue("Bound of x (%s bits): " % X.nbits())}%s' % (beta, epsilon, X))
    for i in range(h*d):
        for j, l in enumerate(f ^ i):
            L[i, j] = N ^ (h - i) * l * X ^ j
    for i in range(k - h*d + 1):
        for j, l in enumerate(x ^ i * f ^ h):
            L[i + h*d, j] = l * X ^ j
    print(_green("Reducing %s x %s Lattice :)" % L.dimensions()))
    #L_ = L.LLL()
    L_ = flatter(L)
    g = sum(j * x ^ i / X ^ i for i, j in enumerate(L_[0]))
    roots = g.roots()
    p = 1
    if roots:
        p = roots[0][0] + pbar
    if p in [0, 1, N] or N % p:
        return 1, N
    return int(p), int(N/p)