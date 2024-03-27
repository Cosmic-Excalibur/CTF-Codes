r'''

Run in SageMath

Bugs and fixes:

1) This line (2166) should been modified in some algorithm implementations below: http://localhost:8888/edit/runtime/opt/sagemath-9.3/local/lib/python3.7/site-packages/sage/rings/polynomial/multi_polynomial_element.py

2) pip3 uninstall sympy 
   pip3 install sympy==1.5.1

3) Neither of the above are needed in Algorithm 5

'''



import random, sys
from Crypto.Util.number import *
import sympy 

sys.setrecursionlimit(int(2147483647))

def polynomial_egcd(f, g):
    old_r, r = f, g
    old_s, s = 1, 0
    old_t, t = 0, 1

    while r != 0:
        try:
            q = old_r // r
            old_r, r = r, old_r - q * r
            old_s, s = s, old_s - q * s
            old_t, t = t, old_t - q * t
        except:
            raise ValueError("No inverse for r in Q.", r)

    return old_r, old_s, old_t

def polynomial_inv_mod(f, g):
    g, s, _ = polynomial_egcd(f, g)

    if g.degree() > 1:
        raise ValueError("No polynomial inverse exists.")

    return s * g.lc()**-1

def _factor_4p_1_algorithm1(D, N):
    assert D == 3
    N = int(N)
    while 1:
        x0, y0 = [random.randint(1, N) for _ in range(2)]
        A = Zmod(N)(0)
        B = Zmod(N)(y0**2 - x0**3)
        E = EllipticCurve(Zmod(N), [A, B])
        d = E.division_polynomial(N, x=Zmod(N)(x0))
        g = gcd(N, d)
        if g not in [0, 1, N]:
            return g

def _factor_4p_1_algorithm2(D, N):
    N = int(N)
    Zn = Zmod(N)
    H = hilbert_class_polynomial(-D).change_ring(Zn)
    assert H.degree() == 1
    j0 = Zn(-H(0))
    while 1:
        x0, R = [random.randint(1, N) for _ in range(2)]
        A = Zn(3*j0*R^2/(1728-j0))
        B = Zn(2*j0*R^3/(1728-j0))
        E = EllipticCurve(Zn, [A, B])
        tau = x0^3 + A*x0 + B
        Pn = Zn[x]
        Qn = Pn.quotient_ring(Pn.gen()^2 - tau)
        d = E.division_polynomial(N, x=Qn.gen())
        d0, d1 = d
        g = gcd(N, d0^2 - d1^2*tau)
        if g not in [0, 1, N]:
            return g

def _factor_4p_1_algorithm3(D, N):
    N = int(N)
    Zn = Zmod(N)
    while 1:
        P.<j, X> = Zn[]
        H = hilbert_class_polynomial(-D)(j)
        R.<j, X> = P.quo(H)
        assert H.degree() == 2
        x0, r = [random.randint(1, N) for _ in range(2)]
        A = R(3*j*r^2 * polynomial_inv_mod((1728-j).lift(), H))
        B = R(2*j*r^3 * polynomial_inv_mod((1728-j).lift(), H))
        E = EllipticCurve(R, [A, B])
        tau = x0^3 + A*x0 + B
        S.<j, X> = P.quotient_ring(ideal([H, (X^2 - tau).lift()]))
        d = E.division_polynomial(N, x=X)
        _, t, s = H.coefficients()
        a3, a1, a2, a0 = d.lift().coefficients()
        b1, b0 = ((a0 + a1*j)^2 - (a2 + a3*j)^2*tau).lift().coefficients()
        c = b0^2 + b1^2*s - b0*b1*t
        g = gcd(N, c)
        if g not in [0, 1, N]:
            return g

def _factor_4p_1_algorithm4(D, N):
    N = int(N)
    Zn = Zmod(N)
    while 1:
        P.<X, j> = Zn[]
        H = hilbert_class_polynomial(-D)(j)
        R.<X, j> = P.quo(H)
        deg = H.degree()
        x0, r = [random.randint(1, N) for _ in range(2)]
        A = R(3*j*r^2 * polynomial_inv_mod((1728-j).lift(), H))
        B = R(2*j*r^3 * polynomial_inv_mod((1728-j).lift(), H))
        E = EllipticCurve(R, [A, B])
        tau = x0^3 + A*x0 + B
        S.<X, j> = R.quotient_ring(X^2 - tau)
        d = E.division_polynomial(N, x=X, two_torsion_multiplicity=0)
        Hcoeffs = H.coefficients()[:-1][::-1]
        bcoeffs = (d*d.lift().subs({X: -X})).lift().coefficients()[::-1]
        f = int(1)
        bs = sympy.symbols('b:%d' % deg)
        js = sympy.symbols('j:%d' % deg)
        for i in range(deg):
            f *= sum([int(bi)*js[i]**k for k,bi in enumerate(bcoeffs)])
        res, _, mappings_ = sympy.symmetrize(f, js, formal=1)
        mappings = [(item[0], int((-1)**(deg-i)*Hcoeffs[deg-i-1])) for i, item in enumerate(mappings_)]
        mappings = dict(mappings)
        c = Zn(int(res.subs(mappings)))
        g = gcd(N, c)
        if g not in [0, 1, N]:
            return int(g)

def super_xgcd(f, g, N):
    toswap = False
    if f.degree() < g.degree():
        toswap = True
        f, g = g, f
    r_i = f
    r_i_plus = g
    r_i_plus_plus = f
    s_i, s_i_plus = 1, 0
    t_i, t_i_plus = 0, 1
    while (True):
        lc = r_i.lc().lift()
        lc *= r_i_plus.lc().lift()
        lc *= r_i_plus_plus.lc().lift()
        divisor = gcd(lc, N)
        if divisor > 1:
            return divisor, None, None
        q = r_i // r_i_plus
        s_i_plus_plus = s_i - q * s_i_plus
        t_i_plus_plus = t_i - q * t_i_plus
        r_i_plus_plus = r_i - q * r_i_plus
        if r_i_plus.degree() <= r_i_plus_plus.degree() or r_i_plus_plus.degree() == -1:
            if toswap == True:
                return r_i_plus, t_i_plus, s_i_plus
            else:
                return r_i_plus, s_i_plus, t_i_plus
        r_i, r_i_plus = r_i_plus, r_i_plus_plus
        s_i, s_i_plus = s_i_plus, s_i_plus_plus
        t_i, t_i_plus = t_i_plus, t_i_plus_plus
        
def _factor_4p_1_algorithm5(D, N):
    N = int(N)
    Zn = Zmod(N)
    while 1:
        P.<j> = Zn[]
        H = hilbert_class_polynomial(-D)(j)
        deg = H.degree()
        r = random.randint(1, N)
        A = 3*j*r^2 * polynomial_inv_mod((1728-j), H)
        B = 2*j*r^3 * polynomial_inv_mod((1728-j), H)
        R.<j> = P.quo(H)
        E = EllipticCurve(R, [A, B])
        d = E.division_polynomial(N, x=j, two_torsion_multiplicity=0)
        g = super_xgcd(d.lift(), H, N)[0]
        if g not in [0, 1, N]:
            return int(g)

def factor_4p_1(D, N, algorithm = 5):
    algorithm_candidates = [_factor_4p_1_algorithm1, _factor_4p_1_algorithm2, _factor_4p_1_algorithm3, _factor_4p_1_algorithm4, _factor_4p_1_algorithm5]
    return algorithm_candidates[algorithm - 1](D, N)

def gen_4p_1_prime(D, pbits):
    while 1:
        V = getRandomNBitInteger((pbits - int(D).bit_length() + 2) // 2)
        p = (D * V ** 2 + 1) / 4
        if p.denom() == 1 and isPrime(int(p)):
            return p

def RSA_4p_1_test(D = 1000003, pbits = 250):
    print("[\033[34m\033[1m*\033[0m] Generating random prime numbers...")
    p = gen_4p_1_prime(D, pbits)
    q = getPrime(pbits)
    n = p * q
    print(f"[\033[34m\033[1m*\033[0m] Expectations:\nD = {D}\nn = {n}\np = {p}\nq = {q}")
    p_ = factor_4p_1(D, n, algorithm = 5)
    if all([n % p_ == 0, p_ not in [1, n]]):
        q_ = n // p_
        print(f'\n[\033[32m\033[1m+\033[0m] Backdoor Factors Found:\n{n} == {p_} * {q_}')
    else:
        print(f'\n[\033[31m\033[1m-\033[0m] Failed :(')