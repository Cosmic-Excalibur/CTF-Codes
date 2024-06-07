from Crypto.Util.number import *

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

def solution(D, N):
    N = int(N)
    Zn = Zmod(N)
    while 1:
        P.<RT> = Zn[]
        #W = P([1, 2, -1, -1, 1, -1, -1, 1])
        #T = P([-1, 237, -235, 47, -76, 248, -159, 75, -9, 1])
        T = P(load("ramanujan_811451435.sobj"))
        h = T.degree()
        r = randrange(1, N)
        #j = (X**24 - 16)**3 * polynomial_inv_mod(X**24, W)
        j = (RT**6-27*polynomial_inv_mod(RT**6,T)-6)**3
        A = 3*j*r^2 * polynomial_inv_mod((1728-j), T)
        B = 2*j*r^3 * polynomial_inv_mod((1728-j), T)
        R.<j> = P.quo(T)
        E = EllipticCurve(R, [A, B])
        #d = E.division_polynomial(N, x=X, two_torsion_multiplicity=0)
        d = E.division_polynomial(N, x=RT, two_torsion_multiplicity=0)
        g = super_xgcd(d.lift(), T, N)[0]
        if g not in [0, 1, N]:
            return int(g)

def gen_4p_1_prime(D, pbits):
    while 1:
        V = getRandomNBitInteger((pbits - int(D).bit_length() + 2) // 2)
        p = (D * V ** 2 + 1) / 4
        if p.denom() == 1 and isPrime(int(p)):
            return p

def main(D = 811451435, pbits = 512):
    print("[\033[34m\033[1m*\033[0m] Generating random prime numbers...")
    p = gen_4p_1_prime(D, pbits)
    q = getPrime(pbits)
    n = p * q
    print(f"[\033[34m\033[1m*\033[0m] Expectations:\nD = {D}\nn = {n}\np = {p}\nq = {q}")
    p_ = solution(D, n)
    if all([n % p_ == 0, p_ not in [1, n]]):
        q_ = n // p_
        print(f'\n[\033[32m\033[1m+\033[0m] Backdoor Factors Found:\n{n} == {p_} * {q_}')
    else:
        print(f'\n[\033[31m\033[1m-\033[0m] Failed :(')

if "__main__" == __name__:
    main()