import itertools

ramanujan_polynomial_A_table = dict()

# https://www.sciencedirect.com/science/article/pii/S0898122110001173
def ramanujan_polynomial(D, cached = 1):
    global ramanujan_polynomial_A_table
    assert D < 0 and D % 24 == 13
    rqf = BinaryQF_reduced_representatives(D, primitive_only=True)
    h = len(rqf) # class number
    c2 = sum([1/RR(qf[0]) for qf in rqf], RR(0))
    prec = c2 * RR(pi) * RR(D).abs().sqrt() / 36 / RR(log(2))
    prec = 200 + prec.ceil()  # allow for rounding error
    Rc = ComplexField(prec)
    R = Rc['t']
    Dsqrt = Rc(D.sqrt(prec = prec))
    t = R.gen()
    pol = R(1)
    Rn = [
        lambda tau: Rc(eta(3*tau)*eta(tau/3)/eta(tau)**2),
        lambda tau: Rc(eta(3*tau)*eta(tau/3+1/3)/eta(tau)**2),
        lambda tau: Rc(eta(3*tau)*eta(tau/3+2/3)/eta(tau)**2),
        lambda tau: Rc(eta(tau/3)*eta(tau/3+2/3)/eta(tau)**2),
        lambda tau: Rc(eta(tau/3)*eta(tau/3+1/3)/eta(tau)**2),
        lambda tau: Rc(eta(tau/3+2/3)*eta(tau/3+1/3)/eta(tau)**2)
    ]
    zeta72 = exp(R(2*pi*I/72))
    N = lambda n: 8 if n == 2 else (9 if n == 3 else None)
    if cached:
        zeta72_cubed_pow_table = dict()
        for k in range(24):
            zeta72_cubed_pow_table.update({k: zeta72**(3*k)})
        zeta72_cubed_pow = lambda k: zeta72_cubed_pow_table[k%24]
        # S0_table = dict()
        # S1_table = dict()
        # T2_table = dict()
        # T3_table = dict()
        # S2_table = dict()
        # S3_table = dict()
        # B_table = dict()
        # ST_table = dict()
        # ST_squared_table = dict()
        if ramanujan_polynomial_A_table:
            break
        ramanujan_polynomial_A_table = [dict() for _ in range(72)]
        for k in range(72):
            S0_tmp = matrix(Rc, 6)
            S0_tmp[0,1] = zeta72_cubed_pow(k)
            S0_tmp[1,2] = zeta72_cubed_pow(k)
            S0_tmp[2,0] = zeta72_cubed_pow(2*k)
            S0_tmp[3,4] = zeta72_cubed_pow(-k)
            S0_tmp[4,5] = zeta72_cubed_pow(-2*k)
            S0_tmp[5,3] = zeta72_cubed_pow(-k)
            S1_tmp = matrix(Rc, 6)
            S1_tmp[0,0] = 1
            S1_tmp[1,3] = 1/(zeta72_cubed_pow(k)*(-zeta72_cubed_pow(10*k)+zeta72_cubed_pow(2*k)))
            S1_tmp[2,4] = zeta72_cubed_pow(k)/(-zeta72_cubed_pow(10*k)+zeta72_cubed_pow(2*k))
            S1_tmp[3,1] = zeta72_cubed_pow(k)*(-zeta72_cubed_pow(10*k)+zeta72_cubed_pow(2*k))
            S1_tmp[4,2] = (-zeta72_cubed_pow(10*k)+zeta72_cubed_pow(2*k))/zeta72_cubed_pow(k)
            S1_tmp[5,5] = 1
            T2_tmp = S0_tmp**9
            T3_tmp = S0_tmp**(-8)
            S2_tmp = S0_tmp**(-1)*S1_tmp*S0_tmp**(-10)*S1_tmp*S0_tmp**(-1)*S1_tmp*S0_tmp**(-18)
            S3_tmp = S0_tmp**(-1)*S1_tmp*S0_tmp**7*S1_tmp*S0_tmp**(-1)*S1_tmp*S0_tmp**16
            B_tmp = matrix(Rc, 6)
            B_tmp[0,0] = 1
            if (k - 1) % 3 == 0:
                B_tmp[1,1] = zeta72**(k-1)
                B_tmp[2,2] = B_tmp[1,1]**2
                B_tmp[3,3] = B_tmp[2,2]
                B_tmp[4,4] = B_tmp[1,1]
                B_tmp[5,5] = B_tmp[1,1]**3
            elif (k - 2) % 3 == 0:
                B_tmp[1,2] = zeta72**(k-2)
                B_tmp[2,1] = zeta72**(2*k-1)
                B_tmp[3,4] = B_tmp[2,1]
                B_tmp[4,3] = B_tmp[1,2]
                B_tmp[5,5] = zeta72**(3*k-3)
            S = [S0_tmp, S1_tmp, S2_tmp, S3_tmp]
            T = [None, None, T2_tmp, T3_tmp]
            for a, b, c in tqdm(itertools.product(range(72), repeat = 3), total = int(72**3)):
                try:
                    An = lambda n: S[n]*T[n]**Zmod(N(n))(-1/a)*S[n]*T[n]**Zmod(N(n))(-a)*S[n]*T[n]**Zmod(N(n))((b-1)/2/a**2-1/a) if a % n != 0 else (T[n]**Zmod(N(n))(1-(b+1)/2)*S[n]*T[n]*S[n]*T[n] if c % n != 0 else T[n]**Zmod(N(n))(1-(b+1)/2-a)*S[n]*T[n]*S[n]*T[n]**Zmod(N(n))(1-1/(a+b+c)))
                    A_tmp = An(2)*An(3)*B_tmp
                except ZeroDivisionError:
                    continue
                ramanujan_polynomial_A_table[k].update({(a,b,c): A_tmp})
            # S0_table.update({k: S0_tmp})
            # S1_table.update({k: S1_tmp})
            # T2_table.update({k: T2_tmp})
            # T3_table.update({k: T3_tmp})
            # S2_table.update({k: S2_tmp})
            # S3_table.update({k: S3_tmp})
            # B_table.update({k: B_tmp})
            # ST_table.update({k: {2: S2_tmp*T2_tmp, 3: S3_tmp*T3_tmp}})
            # ST_squared_table.update({k: {2: S2_tmp*T2_tmp*S2_tmp*T2_tmp, 3: S3_tmp*T3_tmp*S3_tmp*T3_tmp}})
    Ln = lambda n, a, b, c: (matrix([[a,(b-1)/2],[0,1]]) if a % n != 0 else (matrix([[-(b+1)/2,-c],[1,0]]) if c % n != 0 else matrix([[-(b+1)/2-a,(1-b)/2-c],[1,-1]]))).change_ring(Rc if cached else R)
    tmp_base = []
    for qf in tqdm(rqf):
        a, b, c = list(qf)
        L = {2: Ln(2, a, b, c), 3: Ln(3, a, b, c)}
        k = round(RR(real(9*det(L[2])-8*det(L[3]))))
        if cached:
            kmod = k%72
            A = ramanujan_polynomial_A_table[kmod][(a%72,b%72,c%72)]
        else:
            S0 = matrix(R, 6)
            S0[0,1] = zeta72**(3*k)
            S0[1,2] = zeta72**(3*k)
            S0[2,0] = zeta72**(6*k)
            S0[3,4] = zeta72**(-3*k)
            S0[4,5] = zeta72**(-6*k)
            S0[5,3] = zeta72**(-3*k)
            S1 = matrix(R, 6)
            S1[0,0] = 1
            S1[1,3] = 1/(zeta72**(3*k)*(-zeta72**(30*k)+zeta72**(6*k)))
            S1[2,4] = zeta72**(3*k)/(-zeta72**(30*k)+zeta72**(6*k))
            S1[3,1] = zeta72**(3*k)*(-zeta72**(30*k)+zeta72**(6*k))
            S1[4,2] = (-zeta72**(30*k)+zeta72**(6*k))/zeta72**(3*k)
            S1[5,5] = 1
            T2 = S0**9
            T3 = S0**(-8)
            S2 = S0**(-1)*S1*S0**(-10)*S1*S0**(-1)*S1*S0**(-18)
            S3 = S0**(-1)*S1*S0**7*S1*S0**(-1)*S1*S0**16
            ST = {2: S2*T2, 3: S3*T3}
            ST_squared = {2: ST[2]**2, 3: ST[3]**2}
            B = matrix(R, 6)
            B[0,0] = 1
            if (k - 1) % 3 == 0:
                B[1,1] = zeta72**(k-1)
                B[2,2] = B[1,1]**2
                B[3,3] = B[2,2]
                B[4,4] = B[1,1]
                B[5,5] = B[1,1]**3
            elif (k - 2) % 3 == 0:
                B[1,2] = zeta72**(k-2)
                B[2,1] = zeta72**(2*k-1)
                B[3,4] = B[2,1]
                B[4,3] = B[1,2]
                B[5,5] = zeta72**(3*k-3)
            else:
                raise ValueError
            S = [S0, S1, S2, S3]
            T = [None, None, T2, T3]
            An = lambda n: S[n]*T[n]**Zmod(N(n))(-1/a)*S[n]*T[n]**Zmod(N(n))(-a)*S[n]*T[n]**Zmod(N(n))((b-1)/2/a**2-1/a) if a % n != 0 else (T[n]**Zmod(N(n))(1-(b+1)/2)*ST_squared[n] if c % n != 0 else T[n]**Zmod(N(n))(1-(b+1)/2-a)*ST[n]*S[n]*T[n]**Zmod(N(n))(1-1/(a+b+c)))
            A = An(2)*An(3)*B
        tau = Rc((-b+Dsqrt)/2/a)
        if cached:
            tmp = (zeta72_cubed_pow(2*k)-zeta72_cubed_pow(10*k))*sum(A[2,i]*Rn[i](tau) for i in range(6) if A[2,i] != 0)
            tmp_base.append(Rc(-tmp))
        else:
            tmp = (zeta72**(6*k)-zeta72**(30*k))*sum(A[2,i]*Rn[i](tau) for i in range(6) if A[2,i] != 0)
            pol *= (t - R(tmp))
    if cached:
        pol = [Rc(1)]
        for tmp in tqdm(tmp_base):
            l = len(pol)
            pol = [(pol[idx-1] if idx>0 else 0)+tmp*pol[idx] for idx in range(l)] + [Rc(1)]
    #return pol
    if cached:
        coeffs = [cof.real().round() for cof in pol]
    else:
        coeffs = [cof.real().round() for cof in pol.coefficients(sparse=False)]
    return IntegerRing()['x'](coeffs)