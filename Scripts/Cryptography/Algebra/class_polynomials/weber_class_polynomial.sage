# Toy implementation for D \equiv 1 \pmod{8}
# https://people.mpim-bonn.mpg.de/zagier/files/doi/10.1090/S0025-5718-97-00854-5/fulltext.pdf
def weber_class_polynomial_1(D, prec1 = 80, prec2 = 150):
    assert D < 0 and (D - 1) % 8 == 0 and D % 3 != 0
    rqf = BinaryQF_reduced_representatives(D, primitive_only=True)
    h = len(rqf)
    Dsqrt = D.sqrt(prec = prec1)
    R = ComplexField(prec1)['t']
    t = R.gen()
    pol = R(1)
    epsilon_d = pow(-1, (D-1)/8)
    for qf in rqf:
        a, b, c = list(qf)
        zeta_b = exp(R(2*pi*I*b/48))
        tau_Q = (-b+Dsqrt)/2/a
        q = exp(2*pi*I*tau_Q)
        if a % 2 == 0 and c % 2 == 0:
            tmp = pow(zeta_b, (a-c-a*c**2)) * q**(-1/48)*prod(1+pow(q,n-1/2) for n in range(1,prec2+1))
        elif a % 2 == 0 and c % 2 != 0:
            tmp = epsilon_d*pow(zeta_b, (a-c-a*c**2)) * q**(-1/48)*prod(1-pow(q,n-1/2) for n in range(1,prec2+1))
        elif a % 2 != 0 and c % 2 == 0:
            tmp = epsilon_d*pow(zeta_b, (a-c+a**2*c)) * (2).sqrt(prec=prec2)*q**(1/24)*prod(1+pow(q,n) for n in range(1,prec2+1))
        else:
            raise ValueError
        pol *= (t - R(tmp))
    #return pol
    coeffs = [cof.real().round() for cof in pol.coefficients(sparse=False)]
    return IntegerRing()['x'](coeffs)


# Unfinished
# https://arxiv.org/pdf/0804.1652
def weber_class_polynomial_5(D, prec = 80, prec2 = 50):
    pass