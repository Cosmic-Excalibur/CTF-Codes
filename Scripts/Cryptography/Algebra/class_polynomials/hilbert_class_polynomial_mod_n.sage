from Crypto.Util.number import isPrime

def random_prime_with_disc(D, pbits):
    D = abs(Integer(D))
    ub = sqrt((2**(pbits+2)-1)/D)
    lb = sqrt((2**(pbits+1)-1)/D)
    while 1:
        s = randrange(round(lb), round(ub))
        p = (D*s**2+1)/4
        if p.is_integer() and isPrime(int(p)):
            return Integer(p)

def hilbert_class_polynomial_modulo_prime(D, p):
    #...
    pass

def hilbert_class_polynomial_modulo_integer(D, P):
    D = Integer(D)
    if D >= 0:
        raise ValueError("D (=%s) must be negative" % D)
    if (D % 4) not in [0, 1]:
        raise ValueError("D (=%s) must be a discriminant" % D)
    
    rqf = BinaryQF_reduced_representatives(D, primitive_only=True)
    h = len(rqf)
    
    pbits = round(abs(D)*log(abs(D))**6*log(log(abs(D)))**8)
    n = round(sqrt(D)*log(log(abs(D))))
    
    S = [random_prime_with_disc(D) for _ in range(n)]
    M = prod(S)
    m = [M//p for p in S]
    a = [pow(mm, -1, p) for mm, p in zip(m, S)]
    d = [aa*mm%P for aa, mm in zip(a, m)]
    #...