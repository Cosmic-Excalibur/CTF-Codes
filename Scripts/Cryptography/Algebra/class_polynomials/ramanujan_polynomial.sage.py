

# This file was *autogenerated* from the file ramanujan_polynomial.sage
from sage.all_cmdline import *   # import sage library

_sage_const_0 = Integer(0); _sage_const_1 = Integer(1); _sage_const_24 = Integer(24); _sage_const_13 = Integer(13); _sage_const_36 = Integer(36); _sage_const_2 = Integer(2); _sage_const_20 = Integer(20); _sage_const_3 = Integer(3); _sage_const_72 = Integer(72); _sage_const_8 = Integer(8); _sage_const_9 = Integer(9); _sage_const_6 = Integer(6); _sage_const_4 = Integer(4); _sage_const_5 = Integer(5); _sage_const_10 = Integer(10); _sage_const_18 = Integer(18); _sage_const_7 = Integer(7); _sage_const_16 = Integer(16); _sage_const_30 = Integer(30); _sage_const_64 = Integer(64); _sage_const_32 = Integer(32); _sage_const_11 = Integer(11); _sage_const_1000000 = Integer(1000000); _sage_const_120 = Integer(120)
from tqdm import tqdm
from multiprocessing import Pool
import functools

def class_number(D):
    assert D < _sage_const_0 
    return len(BinaryQF_reduced_representatives(D, primitive_only=True))

# https://www.sciencedirect.com/science/article/pii/S0898122110001173
def ramanujan_polynomial(D, cached = _sage_const_1 ):
    assert D < _sage_const_0  and D % _sage_const_24  == _sage_const_13 
    rqf = BinaryQF_reduced_representatives(D, primitive_only=True)
    h = len(rqf) # class number
    c2 = sum([_sage_const_1 /RR(qf[_sage_const_0 ]) for qf in rqf], RR(_sage_const_0 ))
    prec = c2 * RR(pi) * RR(D).abs().sqrt() / _sage_const_36  / RR(log(_sage_const_2 ))
    prec = _sage_const_20  + prec.ceil()  # allow for rounding error
    Rc = ComplexField(prec)
    R = Rc['t']
    Dsqrt = Rc(D.sqrt(prec = prec))
    t = R.gen()
    pol = R(_sage_const_1 )
    Rn = [
        lambda tau: Rc(eta(_sage_const_3 *tau)*eta(tau/_sage_const_3 )/eta(tau)**_sage_const_2 ),
        lambda tau: Rc(eta(_sage_const_3 *tau)*eta(tau/_sage_const_3 +_sage_const_1 /_sage_const_3 )/eta(tau)**_sage_const_2 ),
        lambda tau: Rc(eta(_sage_const_3 *tau)*eta(tau/_sage_const_3 +_sage_const_2 /_sage_const_3 )/eta(tau)**_sage_const_2 ),
        lambda tau: Rc(eta(tau/_sage_const_3 )*eta(tau/_sage_const_3 +_sage_const_2 /_sage_const_3 )/eta(tau)**_sage_const_2 ),
        lambda tau: Rc(eta(tau/_sage_const_3 )*eta(tau/_sage_const_3 +_sage_const_1 /_sage_const_3 )/eta(tau)**_sage_const_2 ),
        lambda tau: Rc(eta(tau/_sage_const_3 +_sage_const_2 /_sage_const_3 )*eta(tau/_sage_const_3 +_sage_const_1 /_sage_const_3 )/eta(tau)**_sage_const_2 )
    ]
    zeta72 = exp(Rc(_sage_const_2 *pi*I/_sage_const_72 ))
    N = lambda n: _sage_const_8  if n == _sage_const_2  else (_sage_const_9  if n == _sage_const_3  else None)
    if cached:
        zeta72_cubed_pow_table = dict()
        for k in range(_sage_const_24 ):
            zeta72_cubed_pow_table.update({k: zeta72**(_sage_const_3 *k)})
        zeta72_cubed_pow = lambda k: zeta72_cubed_pow_table[k%_sage_const_24 ]
        S0_table = dict()
        S1_table = dict()
        T2_table = dict()
        T3_table = dict()
        S2_table = dict()
        S3_table = dict()
        B_table = dict()
        ST_table = dict()
        ST_squared_table = dict()
        for k in range(_sage_const_72 ):
            S0_tmp = matrix(Rc, _sage_const_6 )
            S0_tmp[_sage_const_0 ,_sage_const_1 ] = zeta72_cubed_pow(k)
            S0_tmp[_sage_const_1 ,_sage_const_2 ] = zeta72_cubed_pow(k)
            S0_tmp[_sage_const_2 ,_sage_const_0 ] = zeta72_cubed_pow(_sage_const_2 *k)
            S0_tmp[_sage_const_3 ,_sage_const_4 ] = zeta72_cubed_pow(-k)
            S0_tmp[_sage_const_4 ,_sage_const_5 ] = zeta72_cubed_pow(-_sage_const_2 *k)
            S0_tmp[_sage_const_5 ,_sage_const_3 ] = zeta72_cubed_pow(-k)
            S1_tmp = matrix(Rc, _sage_const_6 )
            S1_tmp[_sage_const_0 ,_sage_const_0 ] = _sage_const_1 
            S1_tmp[_sage_const_1 ,_sage_const_3 ] = _sage_const_1 /(zeta72_cubed_pow(k)*(-zeta72_cubed_pow(_sage_const_10 *k)+zeta72_cubed_pow(_sage_const_2 *k)))
            S1_tmp[_sage_const_2 ,_sage_const_4 ] = zeta72_cubed_pow(k)/(-zeta72_cubed_pow(_sage_const_10 *k)+zeta72_cubed_pow(_sage_const_2 *k))
            S1_tmp[_sage_const_3 ,_sage_const_1 ] = zeta72_cubed_pow(k)*(-zeta72_cubed_pow(_sage_const_10 *k)+zeta72_cubed_pow(_sage_const_2 *k))
            S1_tmp[_sage_const_4 ,_sage_const_2 ] = (-zeta72_cubed_pow(_sage_const_10 *k)+zeta72_cubed_pow(_sage_const_2 *k))/zeta72_cubed_pow(k)
            S1_tmp[_sage_const_5 ,_sage_const_5 ] = _sage_const_1 
            T2_tmp = S0_tmp**_sage_const_9 
            T3_tmp = S0_tmp**(-_sage_const_8 )
            S2_tmp = S0_tmp**(-_sage_const_1 )*S1_tmp*S0_tmp**(-_sage_const_10 )*S1_tmp*S0_tmp**(-_sage_const_1 )*S1_tmp*S0_tmp**(-_sage_const_18 )
            S3_tmp = S0_tmp**(-_sage_const_1 )*S1_tmp*S0_tmp**_sage_const_7 *S1_tmp*S0_tmp**(-_sage_const_1 )*S1_tmp*S0_tmp**_sage_const_16 
            B_tmp = matrix(Rc, _sage_const_6 )
            B_tmp[_sage_const_0 ,_sage_const_0 ] = _sage_const_1 
            if (k - _sage_const_1 ) % _sage_const_3  == _sage_const_0 :
                B_tmp[_sage_const_1 ,_sage_const_1 ] = zeta72**(k-_sage_const_1 )
                B_tmp[_sage_const_2 ,_sage_const_2 ] = B_tmp[_sage_const_1 ,_sage_const_1 ]**_sage_const_2 
                B_tmp[_sage_const_3 ,_sage_const_3 ] = B_tmp[_sage_const_2 ,_sage_const_2 ]
                B_tmp[_sage_const_4 ,_sage_const_4 ] = B_tmp[_sage_const_1 ,_sage_const_1 ]
                B_tmp[_sage_const_5 ,_sage_const_5 ] = B_tmp[_sage_const_1 ,_sage_const_1 ]**_sage_const_3 
            elif (k - _sage_const_2 ) % _sage_const_3  == _sage_const_0 :
                B_tmp[_sage_const_1 ,_sage_const_2 ] = zeta72**(k-_sage_const_2 )
                B_tmp[_sage_const_2 ,_sage_const_1 ] = zeta72**(_sage_const_2 *k-_sage_const_1 )
                B_tmp[_sage_const_3 ,_sage_const_4 ] = B_tmp[_sage_const_2 ,_sage_const_1 ]
                B_tmp[_sage_const_4 ,_sage_const_3 ] = B_tmp[_sage_const_1 ,_sage_const_2 ]
                B_tmp[_sage_const_5 ,_sage_const_5 ] = zeta72**(_sage_const_3 *k-_sage_const_3 )
            S0_table.update({k: S0_tmp})
            S1_table.update({k: S1_tmp})
            T2_table.update({k: T2_tmp})
            T3_table.update({k: T3_tmp})
            S2_table.update({k: S2_tmp})
            S3_table.update({k: S3_tmp})
            B_table.update({k: B_tmp})
            ST_table.update({k: {_sage_const_2 : S2_tmp*T2_tmp, _sage_const_3 : S3_tmp*T3_tmp}})
            ST_squared_table.update({k: {_sage_const_2 : S2_tmp*T2_tmp*S2_tmp*T2_tmp, _sage_const_3 : S3_tmp*T3_tmp*S3_tmp*T3_tmp}})
    Ln = lambda n, a, b, c: (matrix([[a,(b-_sage_const_1 )/_sage_const_2 ],[_sage_const_0 ,_sage_const_1 ]]) if a % n != _sage_const_0  else (matrix([[-(b+_sage_const_1 )/_sage_const_2 ,-c],[_sage_const_1 ,_sage_const_0 ]]) if c % n != _sage_const_0  else matrix([[-(b+_sage_const_1 )/_sage_const_2 -a,(_sage_const_1 -b)/_sage_const_2 -c],[_sage_const_1 ,-_sage_const_1 ]]))).change_ring(Rc if cached else R)
    tmp_base = []
    for qf in tqdm(rqf):
        a, b, c = list(qf)
        L = {_sage_const_2 : Ln(_sage_const_2 , a, b, c), _sage_const_3 : Ln(_sage_const_3 , a, b, c)}
        k = round(RR(real(_sage_const_9 *det(L[_sage_const_2 ])-_sage_const_8 *det(L[_sage_const_3 ]))))
        if cached:
            kmod = k%_sage_const_72 
            S2 = S2_table[kmod]
            S3 = S3_table[kmod]
            T2 = T2_table[kmod]
            T3 = T3_table[kmod]
            ST = ST_table[kmod]
            ST_squared = ST_squared_table[kmod]
            B = B_table[kmod]
        else:
            S0 = matrix(R, _sage_const_6 )
            S0[_sage_const_0 ,_sage_const_1 ] = zeta72**(_sage_const_3 *k)
            S0[_sage_const_1 ,_sage_const_2 ] = zeta72**(_sage_const_3 *k)
            S0[_sage_const_2 ,_sage_const_0 ] = zeta72**(_sage_const_6 *k)
            S0[_sage_const_3 ,_sage_const_4 ] = zeta72**(-_sage_const_3 *k)
            S0[_sage_const_4 ,_sage_const_5 ] = zeta72**(-_sage_const_6 *k)
            S0[_sage_const_5 ,_sage_const_3 ] = zeta72**(-_sage_const_3 *k)
            S1 = matrix(R, _sage_const_6 )
            S1[_sage_const_0 ,_sage_const_0 ] = _sage_const_1 
            S1[_sage_const_1 ,_sage_const_3 ] = _sage_const_1 /(zeta72**(_sage_const_3 *k)*(-zeta72**(_sage_const_30 *k)+zeta72**(_sage_const_6 *k)))
            S1[_sage_const_2 ,_sage_const_4 ] = zeta72**(_sage_const_3 *k)/(-zeta72**(_sage_const_30 *k)+zeta72**(_sage_const_6 *k))
            S1[_sage_const_3 ,_sage_const_1 ] = zeta72**(_sage_const_3 *k)*(-zeta72**(_sage_const_30 *k)+zeta72**(_sage_const_6 *k))
            S1[_sage_const_4 ,_sage_const_2 ] = (-zeta72**(_sage_const_30 *k)+zeta72**(_sage_const_6 *k))/zeta72**(_sage_const_3 *k)
            S1[_sage_const_5 ,_sage_const_5 ] = _sage_const_1 
            T2 = S0**_sage_const_9 
            T3 = S0**(-_sage_const_8 )
            S2 = S0**(-_sage_const_1 )*S1*S0**(-_sage_const_10 )*S1*S0**(-_sage_const_1 )*S1*S0**(-_sage_const_18 )
            S3 = S0**(-_sage_const_1 )*S1*S0**_sage_const_7 *S1*S0**(-_sage_const_1 )*S1*S0**_sage_const_16 
            ST = {_sage_const_2 : S2*T2, _sage_const_3 : S3*T3}
            ST_squared = {_sage_const_2 : ST[_sage_const_2 ]**_sage_const_2 , _sage_const_3 : ST[_sage_const_3 ]**_sage_const_2 }
            B = matrix(R, _sage_const_6 )
            B[_sage_const_0 ,_sage_const_0 ] = _sage_const_1 
            if (k - _sage_const_1 ) % _sage_const_3  == _sage_const_0 :
                B[_sage_const_1 ,_sage_const_1 ] = zeta72**(k-_sage_const_1 )
                B[_sage_const_2 ,_sage_const_2 ] = B[_sage_const_1 ,_sage_const_1 ]**_sage_const_2 
                B[_sage_const_3 ,_sage_const_3 ] = B[_sage_const_2 ,_sage_const_2 ]
                B[_sage_const_4 ,_sage_const_4 ] = B[_sage_const_1 ,_sage_const_1 ]
                B[_sage_const_5 ,_sage_const_5 ] = B[_sage_const_1 ,_sage_const_1 ]**_sage_const_3 
            elif (k - _sage_const_2 ) % _sage_const_3  == _sage_const_0 :
                B[_sage_const_1 ,_sage_const_2 ] = zeta72**(k-_sage_const_2 )
                B[_sage_const_2 ,_sage_const_1 ] = zeta72**(_sage_const_2 *k-_sage_const_1 )
                B[_sage_const_3 ,_sage_const_4 ] = B[_sage_const_2 ,_sage_const_1 ]
                B[_sage_const_4 ,_sage_const_3 ] = B[_sage_const_1 ,_sage_const_2 ]
                B[_sage_const_5 ,_sage_const_5 ] = zeta72**(_sage_const_3 *k-_sage_const_3 )
            else:
                raise ValueError
        S = [None, None, S2, S3]
        T = [None, None, T2, T3]
        An = lambda n: S[n]*T[n]**Zmod(N(n))(-_sage_const_1 /a)*S[n]*T[n]**Zmod(N(n))(-a)*S[n]*T[n]**Zmod(N(n))((b-_sage_const_1 )/_sage_const_2 /a**_sage_const_2 -_sage_const_1 /a) if a % n != _sage_const_0  else (T[n]**Zmod(N(n))(_sage_const_1 -(b+_sage_const_1 )/_sage_const_2 )*ST_squared[n] if c % n != _sage_const_0  else T[n]**Zmod(N(n))(_sage_const_1 -(b+_sage_const_1 )/_sage_const_2 -a)*ST[n]*S[n]*T[n]**Zmod(N(n))(_sage_const_1 -_sage_const_1 /(a+b+c)))
        A = An(_sage_const_2 )*An(_sage_const_3 )*B
        tau = Rc((-b+Dsqrt)/_sage_const_2 /a)
        if cached:
            tmp = (zeta72_cubed_pow(_sage_const_2 *k)-zeta72_cubed_pow(_sage_const_10 *k))*sum(A[_sage_const_2 ,i]*Rn[i](tau) for i in range(_sage_const_6 ) if A[_sage_const_2 ,i] != _sage_const_0 )
            tmp_base.append(Rc(-tmp))
        else:
            tmp = (zeta72**(_sage_const_6 *k)-zeta72**(_sage_const_30 *k))*sum(A[_sage_const_2 ,i]*Rn[i](tau) for i in range(_sage_const_6 ) if A[_sage_const_2 ,i] != _sage_const_0 )
            pol *= (t - R(tmp))
    if cached:
        pol = [Rc(_sage_const_1 )]
        for tmp in tqdm(tmp_base):
            l = len(pol)
            pol = [(pol[idx-_sage_const_1 ] if idx>_sage_const_0  else _sage_const_0 )+tmp*pol[idx] for idx in range(l)] + [Rc(_sage_const_1 )]
    #return pol
    if cached:
        coeffs = [cof.real().round() for cof in pol]
    else:
        coeffs = [cof.real().round() for cof in pol.coefficients(sparse=False)]
    return IntegerRing()['x'](coeffs)

def cache_table_initialization(prec):
    global zeta72_cubed_pow_table, S0_table, S1_table, T2_table, T3_table, S2_table, S3_table, B_table, ST_table, ST_squared_table, zeta72_cubed_pow
    Rc = ComplexField(prec)
    zeta72 = exp(Rc(_sage_const_2 *pi*I/_sage_const_72 ))
    if _sage_const_1 :
        zeta72_cubed_pow_table = dict()
        for k in range(_sage_const_24 ):
            zeta72_cubed_pow_table.update({k: zeta72**(_sage_const_3 *k)})
        zeta72_cubed_pow = lambda k: zeta72_cubed_pow_table[k%_sage_const_24 ]
        S0_table = dict()
        S1_table = dict()
        T2_table = dict()
        T3_table = dict()
        S2_table = dict()
        S3_table = dict()
        B_table = dict()
        ST_table = dict()
        ST_squared_table = dict()
        for k in range(_sage_const_72 ):
            S0_tmp = matrix(Rc, _sage_const_6 )
            S0_tmp[_sage_const_0 ,_sage_const_1 ] = zeta72_cubed_pow(k)
            S0_tmp[_sage_const_1 ,_sage_const_2 ] = zeta72_cubed_pow(k)
            S0_tmp[_sage_const_2 ,_sage_const_0 ] = zeta72_cubed_pow(_sage_const_2 *k)
            S0_tmp[_sage_const_3 ,_sage_const_4 ] = zeta72_cubed_pow(-k)
            S0_tmp[_sage_const_4 ,_sage_const_5 ] = zeta72_cubed_pow(-_sage_const_2 *k)
            S0_tmp[_sage_const_5 ,_sage_const_3 ] = zeta72_cubed_pow(-k)
            S1_tmp = matrix(Rc, _sage_const_6 )
            S1_tmp[_sage_const_0 ,_sage_const_0 ] = _sage_const_1 
            S1_tmp[_sage_const_1 ,_sage_const_3 ] = _sage_const_1 /(zeta72_cubed_pow(k)*(-zeta72_cubed_pow(_sage_const_10 *k)+zeta72_cubed_pow(_sage_const_2 *k)))
            S1_tmp[_sage_const_2 ,_sage_const_4 ] = zeta72_cubed_pow(k)/(-zeta72_cubed_pow(_sage_const_10 *k)+zeta72_cubed_pow(_sage_const_2 *k))
            S1_tmp[_sage_const_3 ,_sage_const_1 ] = zeta72_cubed_pow(k)*(-zeta72_cubed_pow(_sage_const_10 *k)+zeta72_cubed_pow(_sage_const_2 *k))
            S1_tmp[_sage_const_4 ,_sage_const_2 ] = (-zeta72_cubed_pow(_sage_const_10 *k)+zeta72_cubed_pow(_sage_const_2 *k))/zeta72_cubed_pow(k)
            S1_tmp[_sage_const_5 ,_sage_const_5 ] = _sage_const_1 
            T2_tmp = S0_tmp**_sage_const_9 
            T3_tmp = S0_tmp**(-_sage_const_8 )
            S2_tmp = S0_tmp**(-_sage_const_1 )*S1_tmp*S0_tmp**(-_sage_const_10 )*S1_tmp*S0_tmp**(-_sage_const_1 )*S1_tmp*S0_tmp**(-_sage_const_18 )
            S3_tmp = S0_tmp**(-_sage_const_1 )*S1_tmp*S0_tmp**_sage_const_7 *S1_tmp*S0_tmp**(-_sage_const_1 )*S1_tmp*S0_tmp**_sage_const_16 
            B_tmp = matrix(Rc, _sage_const_6 )
            B_tmp[_sage_const_0 ,_sage_const_0 ] = _sage_const_1 
            if (k - _sage_const_1 ) % _sage_const_3  == _sage_const_0 :
                B_tmp[_sage_const_1 ,_sage_const_1 ] = zeta72**(k-_sage_const_1 )
                B_tmp[_sage_const_2 ,_sage_const_2 ] = B_tmp[_sage_const_1 ,_sage_const_1 ]**_sage_const_2 
                B_tmp[_sage_const_3 ,_sage_const_3 ] = B_tmp[_sage_const_2 ,_sage_const_2 ]
                B_tmp[_sage_const_4 ,_sage_const_4 ] = B_tmp[_sage_const_1 ,_sage_const_1 ]
                B_tmp[_sage_const_5 ,_sage_const_5 ] = B_tmp[_sage_const_1 ,_sage_const_1 ]**_sage_const_3 
            elif (k - _sage_const_2 ) % _sage_const_3  == _sage_const_0 :
                B_tmp[_sage_const_1 ,_sage_const_2 ] = zeta72**(k-_sage_const_2 )
                B_tmp[_sage_const_2 ,_sage_const_1 ] = zeta72**(_sage_const_2 *k-_sage_const_1 )
                B_tmp[_sage_const_3 ,_sage_const_4 ] = B_tmp[_sage_const_2 ,_sage_const_1 ]
                B_tmp[_sage_const_4 ,_sage_const_3 ] = B_tmp[_sage_const_1 ,_sage_const_2 ]
                B_tmp[_sage_const_5 ,_sage_const_5 ] = zeta72**(_sage_const_3 *k-_sage_const_3 )
            S0_table.update({k: S0_tmp})
            S1_table.update({k: S1_tmp})
            T2_table.update({k: T2_tmp})
            T3_table.update({k: T3_tmp})
            S2_table.update({k: S2_tmp})
            S3_table.update({k: S3_tmp})
            B_table.update({k: B_tmp})
            ST_table.update({k: {_sage_const_2 : S2_tmp*T2_tmp, _sage_const_3 : S3_tmp*T3_tmp}})
            ST_squared_table.update({k: {_sage_const_2 : S2_tmp*T2_tmp*S2_tmp*T2_tmp, _sage_const_3 : S3_tmp*T3_tmp*S3_tmp*T3_tmp}})

def _ramanujan_polynomial_subprocess(prec, Dsqrt, batch):
    global zeta72_cubed_pow_table, S0_table, S1_table, T2_table, T3_table, S2_table, S3_table, B_table, ST_table, ST_squared_table, zeta72_cubed_pow
    Rc = ComplexField(prec)
    R = Rc['t']
    Ln = lambda n, a, b, c: (matrix([[a,(b-_sage_const_1 )/_sage_const_2 ],[_sage_const_0 ,_sage_const_1 ]]) if a % n != _sage_const_0  else (matrix([[-(b+_sage_const_1 )/_sage_const_2 ,-c],[_sage_const_1 ,_sage_const_0 ]]) if c % n != _sage_const_0  else matrix([[-(b+_sage_const_1 )/_sage_const_2 -a,(_sage_const_1 -b)/_sage_const_2 -c],[_sage_const_1 ,-_sage_const_1 ]]))).change_ring(Rc)
    Rn = [
        lambda tau: Rc(eta(_sage_const_3 *tau)*eta(tau/_sage_const_3 )/eta(tau)**_sage_const_2 ),
        lambda tau: Rc(eta(_sage_const_3 *tau)*eta(tau/_sage_const_3 +_sage_const_1 /_sage_const_3 )/eta(tau)**_sage_const_2 ),
        lambda tau: Rc(eta(_sage_const_3 *tau)*eta(tau/_sage_const_3 +_sage_const_2 /_sage_const_3 )/eta(tau)**_sage_const_2 ),
        lambda tau: Rc(eta(tau/_sage_const_3 )*eta(tau/_sage_const_3 +_sage_const_2 /_sage_const_3 )/eta(tau)**_sage_const_2 ),
        lambda tau: Rc(eta(tau/_sage_const_3 )*eta(tau/_sage_const_3 +_sage_const_1 /_sage_const_3 )/eta(tau)**_sage_const_2 ),
        lambda tau: Rc(eta(tau/_sage_const_3 +_sage_const_2 /_sage_const_3 )*eta(tau/_sage_const_3 +_sage_const_1 /_sage_const_3 )/eta(tau)**_sage_const_2 )
    ]
    N = lambda n: _sage_const_8  if n == _sage_const_2  else (_sage_const_9  if n == _sage_const_3  else None)
    tmp_base = []
    for qf in tqdm(batch):
        a, b, c = list(qf)
        L = {_sage_const_2 : Ln(_sage_const_2 , a, b, c), _sage_const_3 : Ln(_sage_const_3 , a, b, c)}
        k = round(RR(real(_sage_const_9 *det(L[_sage_const_2 ])-_sage_const_8 *det(L[_sage_const_3 ]))))
        kmod = k%_sage_const_72 
        S2 = S2_table[kmod]
        S3 = S3_table[kmod]
        T2 = T2_table[kmod]
        T3 = T3_table[kmod]
        ST = ST_table[kmod]
        ST_squared = ST_squared_table[kmod]
        B = B_table[kmod]
        S = [None, None, S2, S3]
        T = [None, None, T2, T3]
        An = lambda n: S[n]*T[n]**Zmod(N(n))(-_sage_const_1 /a)*S[n]*T[n]**Zmod(N(n))(-a)*S[n]*T[n]**Zmod(N(n))((b-_sage_const_1 )/_sage_const_2 /a**_sage_const_2 -_sage_const_1 /a) if a % n != _sage_const_0  else (T[n]**Zmod(N(n))(_sage_const_1 -(b+_sage_const_1 )/_sage_const_2 )*ST_squared[n] if c % n != _sage_const_0  else T[n]**Zmod(N(n))(_sage_const_1 -(b+_sage_const_1 )/_sage_const_2 -a)*ST[n]*S[n]*T[n]**Zmod(N(n))(_sage_const_1 -_sage_const_1 /(a+b+c)))
        A = An(_sage_const_2 )*An(_sage_const_3 )*B
        tau = Rc((-b+Dsqrt)/_sage_const_2 /a)
        tmp = (zeta72_cubed_pow(_sage_const_2 *k)-zeta72_cubed_pow(_sage_const_10 *k))*sum(A[_sage_const_2 ,i]*Rn[i](tau) for i in range(_sage_const_6 ) if A[_sage_const_2 ,i] != _sage_const_0 )
        tmp_base.append(R(-tmp))
    pol = R(_sage_const_1 )
    for tmp in tqdm(tmp_base):
        pol *= R.gen() + tmp
    return pol

def _polymul_subprocess(prec, batch):
    R = ComplexField(prec)['t']
    pol = R(_sage_const_1 )
    for poly in tqdm(batch):
        pol *= poly
    return pol

def ramanujan_polynomial_multi(D, processes1 = _sage_const_64 , processes2_list = [_sage_const_32 ]):
    assert D < _sage_const_0  and D % _sage_const_24  == _sage_const_13 
    rqf = BinaryQF_reduced_representatives(D, primitive_only=True)
    h = len(rqf) # class number
    c2 = sum([_sage_const_1 /RR(qf[_sage_const_0 ]) for qf in rqf], RR(_sage_const_0 ))
    prec = c2 * RR(pi) * RR(D).abs().sqrt() / _sage_const_36  / RR(log(_sage_const_2 ))
    prec = _sage_const_20  + prec.ceil()  # allow for rounding error
    Rc = ComplexField(prec)
    R = Rc['t']
    Dsqrt = Rc(D.sqrt(prec = prec))
    cache_table_initialization(prec)
    
    pool = Pool(min(processes1, h))
    batch_size = ceil(h / min(processes1, h))
    task = functools.partial(_ramanujan_polynomial_subprocess, prec, Dsqrt)
    res = pool.map(task, (rqf[i:i+batch_size] for i in range(_sage_const_0 ,h,batch_size)))
    pool.close()
    pool.join()
    
    idx = _sage_const_0 
    while _sage_const_1 :
        processes2 = processes2_list[min(idx, len(processes2_list)-_sage_const_1 )]
        if len(res) <= processes2:
            break
        pool = Pool(processes2)
        batch_size = ceil(len(res) / processes2)
        task = functools.partial(_polymul_subprocess, prec)
        res = pool.map(task, (res[i:i+batch_size] for i in range(_sage_const_0 ,len(res),batch_size)))
        pool.close()
        pool.join()
        idx += _sage_const_1 
    
    pol = R(_sage_const_1 )
    for poly in tqdm(res):
        pol *= poly
    coeffs = [cof.real().round() for cof in pol.coefficients(sparse=False)]
    return IntegerRing()['x'](coeffs)

if __name__ == "__main__":
    #time h1 = ramanujan_polynomial(-11-24*1000000, 1)
    __time__ = cputime(); __wall__ = walltime(); h2 = ramanujan_polynomial_multi(-_sage_const_11 -_sage_const_24 *_sage_const_1000000 , _sage_const_120 , [_sage_const_16 ,_sage_const_8 ]); print("Time: CPU {:.2f} s, Wall: {:.2f} s".format(cputime(__time__), walltime(__wall__)))
    #assert h1 == h2

