_COMMENTS = '''

# A direct implementation of https://github.com/spawnmason/randar-explanation/blob/master/README.md
# Tested in SageMath 9.3

# The code below has been commented since solving SVP does very often fail to give the correct shortest vector. Babai's Rounding method for CVP is exploited in this file.

def solve_xz(dx, dy, dz):
    global L
    a = 25214903917
    b = 11
    q = 2**48
    x1bar, x2bar, x3bar = (int((x-0.25)*2*2**24)*2**24+2**23 for x in (dx, dy, dz))
    beta = 2**48
    L = matrix(ZZ, [
    [            a,         a**2,         a**3,            1,            0,            0],
    [            b,        a*b+b, a**2*b+a*b+b,            0,         beta,            0],
    [        x1bar,        x2bar,        x3bar,            0,         beta,         beta],
    [            q,            0,            0,            0,            0,            0],
    [            0,            q,            0,            0,            0,            0],
    [            0,            0,            q,            0,            0,            0]
    ])
    L_ = L.LLL()
    return L_
    try:
        v = next(v for v in L_ if abs(v[-1]) == beta)
        v *= -sgn(v[-1])
    except StopIteration:
        return None
    return v

'''

WORLD_SEED = -1174984337720969396
evaluate = lambda x, z: (((x * 1280 - 128), (x * 1280 + 1151)), ((z * 1280 - 128), (z * 1280 + 1151)))

def solve_xz(dx, dy, dz):
    a = 25214903917
    b = 11
    q = 2**48
    x1bar, x2bar, x3bar = (int((x-0.25)*2*2**24)*2**24 for x in (dx, dy, dz))
    A = matrix(ZZ, [
    [    1,    a, a**2],
    [    0,    q,    0],
    [    0,    0,    q]
    ])
    A_ = A.LLL()
    t = vector([x1bar + 2**23, x2bar + 2*23, x3bar + 2**23])
    t -= vector([0, b, a*b+b])
    v = vector(round(x) for x in t*A_.change_ring(RR)**-1)
    v = v * A_
    seed = v[0]
    if (((seed-x1bar) >> 24) & (2**24-1) | (((a*seed+b)%q-x2bar) >> 24) & (2**24-1) | (((seed*a**2+a*b+b)%q-x3bar) >> 24) & (2**24-1)) != 0:
        return
    for i in tqdm(range(50)):
        for x in range(-23440, 23440 + 1):
            z = (((int(seed) ^^ int(a)) - int(WORLD_SEED) - int(10387319) - int(x) * int(341873128712)) * int(211541297333629)) % int(q)
            z = z - int(2**48) if z >= int(2**47) else z
            if z in range(-23440, 23440 + 1):
                return (x, z)
        seed = (seed * int(246154705703781) + int(107048004364969)) % int(q)
    

data = '''
(0.4975970387458801, 0.25809618830680847, 0.25461313128471375)
(0.5435881912708282, 0.6035351157188416, 0.6890734732151031)
(0.4975970387458801, 0.25809618830680847, 0.25461313128471375)
(0.6799367964267731, 0.2503877580165863, 0.5870234370231628)
#

(0.6376921832561493, 0.35866010189056396, 0.3733369708061218)
(0.6184333860874176, 0.49297502636909485, 0.35139578580856323)
(0.5883518755435944, 0.47967222332954407, 0.541723370552063)
(0.6376921832561493, 0.35866010189056396, 0.3733369708061218)
(0.3142523467540741, 0.4354858696460724, 0.6359781324863434)
#

(0.42160940170288086, 0.635073184967041, 0.29384133219718933)
#

(0.7490202188491821, 0.47727930545806885, 0.25538215041160583)
(0.502590149641037, 0.7396616041660309, 0.6954899728298187)
(0.5562916100025177, 0.502590149641037, 0.7396616041660309)
(0.43094602227211, 0.34591880440711975, 0.2553098797798157)

(0.30929598212242126, 0.7216057777404785, 0.7075901329517365)
(0.5447381138801575, 0.30929598212242126, 0.7216057777404785)
(0.3080557882785797, 0.4133829176425934, 0.31755658984184265)
(0.6097800135612488, 0.5313882231712341, 0.4003000259399414)
'''.split('\n')

if '__main__' == __name__:
    for datum in data:
        if datum.strip() == '': continue
        if datum.strip() == '#': break
        out = solve_xz(*map(float, eval(datum)))
        print(out, evaluate(*out) if out else None)
        print()