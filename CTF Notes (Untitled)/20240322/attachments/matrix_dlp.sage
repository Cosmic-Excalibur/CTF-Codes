def matrix_dlp(Y, M):
    assert M.base_ring() == Y.base_ring()
    Fq = M.base_ring()
    assert Fq.is_field()
    assert Fq.is_finite()
    p = Fq.base().order()
    
    char_poly_M = M.characteristic_polynomial()
    F.<x> = char_poly_M.splitting_field()
    # print()
    # print(F.order(), factor(F.order()-1))
    # J_M = M.change_ring(F).diagonalization()[0]
    J_M = M.change_ring(F).jordan_form()
    # J_Y = Y.change_ring(F).diagonalization()[0]
    J_Y = Y.change_ring(F).jordan_form()
    assert J_M.is_diagonal()
    assert J_Y.is_diagonal()
    M_eigenvals = sorted(set([J_M[i,i] for i in range(J_M.dimensions()[0])]), key = lambda entry: entry.polynomial().degree())
    Y_eigenvals = sorted(set([J_Y[i,i] for i in range(J_Y.dimensions()[0])]), key = lambda entry: entry.polynomial().degree())
    
    for entry_M in M_eigenvals:
        for entry_Y in Y_eigenvals:
            try:
                # print()
                # print(entry_M, entry_Y)
                res = discrete_log(entry_Y, entry_M)
                if M**res == Y: return res
            except (ValueError, ZeroDivisionError):
                continue
    return None

def random_smooth_prime(pbits, B):
    B = ZZ(B)
    while 1:
        res = 2
        while pbits - res.nbits() > B.nbits():
            fac = random_prime(B, lbound = 2)
            res *= fac
        rem = pbits - res.nbits()
        res *= random_prime(2**(rem), lbound = 2**(rem - 1))
        res += 1
        if is_prime(res): return res

def test_matrix_dlp(round = 10, pbits = 100, B = 100, m = -1, dimrange = (5,6)):
    func_name = "matrix_dlp"
    print(f'[\033[32m\033[1m+\033[0m] Testing the function "\033[1m{func_name}\033[0m"...\n')
    succ = 0
    t0 = cputime()
    
    for i in range(1, round + 1):
        print(f'\r[\033[34m\033[1m*\033[0m] Round \033[1m%{len(str(round))}s\033[0m / {round}...' % i, end = '')
        
        p = random_smooth_prime(pbits, B)
        Fq = GF(p)
        dim = randrange(*dimrange)
        x = randrange(p)
        while 1:
            M = random_matrix(Fq, dim)
            if m < 0 or max([x[0].degree() for x in factor(M.characteristic_polynomial())]) <= m:
                break
        Y = M ** x
        
        t = cputime()
        x_ = matrix_dlp(Y, M)
        t = cputime(t)
        if M**x_ == Y:
            succ += 1
            print(f'\r[\033[32m\033[1m+\033[0m] Round \033[1m%{len(str(round))}s\033[0m / {round} succeeded in \033[1m%.2f\033[0ms! 🥳' % (i, t))
        else:
            print(f'\r[\033[31m\033[1m-\033[0m] Round \033[1m%{len(str(round))}s\033[0m / {round} failed in \033[1m%.2f\033[0ms! 😭' % (i, t))
    print(f'\n[\033[32m\033[1m+\033[0m] Test finished in \033[1m%.2f\033[0ms. Succ rate: \033[1m%05.2f\033[0m%%  (\033[1m%{len(str(round))}s\033[0m / {round})' % (cputime(t0), succ / round * 100, succ))