def div_poly(E, n, x=None):
        if x is None:
            # The generic division polynomials should be cached "forever".
            assert 0
        else:
            # For other inputs, we use a temporary cache.
            cache = dict()

        b2, b4, b6, b8 = E.b_invariants()
        
        N = n
        scale = RR(88/N.bit_length())

        def poly(n):
            if n > 0:
                print(f'\r[%-{round(N.bit_length()*scale)}s]    %{len(str(N.bit_length()))+6}.5f'%(round(n.bit_length()*scale)*'*', float(RR(log(n)/log(2)))), end = '')
            try:
                return cache[n]
            except KeyError:
                pass
            if n == -2:
                ret = poly(-1)**2
            elif n == -1:
                ret = 4*x**3 + b2*x**2 + 2*b4*x + b6
            elif n <= 0:
                raise ValueError("n must be a positive integer (or -1 or -2)")
            elif n == 1 or n == 2:
                ret = x.parent().one()
            elif n == 3:
                ret = 3*x**4 + b2*x**3 + 3*b4*x**2 + 3*b6*x + b8
            elif n == 4:
                ret = -poly(-2) + (6*x**2 + b2*x + b4) * poly(3)
            elif n % 2 == 0:
                m = (n-2) // 2
                ret = poly(m+1) * (poly(m+3) * poly(m)**2 - poly(m-1) * poly(m+2)**2)
            else:
                m = (n-1) // 2
                if m % 2 == 0:
                    ret = poly(-2) * poly(m+2) * poly(m)**3 - poly(m-1) * poly(m+1)**3
                else:
                    ret = poly(m+2) * poly(m)**3 - poly(-2) * poly(m-1) * poly(m+1)**3
            cache[n] = ret
            return ret
            
        if not isinstance(n, (list, tuple)):
            return poly(int(n))
        else:
            return [poly(int(k)) for k in n]