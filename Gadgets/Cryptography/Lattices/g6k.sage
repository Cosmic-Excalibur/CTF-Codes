from fpylll import IntegerMatrix, LLL
from g6k import Siever

def g6k(B, best=True):
    n = B.nrows()
    assert n == B.ncols()
    A = IntegerMatrix(n, n)
    A = A.from_matrix(B)
    A = LLL.reduction(A)
    g6k = Siever(A)
    g6k.initialize_local(0, 0, n)
    g6k(alg="gauss")
    g6k()
    
    if best and g6k.best_lifts() != []:
        return matrix(ZZ, [x[2] for x in g6k.best_lifts()])

    db = list(g6k.itervalues())
    return matrix(ZZ, db)