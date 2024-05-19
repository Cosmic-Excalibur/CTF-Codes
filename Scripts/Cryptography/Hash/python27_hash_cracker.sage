# SageMath 10.2

def hash_27(x):
    mask = 0xffffffffffffffff
    l = len(x)
    y = x[0] << 7 & mask
    for i in range(l):
        y = (1000003 * y) & mask ^^ x[i]
    y ^^= l & mask
    return y

def crack_27(x, l):
    pass
