### 简简又单单

阅读代码发现，题目可以看作是在一个有着陷门的格上求解CVP问题。

格的平凡格基为：
$$
L= \begin{bmatrix}
A & B\\
C & 0
\end{bmatrix}\\
$$
$cipher = secret * A + r * C + t$，则可以构造CVP问题：在$L$ 生成的格上，对 $(cipher, 0)$ 求最接近的格点，存在格点：$ (secret * A + r * C, secret * B)$，与目标点距离为 $(-t, secret * B)$，又因为 $t, secret *B$均为短向量，故考虑求解CVP解决问题。

通过对代码的观察发现$L$ 生成的格存在一组更好的格基：
$$
L' = \begin{bmatrix}
K & X\cdot B\\
P & 0
\end{bmatrix}\\
P = (X\cdot B)^{-1} \cdot(B\cdot C)
$$
上述格基存在的原因在于有 $X\cdot A + Y\cdot C = K $，故 $\begin{bmatrix}
K & X\cdot B
\end{bmatrix}\\$ 为$L$ 的一个不满秩子格。

考虑构造 $P$ 使得 $L'$ 行列式与 $L$  相同，则为相同格。

即需要 $XBP = BC$，即 $P = (X\cdot B)^{-1} \cdot(B\cdot C)$。

而 $X, B, C,K$ 均给出，故可以直接得到 $L'$ ，对其使用LLL规约后直接使用Babai Rounding Off算法求解CVP即可得到flag，当然这里可以不用给出B，自己生成一个分量大小差不多的B也是可以的，不过放在代码里就当hint了，exp如下：

```python
# exp
# known cipher, X, B, C, K
from sage.all import *
from hashlib import md5
from subprocess import check_output
from re import findall


def flatter(M):
    z = "[[" + "]\n[".join(" ".join(map(str, row)) for row in M) + "]]"
    ret = check_output(["flatter"], input=z.encode())
    return matrix(M.nrows(), M.ncols(), map(int, findall(b"-?\\d+", ret)))


def str_to_matrix(M_str):
    M_list = eval(M_str)
    M_mat = Matrix(ZZ, dims)
    for i in range(dims):
        for j in range(dims):
            M_mat[i, j] = M_list[i * dims + j]
    return M_mat


def ternary_with_density(density):
    tmp = randrange(0, density)
    if tmp == 0:
        return 1
    elif tmp == 1:
        return -1
    else:
        return 0


def get_matrix(density):
    P = identity_matrix(ZZ, dims)
    for _ in range(2):
        Li = identity_matrix(ZZ, dims)
        Ui = identity_matrix(ZZ, dims)
        for i in range(dims):
            for j in range(i + 1, dims):
                Li[i, j] = ternary_with_density(density)
                Ui[j, i] = ternary_with_density(density)
        P *= Li * Ui
    return P


density = 30
dims = 190
data = open('./cipher.txt', 'r').read().split('\n')
cipher, X, _, C, K = data
cipher = vector(ZZ, eval(cipher))
X = str_to_matrix(X)
B = get_matrix(density)
C = str_to_matrix(C)
K = str_to_matrix(K)

# build trapdoor lattice
P = (X*B).inverse() * (B * C)
trapdoor = block_matrix(ZZ, [
    [K, X * B],
    [P, 0]
])
trapdoorL = flatter(trapdoor)

# solve CVP by Babai-RO
trapdoorLi = trapdoorL.inverse()
v = vector(list(cipher) + [0] * dims)
my_secret = vector(round(vi) for vi in v * trapdoorLi)
my_e = v - my_secret * trapdoorL

# get flag
final_secret = -my_e[dims:] * B.inverse()
print('DubheCTF{' + md5(str(final_secret).encode()).hexdigest() + '}')
# DubheCTF{b9a5671e706f26f52378e8b3139ab588}
```

