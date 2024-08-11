"""
Commonly used utilities in stream ciphers 4 the lazy guys :p
Can be renamed as "utils_lazy.py" to avoid namespace pollution.
"""


from collections.abc import Iterable, Sequence
from typing import Callable
from itertools import islice, cycle, count, chain
import functools


def chunks(iterable: Iterable, size: int):
    """
    Split an iterable into chunks of "smaller" iterables,
    works as generator.
    
    Parameters
    ----------
    iterable : Iterable
        The target iterable, can be `list`, `generator`,
        `bytes`, `iterator` and so on.
    size : int
        The maximum of each chunk.
    
    Examples
    --------
    
    >>> for chunk in chunks(range(10), 3):
    ...     print(*chunk)
    0 1 2
    3 4 5
    6 7 8
    9
    
    >>> for chunk in chunks(range(10), 3):
    ...     print(chunk)
    <itertools.chain object at 0x000001D87EDB76D0>
    <itertools.chain object at 0x000001D87EF2AF70>
    <itertools.chain object at 0x000001D87EDB7D30>
    <itertools.chain object at 0x000001D87EF2A520>
    
    """
    i = iter(iterable)
    for first in i:
        rest = islice(i, size - 1)
        yield chain([first], rest)
        next(islice(rest, size - 1, None), None)
        

"""
bitcat : Bitwise concatenation
intcat : Monic bit sequence bitwise concatenation
xorsum : Xor summation 
"""
bitcat = lambda bits: functools.reduce(lambda a, b: a << 1 | b, bits)
intcat = lambda ints: functools.reduce(lambda a, b: a << b.bit_length() | b, ints)
xorsum = lambda ints: functools.reduce(lambda a, b: a ^ b, ints)


def isqrt(n: int) -> int:
    """
    Get square root of an integer, integer part only.
    
    ref: https://en.wikipedia.org/wiki/Integer_square_root
    
    Parameters
    ----------
    n : int
        The target integer s.t. `n >= 0`.
    
    Returns
    -------
    out : int
        The integer part of the square root of `n`.
    
    Examples
    --------
    
    >>> isqrt(289)
    17
    >>> isqrt(2)
    1
    >>> isqrt(1000000 ** 2)
    1000000
    
    """
    if n == 0:
        return 0

    # ref: https://en.wikipedia.org/wiki/Methods_of_computing_square_roots#Rough_estimation
    x = 2 ** ((n.bit_length() + 1) // 2)
    while True:
        y = (x + n // x) // 2
        if y >= x:
            return x
        x = y

def is_perfect_square(n: int) -> bool:
    """
    Check if an integer is a perfect square.
    
    ref: https://hnw.hatenablog.com/entry/20140503
    
    Parameters
    ----------
    n : int
        The integer to be checked, where `n >= 0`.
    
    Returns
    -------
    out : bool
        `True` if `n` is a perfect square, else `False`.
    
    Examples
    --------
    
    >>> is_perfect_square(100)
    True
    
    >>> is_perfect_square(2000000000000000000000000000 ** 2)
    True

    >>> is_perfect_square(2000000000000000000000000000 ** 2 + 1)
    False
    
    """
    sq_mod256 = (1,1,0,0,1,0,0,0,0,1,0,0,0,0,0,0,1,1,0,0,0,0,0,0,0,1,0,0,0,0,0,0,0,1,0,0,1,0,0,0,0,1,0,0,0,0,0,0,0,1,0,0,0,0,0,0,0,1,0,0,0,0,0,0,1,1,0,0,1,0,0,0,0,1,0,0,0,0,0,0,0,1,0,0,0,0,0,0,0,1,0,0,0,0,0,0,0,1,0,0,1,0,0,0,0,1,0,0,0,0,0,0,0,1,0,0,0,0,0,0,0,1,0,0,0,0,0,0,0,1,0,0,1,0,0,0,0,1,0,0,0,0,0,0,1,1,0,0,0,0,0,0,0,1,0,0,0,0,0,0,0,1,0,0,1,0,0,0,0,1,0,0,0,0,0,0,0,1,0,0,0,0,0,0,0,1,0,0,0,0,0,0,0,1,0,0,1,0,0,0,0,1,0,0,0,0,0,0,0,1,0,0,0,0,0,0,0,1,0,0,0,0,0,0,0,1,0,0,1,0,0,0,0,1,0,0,0,0,0,0,0,1,0,0,0,0,0,0,0,1,0,0,0,0,0,0)
    if sq_mod256[n & 0xff] == 0:
        return False

    mt = (
        (9, (1,1,0,0,1,0,0,1,0)),
        (5, (1,1,0,0,1)),
        (7, (1,1,1,0,1,0,0)),
        (13, (1,1,0,1,1,0,0,0,0,1,1,0,1)),
        (17, (1,1,1,0,1,0,0,0,1,1,0,0,0,1,0,1,1))
    )
    a = n % (9 * 5 * 7 * 13 * 17)
    if any(t[a % m] == 0 for m, t in mt):
        return False

    return isqrt(n) ** 2 == n


NaturalNumbers = lambda: count(start = 0)

MIX_COLUMN = [
    2, 3, 1, 1,
    1, 2, 3, 1,
    1, 1, 2, 3,
    3, 1, 1, 2
]

UNMIX_COLUMN = [
    14, 11, 13, 9,
    9, 14, 11, 13,
    13, 9, 14, 11,
    11, 13, 9, 14
]

SBOX = [
	0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
	0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
	0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
	0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
	0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
	0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
	0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
	0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
	0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
	0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
	0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
	0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
	0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
	0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
	0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
	0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16
]

INV_SBOX = [
    0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb, 
    0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb, 
    0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e, 
    0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25, 
    0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92, 
    0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84, 
    0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06, 
    0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b, 
    0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73, 
    0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e, 
    0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b, 
    0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4, 
    0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f, 
    0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef, 
    0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61, 
    0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d
]

class Context:
    def __init__(self, m: int, n: int, ret: type = list):
        """
        Specify the context!
        
        Parameters
        ----------
        m : int
            Number of bits for each entry.
        n : int
            Length of messages.
        ret : Iterable type
            Basic type for return values.
        
        """
        self.m = m
        self.n = n
        self.ret = ret
        
        self.mask = 2**self.m - 1
        self.is_square = is_perfect_square(self.n)
        if self.is_square:
            self.order = isqrt(self.n)
    
    def xor(self, msg1: Iterable, msg2: Iterable) -> Iterable:
        """
        Entrywise then bitwise xor
        without checking the lengths.
        
        Parameters
        ----------
        msg1, msg2 : Iterable of ints
            Input messages.
        
        Returns
        -------
        out : Iterable of ints
            An iterable consisting of ints
            resulting from the xor-ing of the inputs.
        
        """
        return self.ret(x ^ y for x, y in zip(msg1, msg2))
    
    def xor_key(self, msg: Iterable, key: int) -> Iterable:
        """
        Entrywise xor using the same key.
        
        Parameters
        ----------
        msg1 : Iterable of ints
            The input message.
        key : int
            The constant xor addend.
        
        Returns
        -------
        out : Iterable of ints
            An iterable consisting of ints
            resulting from the xor-ing of the inputs.
        
        """
        return self.ret(x ^ key for x in msg)
    
    def permute(self, message: Sequence, table: Sequence) -> Iterable:
        """
        Perform a permutation with out checking
        the lengths.
        
        The permutation table should contain `n`
        distinct ints in the range `0 ~ n-1`.
        
        Each entry at index `i` in the message will be
        mapped to the location specified by the entry in
        the permutation table at index `i`.
        
        Index mapping:
        
           0         1         2      ...
           |         |         |      
           v         v         v
        table[0]  table[1]  table[2]  ...
        
        Parameters
        ----------
        message : Sequence of ints
            The input message.
        table : Sequence of ints
            A index-entry or key-value table.
        
        Returns
        -------
        out : Iterable of ints
            An iterable consisting of ints
            resulting from the permutation.
        
        """
        l = len(message)
        ret = [0] * l
        for i in range(l):
            ret[table[i]] = message[i]
        return self.ret(ret)
    
    def permute_inv(self, message: Sequence, table: Sequence) -> Iterable:
        """
        Invert a permutation with out checking
        the lengths.
        
        The permutation table should contain `n`
        distinct ints in the range `0 ~ n-1`.
        
        Each entry at index `i` in the message will be
        mapped to the location specified by the entry in
        the permutation table at index `i`.
        
        Index mapping:
        
        table[0]  table[1]  table[2]  ...
           |         |         |      
           v         v         v
           0         1         2      ...
        
        Parameters
        ----------
        message : Sequence of ints
            The input message.
        table : Sequence of ints
            A index-entry or key-value table.
        
        Returns
        -------
        out : Iterable of ints
            An iterable consisting of ints
            resulting from the inverted permutation.
        
        """
        return self.ret(message[table[i]] for i in range(len(message)))
    
    def rol(self, message: Iterable, keys: Iterable) -> Iterable:
        """
        Circularly shift the bits of each message entry
        leftward according to the corresponding
        shift operand in `keys`.
        
        Each entry `key in `keys` should satisfy
        `0 <= key <= m`.
        
        e.g. for `keys = [2, ..., 2]`, the
        bit mapping (MSB):
        
         m  ||  m-1  ||  ...  ||  2  ||  1  ||  0
         |       |                |      |      |
         v       v                v      v      v
        m-2     m-3               0      m     m-1
        
        Parameters
        ----------
        message : Iterable of ints
            The input message.
        keys : Iterable of ints
            Shift operands for each message entry.
        
        Returns
        -------
        out : Iterable of ints
            An iterable consisting of ints
            resulting from the leftward bit shifting.
        
        """
        return self.ret((m << k | m >> (self.m - k)) & self.mask for m, k in zip(message, keys))
    
    def ror(self, message: Iterable, keys: Iterable) -> Iterable:
        """
        Circularly shift the bits of each message entry
        rightward according to the corresponding
        shift operand in `keys`.
        
        Each entry `key in `keys` should satisfy
        `0 <= key <= m`.
        
        e.g. for `keys = [2, ..., 2]`, the
        bit mapping (MSB):
        
        m  ||  m-1  ||  m-2  ||  ...  ||  1  ||  0
        |       |        |                |      |
        v       v        v                v      v
        1       0        m                3      2
        
        Parameters
        ----------
        message : Iterable of ints
            The input message.
        keys : Iterable of ints
            Shift operands for each message entry.
        
        Returns
        -------
        out : Iterable of ints
            An iterable consisting of ints
            resulting from the rightward bit shifting.
        
        """
        return self.ret((m >> k | m << (self.m - k)) & self.mask for m, k in zip(message, keys))
    
    def rol_key(self, message: Iterable, key: int) -> Iterable:
        """
        Circularly shift the bits of each message entry
        leftward according to the shift operand `key`.
        
        `0 <= key <= m` should be guaranteed.
        
        e.g. for `key = 2`, the
        bit mapping (MSB):
        
         m  ||  m-1  ||  ...  ||  2  ||  1  ||  0
         |       |                |      |      |
         v       v                v      v      v
        m-2     m-3               0      m     m-1
        
        Parameters
        ----------
        message : Iterable of ints
            The input message.
        key : int
            The shift operand for each message entry.
        
        Returns
        -------
        out : Iterable of ints
            An iterable consisting of ints
            resulting from the leftward bit shifting.
        
        """
        return self.ret((m << key | m >> (self.m - key)) & self.mask for m in message)
    
    def ror_key(self, message: Iterable, key: int) -> Iterable:
        """
        Circularly shift the bits of each message entry
        rightward according to the shift operand `key`.
        
        `0 <= key <= m` should be guaranteed.
        
        e.g. for `key = 2`, the
        bit mapping (MSB):
        
        m  ||  m-1  ||  m-2  ||  ...  ||  1  ||  0
        |       |        |                |      |
        v       v        v                v      v
        1       0        m                3      2
        
        Parameters
        ----------
        message : Iterable of ints
            The input message.
        key : int
            The shift operand for each message entry.
        
        Returns
        -------
        out : Iterable of ints
            An iterable consisting of ints
            resulting from the rightward bit shifting.
        
        """
        return self.ret((m >> key | m << (self.m - key)) & self.mask for m in message)
    
    def rol_rows(self, message: Sequence, key: Iterable = NaturalNumbers()) -> Iterable:
        """
        Circularly shift the entries of each row,
        leftward, provided that all entries indeed
        form a *square matrix*, i.e. `n = k^2` for
        some integer k.
        
        `is_square` should be `True`.
        
        e.g. for `n = 16, key = [0, 1, 2, 3]`,
        we shift the rows in the AES-style:
        
        a00  a01  a02  a03        a00  a01  a02  a03
        ------------------        ------------------
        a04  a05  a06  a07        a05  a06  a07  a08
        ------------------   ->   ------------------
        a08  a09  a10  a11        a10  a11  a08  a09
        ------------------        ------------------
        a12  a13  a14  a15        a15  a12  a13  a14
        
        
        Parameters
        ----------
        message : Iterable of ints
            The input message.
        key : Iterable of ints
            Shift operands for each row.
        
        Returns
        -------
        out : Iterable of ints
            An iterable consisting of ints
            resulting from the leftward row shifting.
        
        """
        assert self.is_square, "Not a square matrix."
        ret = [0] * self.n
        for i, k in enumerate(key):
            if i >= self.order: break
            for j in range(self.order):
                ret[i*self.order + j] = message[i*self.order + (j + k) % self.order]
        return self.ret(ret)
    
    def ror_rows(self, message: Sequence, key: Iterable = NaturalNumbers()) -> Iterable:
        """
        Circularly shift the entries of each row,
        rightward, provided that all entries indeed
        form a *square matrix*, i.e. `n = k^2` for
        some integer k.
        
        `is_square` should be `True`.
        
        e.g. for `n = 16, key = [0, 1, 2, 3]`,
        we unshift the rows in the AES-style:
        
        a00  a01  a02  a03        a00  a01  a02  a03
        ------------------        ------------------
        a05  a06  a07  a08        a04  a05  a06  a07
        ------------------   ->   ------------------
        a10  a11  a08  a09        a08  a09  a10  a11
        ------------------        ------------------
        a15  a12  a13  a14        a12  a13  a14  a15
        
        
        Parameters
        ----------
        message : Iterable of ints
            The input message.
        key : Iterable
            Shift operands for each row.
        
        Returns
        -------
        out : Iterable of ints
            An iterable consisting of ints
            resulting from the rightward row shifting.
        
        """
        assert self.is_square, "Not a square matrix."
        ret = [0] * self.n
        for i, k in enumerate(key):
            if i >= self.order: break
            for j in range(self.order):
                ret[i*self.order + j] = message[i*self.order + (j - k) % self.order]
        return self.ret(ret)
    
    def bit_reverse(self, message: Iterable) -> Iterable:
        """
        Reverse bits in each entry of the message.
        
        Bit mapping (MSB):
        
        m  ||  m-1  ||  ...  ||  1  ||  0
        |       |                |      |
        v       v                v      v
        0       1               m-1     m
        
        Parameters
        ----------
        message : Iterable of ints
            The input message.
        
        Returns
        -------
        out : Iterable of ints
            An iterable consisting of ints
            resulting from the entrywise bit reversal.
        
        """
        return self.ret(bitcat(m >> i & 1 for i in range(self.m)) for m in message)
    
    def _gmul(self, a: int, b: int, modulus: int) -> int:
        """
        Multiplication on `GF(2^8)=GF(2)/modulus`,
        and `modulus` should be irreducible in concept.
        
        `a, b, modulus` must not be negative and
        should be less than `2^m`.
        
        ref: https://stackoverflow.com/questions/66115739/aes-mixcolumns-with-python
        
        
        Parameters
        ----------
        a : int
            The first polynomial as an element in GF(2^8).
        b : int
            The second polynomial as an element in GF(2^8).

        Returns
        -------
        out : int
            An integer as the polynomial of
            the product of `a` and `b`.
        
        Examples
        --------
        
        If we choose
            `m       =    8`,
            `a       = 0x11`,
            `b       = 0x45`,
            `modulus = 0x2b`,
        Then `_gmul(a, b, modulus)` is equal to
        
        `(x^4 + 1) * (x^6 + x^2 + 1)`
            on `GF(2^8)/(x^8 + x^5 + x^3 + x + 1)`
        
        which is `x^7 + x^5 + x^4 + x^3 + 1`,
        and equivalently `0xb9`.
        
        """
        if b < 0:
            raise ValueError("Multiplicand `b` must not be negative.")
        if b == 1:
            return a
        tmp = (a << 1) & self.mask
        if b == 2:
            return tmp if a < 1 << self.m-1 else tmp ^ modulus
        half = self._gmul(a, 2, modulus)
        half = self._gmul(half, b >> 1, modulus)
        return half ^ a if b & 1 else half
    
    def _mix_column(self, column: Iterable, matrix: Iterable, modulus: int) -> Sequence:
        """
        
        """
        return [xorsum(self._gmul(c, m, modulus) for c, m in chunk) for chunk in chunks(zip(cycle(column), matrix), self.order)]
    
    def _sbox(self, entry: int, sbox: Sequence) -> int:
        """
        
        """
        return sbox[entry]
    
    def mix_columns(self, message: Sequence) -> Iterable:
        """
        
        """
        assert self.is_square, "Not a square matrix."
        assert self.order == 4, "Not a 4 x 4 matrix."
        matrix = MIX_COLUMN
        modulus = 0x1b
        ret = [0] * self.n
        for i in range(self.order):
            tmp = self._mix_column(message[i: self.n + i: self.order], matrix, modulus)
            ret[i: self.n + i: self.order] = tmp
        return self.ret(ret)
    
    def unmix_columns(self, message: Sequence) -> Iterable:
        """
        
        """
        matrix = UNMIX_COLUMN
        modulus = 0x1b
        assert self.is_square, "Not a square matrix."
        assert self.order == 4, "Not a 4 x 4 matrix."
        ret = [0] * self.n
        for i in range(self.order):
            tmp = self._mix_column(message[i: self.n + i: self.order], matrix, modulus)
            ret[i: self.n + i: self.order] = tmp
        return self.ret(ret)
    
    def sbox(self, message: Iterable) -> Iterable:
        """
        
        """
        sbox = SBOX
        return self.ret(self._sbox(m, sbox) for m in message)
    
    def sbox_inv(self, message: Sequence) -> Iterable:
        """
        
        """
        # sbox = SBOX
        # return self.ret(self._sbox_inv(m, sbox) for m in message)
        sbox = INV_SBOX
        return self.ret(self._sbox(m, INV_SBOX) for m in message)
    
    def _invert(self, operation: Callable, *args) -> Callable:
        """
        Invert an operation with specific parameters.
        
        Parameters
        ----------
        operation : Callable
            The operation to be reversed.
        args : argument list
            Arguments except the message for the operation.
        
        Returns
        -------
        out : Callable
            The inverted operation with specific parameters.
        
        """
        if operation == self.xor:
            return lambda msg: self.xor(msg, *args)
        elif operation == self.xor_key:
            return lambda msg: self.xor_key(msg, *args)
        elif operation == self.permute:
            return lambda msg: self.permute_inv(msg, *args)
        elif operation == self.permute_inv:
            return lambda msg: self.permute(msg, *args)
        elif operation == self.rol:
            return lambda msg: self.ror(msg, *args)
        elif operation == self.ror:
            return lambda msg: self.rol(msg, *args)
        elif operation == self.rol_key:
            return lambda msg: self.ror_key(msg, *args)
        elif operation == self.ror_key:
            return lambda msg: self.rol_key(msg, *args)
        elif operation == self.bit_reverse:
            return lambda msg: self.bit_reverse(msg, *args)
        elif operation == self.rol_rows:
            return lambda msg: self.ror_rows(msg, *args)
        elif operation == self.ror_rows:
            return lambda msg: self.rol_rows(msg, *args)
        elif operation == self.mix_columns:
            return lambda msg: self.unmix_columns(msg, *args)
        elif operation == self.unmix_columns:
            return lambda msg: self.mix_columns(msg, *args)
        elif operation == self.sbox:
            return lambda msg: self.sbox_inv(msg, *args)
        elif operation == self.sbox_inv:
            return lambda msg: self.sbox(msg, *args)
        else:
            raise ValueError("Unrecognized operation: %s" % (operation.__name__ if hasattr(operation, '__name__') else str(operation)))
        
        
    
class Streamer:
    def __init__(self, context: Context):
        """
        Specify the context!
        
        Parameters
        ----------
        context : Context
            A context object defined by you :p
        
        """
        self.context = context
        self.stream = []
    
    def set_stream(self, stream: Sequence) -> 'Streamer':
        """
        Specify the bit operation stream.
        
        The stream:
        
                 head  -------->  tail
                  |                |
                  v                v
        stream = op_1, op_2, ..., op_n
        op_i = op_name, *args
        
        Parameters
        ----------
        stream : Sequence of sequences
            A stream of bit operations in the context,
            input format defined above.
        
        Returns
        -------
        self : Self
        
        Examples
        --------
        >>> ctx = Context(8, 16, bytes)
        >>> msg = b'This is 16 bytes'
        >>> key = b'Another 16 bytes'
        >>> streamer = Streamer(ctx)
        >>> streamer.set_stream([
        ...     [ctx.xor, key],
        ...     [ctx.bit_reverse],
        ...     [ctx.ror_key, 3]
        ... ])
        
        The above specifies a stream of operations that
        firstly xors the input with `key`, then reverse
        the bits of each entry, and lastly rotate the bits
        rightward by 3 bits.
        
        """
        self.stream = stream
        tmp = []
        for op in self.stream.__reversed__():
            tmp.append(self.context._invert(*op[:]))
        self._stream_reversed = tmp
        return self
    
    def input(self, message: Iterable, maxstep: int = -1, reversed: bool = False) -> Iterable:
        """
        Input your message into either end of the stream,
        note that your stream has two ends. When your input
        goes into the head, the streamer encrypts it by
        performing the operations the stream contains.
        When your input goes into the tail, the streamer
        decrypts it by performing inverse operations
        of the stream!
        
        Parameters
        ----------
        message : Iterable of ints
            The input message.
        maxstep : int
            Not more than `maxstep` operations are performed
            in the stream. Set `maxstep` to negative to revoke
            the limit.
        reversed : bool
            Determines whether the input is put into the head
            (`reversed = False`) or the tail (`reversed = True`).
        
        Returns
        -------
        out : Iterable
            The output of the stream.
        
        Examples
        --------
        >>> ctx = Context(8, 16, bytes)
        >>> msg = b'This is 16 bytes'
        >>> key = b'Another 16 bytes'
        >>> streamer = Streamer(ctx)
        >>> streamer.set_stream([
        ...     [ctx.xor, key],
        ...     [ctx.bit_reverse],
        ...     [ctx.ror_key, 3]
        ... ])
        >>> streamer.input(msg)
        b'\x15\x0c\x0c\x1cB\x06\x10\x00\x00\x00\x00\x00\x00\x00\x00\x00'
        
        One can equivalently use instructions below
        to put the message into the head.
        
        >>> ctx = Context(8, 16, bytes)
        >>> msg = b'This is 16 bytes'
        >>> key = b'Another 16 bytes'
        >>> msg = ctx.xor(msg, key)
        >>> msg = ctx.bit_reverse(msg)
        >>> msg = ctx.ror_key(msg, 3)
        >>> msg
        b'\x15\x0c\x0c\x1cB\x06\x10\x00\x00\x00\x00\x00\x00\x00\x00\x00'
        
        Putting the message into the tail.
        
        >>> ctx = Context(8, 16, bytes)
        >>> msg = b'\x15\x0c\x0c\x1cB\x06\x10\x00\x00\x00\
            \x00\x00\x00\x00\x00\x00'
        >>> key = b'Another 16 bytes'
        >>> streamer = Streamer(ctx)
        >>> streamer.set_stream([
        ...     [ctx.xor, key],
        ...     [ctx.bit_reverse],
        ...     [ctx.ror_key, 3]
        ... ])
        >>> streamer.input(msg, reversed = True)
        b'This is 16 bytes'
        
        Which is equivalent to instructions below.
        
        >>> ctx = Context(8, 16, bytes)
        >>> msg = b'\x15\x0c\x0c\x1cB\x06\x10\x00\x00\x00\
            \x00\x00\x00\x00\x00\x00'
        >>> key = b'Another 16 bytes'
        >>> msg = ctx.rol_key(msg, 3)
        >>> msg = ctx.bit_reverse(msg)
        >>> msg = ctx.xor(msg, key)
        >>> msg
        b'This is 16 bytes'
        
        """
        msg = self.context.ret(message)
        for op in (self._stream_reversed if reversed else self.stream):
            if maxstep == 0: return msg
            msg = op(msg) if reversed else op[0](msg, *op[1:])
            maxstep -= 1
        return msg



"""
Several sanity checks    :p
"""

if '__main__' == __name__:
    print(bitcat([1, 0, 1, 1, 0]), 0b10110)
    print(intcat([255, 254, 253]), 255 * 65536 + 254 * 256 + 253)

    ctx = Context(8, 16, bytes)
    
    msg1 = b'This is 16 bytes'
    msg2 = b'Another 16 bytes'
    msg3 = b'i  yhs6e b1siTst'
    msg4 = b'T\xd0\xa5\x9b\x02-\xdc\x101\x1b\x08L\x97\xa3\x95\xe6'
    msg5 = b'E\x86\x967\x02\x967\x02\x13c\x02&\x97GV7'
    msg6 = b'Thisis   b16syte'
    msg7 = b'isTh  isb16 tesy'
    msg8 = b'\x80)\x02\x97>\x94\x8a\xe6\x9d\xf1\xf5\x02\x1f\x0f"1'
    table = [
        13, 4, 0, 5,
        2, 12, 11, 8,
        10, 6, 1, 9,
        3, 15, 7, 14
    ]
    shifts = [0, 1, 2, 3, 4, 5, 6, 7, 8, 7, 6, 5, 4, 3, 2, 1]
    
    print(ctx.xor(msg1, msg2))
    print(ctx.xor_key(msg1, 42))
    
    print(ctx.permute(msg1, table))
    print(ctx.permute_inv(msg3, table))
    
    print(ctx.rol(msg1, shifts))
    print(ctx.ror(msg4, shifts))
    
    print(ctx.rol_key(msg1, 4))
    print(ctx.ror_key(msg5, 4))
    
    print(ctx.bit_reverse(msg1))
    
    print(ctx.rol_rows(msg1))
    print(ctx.ror_rows(msg6))
    
    print(ctx.rol_rows(msg1, [2,3,-1,1]))
    print(ctx.ror_rows(msg7, [2,3,-1,1]))
    
    print(hex(ctx._gmul(0x11, 0x45, 0x2b)))
    print(hex(ctx._gmul(0x1e, 0xaa, 0x2b)))
    print(hex(ctx._gmul(0x06, 0xff, 0xa6)))    # not irreducible
    
    print(ctx.mix_columns(msg1))
    print(ctx.unmix_columns(msg8))
    
    ctx2 = Context(8, 17, bytes)
    
    try:
        print(ctx2.rol_rows(b'a'*17))
    except AssertionError as e:
        print(e)
    
    msg = b'This is 16 bytes'
    key = b'Another 16 bytes'
    streamer = Streamer(ctx)
    streamer.set_stream([
        [ctx.xor, key],
        [ctx.bit_reverse],
        [ctx.ror_key, 3]
    ])
    print(streamer.input(msg))
    
    msg = b'\x15\x0c\x0c\x1cB\x06\x10\x00\x00\x00\x00\x00\x00\x00\x00\x00'
    key = b'Another 16 bytes'
    streamer = Streamer(ctx)
    streamer.set_stream([
        [ctx.xor, key],
        [ctx.bit_reverse],
        [ctx.ror_key, 3]
    ])
    print(streamer.input(msg, reversed = True))
    
    msg = b'This is 16 bytes'
    key = b'Another 16 bytes'
    streamer = Streamer(ctx)
    streamer.set_stream([
        [ctx.xor, key],
        [ctx.bit_reverse],
        [ctx.ror_key, 3]
    ])
    print(streamer.input(msg, maxstep = 2))
    
    ctx = Context(32, 4, list)
    msg = [114514, 1919810, 893, 133700]
    key = [1337, 7331, 422244, 110010]
    table = [1, 3, 2, 0]
    shifts = [20, 30, 15, 3]
    streamer = Streamer(ctx)
    print(streamer.set_stream([
        [ctx.xor, key],
        [ctx.rol_rows],
        [ctx.bit_reverse],
        [ctx.ror_key, 14],
        [ctx.rol, shifts],
        [ctx.permute_inv, table]
    ]).input(msg))
    
    msg = [2147538525, 1047736, 815579137, 4205707297]
    key = [1337, 7331, 422244, 110010]
    streamer = Streamer(ctx)
    print(streamer.set_stream([
        [ctx.xor, key],
        [ctx.rol_rows],
        [ctx.bit_reverse],
        [ctx.ror_key, 14],
        [ctx.rol, shifts],
        [ctx.permute_inv, table]
    ]).input(msg, reversed = True))
    
    try:
        streamer.set_stream([
            [lambda: 'dummy']
        ])
    except ValueError as e:
        print(e)
    
    ctx = Context(8, 16, bytes)
    msg = b'AbCdEfGhIjKlMnOp'
    table = [
        13, 4, 0, 5,
        2, 12, 11, 8,
        10, 6, 1, 9,
        3, 15, 7, 14
    ]
    key = b'1002202022010100'
    shifts = [1, 3, 4, 2] * 4
    streamer = Streamer(ctx)
    print(streamer.set_stream([
        [ctx.xor, key],
        [ctx.mix_columns],
        [ctx.rol_rows],
        [ctx.bit_reverse],
        [ctx.ror_key, 3],
        [ctx.rol, shifts],
        [ctx.mix_columns],
        [ctx.sbox_inv],
        [ctx.permute_inv, table]
    ]).input(msg))
    
    msg = b"\x91\x18\xe6[S\x9aL\x1c\xf0'\xa5\xc0Q\xcb\x85\x80"
    print(streamer.set_stream([
        [ctx.xor, key],
        [ctx.mix_columns],
        [ctx.rol_rows],
        [ctx.bit_reverse],
        [ctx.ror_key, 3],
        [ctx.rol, shifts],
        [ctx.mix_columns],
        [ctx.sbox_inv],
        [ctx.permute_inv, table]
    ]).input(msg, reversed = True))
    