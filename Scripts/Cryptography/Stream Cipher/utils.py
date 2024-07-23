"""
Commonly used utils in stream ciphers 4 the lazy guys :p
Can be renamed as "utils_lazy.py" to avoid namespace pollution.
"""


from collections.abc import Iterable, Sequence
import functools


"""
bitcat : Bitwise concatenation
intcat : Monic bit sequence bitwise concatenation
"""
bitcat = lambda bits: functools.reduce(lambda a, b: a << 1 | b, bits)
intcat = lambda ints: functools.reduce(lambda a, b: a << b.bit_length() | b, ints)

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
    
    def xor(self, msg1: Iterable, msg2: Iterable):
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
    
    def xor_key(self, msg: Iterable, key: int):
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
    
    def permute(self, message: Sequence, table: Sequence):
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
    
    def permute_inv(self, message: Sequence, table: Sequence):
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
    
    def rol(self, message: Iterable, keys: Iterable):
        """
        Circularly shift the bits of each message entry
        leftward according to the corresponding
        shift operand in `keys`.
        
        Each entry in `keys` should not be
        greater than `m`.
        
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
        mask = (1 << self.m) - 1
        return self.ret((m << k | m >> (self.m - k)) & mask for m, k in zip(message, keys))
    
    def ror(self, message: Iterable, keys: Iterable):
        """
        Circularly shift the bits of each message entry
        rightward according to the corresponding
        shift operand in `keys`.
        
        Each entry in `keys` should not be
        greater than `m`.
        
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
        mask = (1 << self.m) - 1
        return self.ret((m >> k | m << (self.m - k)) & mask for m, k in zip(message, keys))
    
    def rol_key(self, message: Iterable, key: int):
        """
        Circularly shift the bits of each message entry
        leftward according to the shift operand `key`.
        
        `key` should not be greater than `m`.
        
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
        mask = (1 << self.m) - 1
        return self.ret((m << key | m >> (self.m - key)) & mask for m in message)
    
    def ror_key(self, message: Iterable, key: int):
        """
        Circularly shift the bits of each message entry
        rightward according to the shift operand `key`.
        
        `key` should not be greater than `m`.
        
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
        mask = (1 << self.m) - 1
        return self.ret((m >> key | m << (self.m - key)) & mask for m in message)
    
    def bit_reverse(self, message: Iterable):
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


"""
Several sanity checks
"""

if '__main__' == __name__:
    print(bitcat([1,0,1,1,0]), 0b10110)
    print(intcat([255, 254, 253]), 255 * 65536 + 254 * 256 + 253)

    ctx = Context(8, 16, bytes)
    
    msg1 = b'This is 16 bytes'
    msg2 = b'Another 16 bytes'
    msg3 = b'i  yhs6e b1siTst'
    msg4 = b'T\xd0\xa5\x9b\x02-\xdc\x101\x1b\x08L\x97\xa3\x95\xe6'
    msg5 = b'E\x86\x967\x02\x967\x02\x13c\x02&\x97GV7'
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