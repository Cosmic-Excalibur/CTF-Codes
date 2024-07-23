"""
Commonly used utils in stream ciphers 4 the lazy guys :p
Can be renamed as "utils_lazy.py" to avoid namespace pollution.
"""


from collections.abc import Iterable, Sequence
from typing import Callable
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
    
    def ror(self, message: Iterable, keys: Iterable) -> Iterable:
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
    
    def rol_key(self, message: Iterable, key: int) -> Iterable:
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
    
    def ror_key(self, message: Iterable, key: int) -> Iterable:
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
    
    def set_stream(self, stream: Sequence):
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
Several sanity checks
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
    streamer.set_stream([
        [ctx.xor, key],
        [ctx.bit_reverse],
        [ctx.ror_key, 14],
        [ctx.rol, shifts],
        [ctx.permute_inv, table]
    ])
    print(streamer.input(msg))
    
    msg = [3087042538, 1047736, 815579137, 2539651125]
    key = [1337, 7331, 422244, 110010]
    streamer = Streamer(ctx)
    streamer.set_stream([
        [ctx.xor, key],
        [ctx.bit_reverse],
        [ctx.ror_key, 14],
        [ctx.rol, shifts],
        [ctx.permute_inv, table]
    ])
    print(streamer.input(msg, reversed = True))