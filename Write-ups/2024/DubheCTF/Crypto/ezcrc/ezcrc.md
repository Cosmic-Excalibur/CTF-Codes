# ezcrc

Assignee: leukocyte 
Status: Completed
Tags: Crypto

去年做过一个 ACTF 的题，也是 crc，那个题没出，但是留下了这个：

```python
def crc256(msg,IN,OUT,POLY):
        crc = IN
        for b in msg:
            crc ^^= b
            for _ in range(8):
                crc = (crc >> 1) ^^ (POLY & -(crc & 1))
        return int(crc ^^ OUT).to_bytes(32,'big')

def equivalent_affine_crc(IN,OUT,POLY,target_bytes):
    crc=crc256
    crc_bits = 256
    zero_crc = crc(target_bytes*b"\x00",IN,OUT,POLY)
    zero_crc=bytes_to_long(zero_crc)
    target_bits = 8 * target_bytes
    v2n = lambda v: int(''.join(map(str, v)), 2)
    n2v = lambda n: vector(GF(2), bin(n)[2:].zfill(crc_bits))
    # n2v_t = lambda n: vector(GF(2), bin(n)[2:].zfill(target_bits))
    Affine_Matrix = []
    for i in range(target_bits):
        v = vector(GF(2), (j == i for j in range(target_bits)))
        value = bytes_to_long(crc(long_to_bytes(v2n(v),target_bytes),IN,OUT,POLY))^^zero_crc
        Affine_Matrix.append(n2v(value))
    # crc affine function: crc_128(x) = M*x+ C
    return matrix(GF(2),Affine_Matrix).transpose(), n2v(zero_crc)

def crc_256_reverse(crc_value,IN,OUT,POLY,target):
    M , C = equivalent_affine_crc(IN,OUT,POLY,target)
    # crc affine function: crc_128(x) = M*x+ C
    v2n = lambda v: int(''.join(map(str, v)), 2)
    n2v = lambda n: vector(GF(2), bin(n)[2:].zfill(256))
    res = M.solve_right(n2v(crc_value)+C)
    return long_to_bytes(v2n(res),16)
```

原题是 128，这个是我改的 256。

那么这个就给了我们一个可以对 crc 求逆的东西。

然后这个题他给了我们一个 len(flag)==42，flag 的形式是 DubheCTF{…}，把前后删去，正好 32 个字符，是足够我们解的。

我们是不知道 IN,OUT,POLY 这三个 crc 参数，但是 crc 是线性的，所以：

crc(m1,IN,OUT,POLY) xor crc(m2,IN,OUT,POLY) = crc(m1 xor m2,0,0,POLY)

IN,OUT 就可以直接绕过。

然后求 POLY，观察 crc 的流程，我们发现 crc(byte[256], 0, 0, POLY)=POLY。

剩下的就是实现了，总共的交互次数是 4 次，exp：

```python
# sage
from pwn import *
import random
import os
import string
from hashlib import sha256
import signal
import json
from Crypto.Util.number import *

def crc256(msg,IN,OUT,POLY):
        crc = IN
        for b in msg:
            crc ^^= b
            for _ in range(8):
                crc = (crc >> 1) ^^ (POLY & -(crc & 1))
        return int(crc ^^ OUT).to_bytes(32,'big')

def equivalent_affine_crc(IN,OUT,POLY,target_bytes):
    crc=crc256
    crc_bits = 256
    zero_crc = crc(target_bytes*b"\x00",IN,OUT,POLY)
    zero_crc=bytes_to_long(zero_crc)
    target_bits = 8 * target_bytes
    v2n = lambda v: int(''.join(map(str, v)), 2)
    n2v = lambda n: vector(GF(2), bin(n)[2:].zfill(crc_bits))
    # n2v_t = lambda n: vector(GF(2), bin(n)[2:].zfill(target_bits))
    Affine_Matrix = []
    for i in range(target_bits):
        v = vector(GF(2), (j == i for j in range(target_bits)))
        value = bytes_to_long(crc(long_to_bytes(v2n(v),target_bytes),IN,OUT,POLY))^^zero_crc
        Affine_Matrix.append(n2v(value))
    # crc affine function: crc_128(x) = M*x+ C
    return matrix(GF(2),Affine_Matrix).transpose(), n2v(zero_crc)

def crc_256_reverse(crc_value,IN,OUT,POLY,target):
    M , C = equivalent_affine_crc(IN,OUT,POLY,target)
    # crc affine function: crc_128(x) = M*x+ C
    v2n = lambda v: int(''.join(map(str, v)), 2)
    n2v = lambda n: vector(GF(2), bin(n)[2:].zfill(256))
    res = M.solve_right(n2v(crc_value)+C)
    return long_to_bytes(v2n(res),16)

r=remote("1.95.38.136","8888")
r.recv()

def proof(r):
    poss=string.ascii_letters + string.digits
    lis=r.recv().split(b'sha256(XXXX+')
    lis=lis[1].strip(b'\nGive me XXXX: ').split(b') == ')
    suf,hash=lis[0],lis[1]
    print(suf,hash)
    suf=suf.decode()
    hash=hash.decode()
    for a in poss:
        for b in poss:
            for c in poss:
                for d in poss:
                    if(sha256((a+b+c+d+suf).encode()).hexdigest()==hash):
                        r.send((a+b+c+d).encode())
                        return
proof(r)

def get_flag(r):
    r.recvuntil(b'exit\n>')
    r.sendline(b'2')
    return r.recvline().split(b'Here is your flag: ')[-1].strip()

crc_flag=int(get_flag(r).decode(),16)
print(crc_flag)

def send_mes(r,mes):
    r.recvuntil(b'exit\n')
    r.sendline(b'1')
    r.recvline()
    r.sendline(mes)
    return r.recvline().split(b'Here is your crc: ')[-1].strip()

def get_poly(r):
    m1=send_mes(r,b'\x00')
    m2=send_mes(r,b'\x80')
    return int(m1.decode(),16)^^int(m2.decode(),16)

POLY=get_poly(r)

tmp=int(send_mes(r,b"DubheCTF{"+b"\x00"*33).decode(),16)
crc_flag^^=tmp

def rev_crc(mes,POLY,data=b'}'):
    for i in range(8):
        t=mes>>255&1
        mes=(mes^^(POLY & -t))<<1|t
    mes^^=data[0]
    return mes
    
crc_flag=rev_crc(crc_flag,POLY)

flag=crc_256_reverse(crc_flag,0,0,POLY,32)
print(flag)

# DubheCTF{990676d29c2e351c80f382b065ba7418}
```