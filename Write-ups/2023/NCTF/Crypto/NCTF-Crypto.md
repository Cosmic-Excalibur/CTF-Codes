## Crypto

### SteinsGate

Padding Oracle + 差分优化

填充的方法取自：[HITCON2023同文章](https://link.springer.com/chapter/10.1007/978-3-319-30840-1_21#Sec16)(细心的朋友一定发现了这里题目脚本大部分直接抄HITCON2023的)

上次HITCON是用了模型1，看了官方的WP说，他推了一下发现三个模型都是有问题的，那我也试着去推一下看看，这题不就出来了吗？这题不就出来了吗？

那么这题有什么新意在里面呢？除了PaddingOracle这种古老的东西。

1. 和HITCON2023的CareLess 一样，我提供了一个NCTF{的明文头作为提示，可以发现每组密文单独提出来都有办法提交到服务器去做解密，我们只需要猜测后面两个字符就可以直接按照PaddingOracle的思路去打，但是我们一定要猜256*256吗？注意到填充的时候是会忽略到Y的最低位，所以我们如法炮制，猜256*128组就可以。
2. 接下来就是猜明文，很多师傅都是直接猜16*16的十六进制明文，一开始出这道题的时候我也想过会有这种办法，但是实际上这样猜最差情况要猜大概20-30分钟左右(复杂度我懒得估算了)，有点没意思。仔细想想，我们再猜倒数第三位和第四位的时候，是要用到异或"有效明文"才能继续猜测，有没有一种可能有效明文我们不一定知道，但是这个异或值是可以知道的，那就是差分。
3. 16*16的两个十六进制数差分值大概只有30组左右，猜那个复杂度一下就低很多了。所以预期解就如下所示：

```Python
from pwn import *
import itertools
import string
import hashlib
from Crypto.Util.number import *
#context.log_level = 'debug'
import time
start = time.time()
#io = process(['python3','Padding.py'])
io = remote('8.222.191.182',11111)

def proof(io):
    io.recvuntil(b"XXXX+")
    suffix = io.recv(16).decode("utf8")
    io.recvuntil(b"== ")
    cipher = io.recvline().strip().decode("utf8")
    for i in itertools.product(string.ascii_letters+string.digits, repeat=4):
        x = "{}{}{}{}".format(i[0],i[1],i[2],i[3])
        proof=hashlib.sha256((x+suffix.format(i[0],i[1],i[2],i[3])).encode()).hexdigest()
        if proof == cipher:
            break
    print(x)
    io.sendlineafter(b"XXXX:",x.encode())

def send_payload(m):
        io.recvuntil(b'Try unlock:')
        io.sendline(m.hex().encode())
        return io.recvline()

def enc2text(X,Y,D_iv):
        box = [X,Y,X,Y,Y,Y,Y,Y,Y,Y,Y,Y,Y,Y,Y,Y]
        return xor(box,D_iv)

def search_TOP2(BIV,BC):
        #diff_box = [ 1, 2, 3, 4, 5, 6, 7, 8, 9, 81, 82, 83, 84, 85, 86, 80, 87, 10, 11, 12, 13, 14, 15, 89, 90, 91, 92, 93, 94, 88, 95]
        #可能的16进制差分值
        diff_box = [ord(b'N')^ord(b'C')]
        #diff_box = [85]
        #diff_box = [85]
        D_iv = bytearray(BIV)
        for k in range(0xff):
                times = 0
                for i in range(0,0xff,2):
                        #check = bytearray(BIV)
                        D_iv[14] = k
                        D_iv[15] = i
                        payload = bytes(D_iv)+BC
                        result = send_payload(payload)
                        if b'Bad key... do you even try?' in result:
                                print(result)
                                print(list(D_iv))
                                times +=1
                                break
                if times:break

        cache = D_iv[14]
        time = 0
        for diff in diff_box:
                D_iv[14] = cache^diff
                for i in range(0xff):
                        D_iv[13] = i
                        payload = bytes(D_iv)+BC
                        result = send_payload(payload)
                        if b'Bad key... do you even try?' in result:
                                print(result,'test:',diff)
                                result_diff = diff
                                D_iv[13] = i^diff
                                time += 1
                                break
                if time==0:
                        D_iv[15] ^= 1
                        for i in range(0xff):
                                D_iv[13] = i
                                payload = bytes(D_iv)+BC
                                result = send_payload(payload)
                                if b'Bad key... do you even try?' in result:
                                        print(result,'test:',diff)
                                        result_diff = diff
                                        D_iv[13] = i^diff
                                        time += 1
                                        break
                #if time:break
        return D_iv,result_diff

def oracle_block(BIV,BC):
        D_iv,diff = search_TOP2(BIV,BC)
        for _ in range(12,1,-1):
                for i in range(0xff):
                        D_iv[_] = i
                        payload = bytes(D_iv)+BC
                        result = send_payload(payload)
                        if b'Bad key' in result:
                                print(result)
                                D_iv[_] = i^diff
                                break
        
        #print(list(D_iv))
        #print(list(bytearray(BIV)))
        
        diff_box = {'0': [(48, 48), (49, 49), (50, 50), (51, 51), (52, 52), (53, 53), (54, 54), (55, 55), (56, 56), (57, 57), (97, 97), (98, 98), (99, 99), (100, 100), (101, 101), (102, 102)], '1': [(48, 49), (49, 48), (50, 51), (51, 50), (52, 53), (53, 52), (54, 55), (55, 54), (56, 57), (57, 56), (98, 99), (99, 98), (100, 101), (101, 100)], '2': [(48, 50), (49, 51), (50, 48), (51, 49), (52, 54), (53, 55), (54, 52), (55, 53), (97, 99), (99, 97), (100, 102), (102, 100)], '3': [(48, 51), (49, 50), (50, 49), (51, 48), (52, 55), (53, 54), (54, 53), (55, 52), (97, 98), (98, 97), (101, 102), (102, 101)], '4': [(48, 52), (49, 53), (50, 54), (51, 55), (52, 48), (53, 49), (54, 50), (55, 51), (97, 101), (98, 102), (101, 97), (102, 98)], '5': [(48, 53), (49, 52), (50, 55), (51, 54), (52, 49), (53, 48), (54, 51), (55, 50), (97, 100), (99, 102), (100, 97), (102, 99)], '6': [(48, 54), (49, 55), (50, 52), (51, 53), (52, 50), (53, 51), (54, 48), (55, 49), (98, 100), (99, 101), (100, 98), (101, 99)], '7': [(48, 55), (49, 54), (50, 53), (51, 52), (52, 51), (53, 50), (54, 49), (55, 48), (97, 102), (98, 101), (99, 100), (100, 99), (101, 98), (102, 97)], '8': [(48, 56), (49, 57), (56, 48), (57, 49)], '9': [(48, 57), (49, 56), (56, 49), (57, 48)], '81': [(48, 97), (50, 99), (51, 98), (52, 101), (53, 100), (55, 102), (97, 48), (98, 51), (99, 50), (100, 53), (101, 52), (102, 55)], '82': [(48, 98), (49, 99), (51, 97), (52, 102), (54, 100), (55, 101), (97, 51), (98, 48), (99, 49), (100, 54), (101, 55), (102, 52)], '83': [(48, 99), (49, 98), (50, 97), (53, 102), (54, 101), (55, 100), (97, 50), (98, 49), (99, 48), (100, 55), (101, 54), (102, 53)], '84': [(48, 100), (49, 101), (50, 102), (53, 97), (54, 98), (55, 99), (97, 53), (98, 54), (99, 55), (100, 48), (101, 49), (102, 50)], '85': [(48, 101), (49, 100), (51, 102), (52, 97), (54, 99), (55, 98), (97, 52), (98, 55), (99, 54), (100, 49), (101, 48), (102, 51)], '86': [(48, 102), (50, 100), (51, 101), (52, 98), (53, 99), (55, 97), (97, 55), (98, 52), (99, 53), (100, 50), (101, 51), (102, 48)], '80': [(49, 97), (50, 98), (51, 99), (52, 100), (53, 101), (54, 102), (97, 49), (98, 50), (99, 51), (100, 52), (101, 53), (102, 54)], '87': [(49, 102), (50, 101), (51, 100), (52, 99), (53, 98), (54, 97), (97, 54), (98, 53), (99, 52), (100, 51), (101, 50), (102, 49)], '10': [(50, 56), (51, 57), (56, 50), (57, 51)], '11': [(50, 57), (51, 56), (56, 51), (57, 50)], '12': [(52, 56), (53, 57), (56, 52), (57, 53)], '13': [(52, 57), (53, 56), (56, 53), (57, 52)], '14': [(54, 56), (55, 57), (56, 54), (57, 55)], '15': [(54, 57), (55, 56), (56, 55), (57, 54)], '89': [(56, 97), (97, 56)], '90': [(56, 98), (57, 99), (98, 56), (99, 57)], '91': [(56, 99), (57, 98), (98, 57), (99, 56)], '92': [(56, 100), (57, 101), (100, 56), (101, 57)], '93': [(56, 101), (57, 100), (100, 57), (101, 56)], '94': [(56, 102), (102, 56)], '88': [(57, 97), (97, 57)], '95': [(57, 102), (102, 57)]}
        print(diff)
        key = diff_box[str(diff)]
        key = [(ord('N'),(ord('C')))] #位置1与位置2的差分
        print(key)
        text = []
        for (i,k) in key:
                text.append(xor(BIV,enc2text(i,k,D_iv)))
        return text


def attack(enc):
        block = [enc[16*i:16*(i+1)] for i in range(len(enc)//16)]
        for i in range(1,len(block)): #这里手动选一下要猜测的密文块
                result = oracle_block(block[i-1],block[i])
                print(result)
                break

proof(io)
io.recvuntil(b'key:')
enc = bytes.fromhex(io.recvline()[:-1].decode())
attack(enc)
end = time.time()
print(end - start)
```

上题的时候没注意，把测试版丢上去了，结果出了一个BUG，我在用自己的脚本打的时候发现解不了，我以为是服务器问题，加上有师傅反馈本地通了，远程交互时间不够。出题时间太早，一时半会我也记不清细节了，还真以为这题废了。后来再测试的时候发现400秒完全是绰绰有余的:

![img](https://hackforfun.feishu.cn/space/api/box/stream/download/asynccode/?code=NmE3NjJjOTY1ZGRjNjA2ZDAxMjhlN2I4ODdhMzI0ZDBfRUU3c05vZ2VjSjVrMTZ4clRNQXduaWt5cTlpUU9RZVlfVG9rZW46R3FNdGJNb1hLb09VYk14bFBUTGNnVmlSbkVlXzE3MDM0Mjc0Mzc6MTcwMzQzMTAzN19WNA)

随即把交互时间改回去了，唉明明是一个很巧妙的Padding，被暴力非预期了。。

### FaultMilestone

参考文献：[文献地址](https://www.iacr.org/archive/ches2009/57470460/57470460.pdf)

本题为DES故障差分分析，其实关于DES差分的核心都差不多，

篇幅有限，这里就简单阐述如何攻击DES算法：

1. 只要我们能够恢复某一轮的密钥，就能够倒推回256种可能的主密钥(轮密钥拓展时会丢失信息)
2. 现在首要目标就是恢复某一轮的轮密钥，仔细观察DES的其中某一轮的加密结构，如图：

![img](https://hackforfun.feishu.cn/space/api/box/stream/download/asynccode/?code=YmU4MWNhN2M2Yzg1MjEwZTdlMDc4NDM1ZjFlYjBjZDNfbERPc2FGUGt0cXRxSUJ0NGx3YWllV1dFYzhpZE9XV1BfVG9rZW46UHkwTmJva2Ryb3pBQm54ZWU1NWN2M05oblRkXzE3MDM0Mjc0Mzc6MTcwMzQzMTAzN19WNA)

可以看到轮密钥加(第一个XOR)这步在S盒之前，那么我们的差分分析就应该应用在此处。

1. E盒，P盒是线性可逆的，那么接下来要应用差分攻击就得拿到进入S盒的前后输入，之后就猜测轮密钥就可以。通过密文可以直接了当地拿到输入加密前的差分(注意右半部分直接移动到左半部分作为密文)，那么现在问题自然而然地就落到了怎么找输出差分上面，也就是拿到(第二个XOR的输入值)。
2. 观察题目故障(Fault)的发生位置是位于13轮加密前，只造成了 1 bit 的故障，就是因为这个才使得我们有机可乘拿到第二个XOR的差分输入，所以重点的分析就落在了这里——找到这个bit造成的影响。

这里我推荐一种直观的分析办法：现在我们的目标是拿到最后一轮的输入输出差分，那么既然题目是可以多次提供密文的，就说明上一轮的输出差分(作为下一轮的输入差分)会有某种固定的关系(具体原因篇幅有限难以解释)，那么我们直接在本地把16轮中的最后一轮加密删去，反复测试一下密文右半部分的差分关系。

这时候就发现猫腻了——15轮输出的差分虽然不是固定的，但是确实可猜测的，有极大概率会落在10种可能中(出完题测试脚本就删了，这里就不放截图了，感兴趣的可以自己测试，直接给出结果)。

大致上可能的取值如下:

```Python
diffs = ['0x202', '0x8002', '0x8200', '0x8202', '0x800002', '0x800200', '0x800202', '0x808000', '0x808002', '0x808200', '0x808202']
```

到这里这道题就变得很简单了，把这几个可能值当做已知去用，直接做差分分析猜测轮密钥，再从轮密钥恢复主密钥就结束了。——原本这道题是给了静态密文不打算部署在云端的，考虑到公平性和防作弊还是部署在云端生成密文了，这里会有极低的可能性出现15轮的输出差分不落在diffs上面的情况，这组不行建议多试试几组，总能行的。

这里给出个人解法:

先补完解密函数，写一个正常的DES，用作还原FLAG:

```Python
from operator import add
from typing import List
from functools import reduce
from gmpy2 import *
from Crypto.Util.number import long_to_bytes,bytes_to_long

_IP = [57, 49, 41, 33, 25, 17, 9,  1,
        59, 51, 43, 35, 27, 19, 11, 3,
        61, 53, 45, 37, 29, 21, 13, 5,
        63, 55, 47, 39, 31, 23, 15, 7,
        56, 48, 40, 32, 24, 16, 8,  0,
        58, 50, 42, 34, 26, 18, 10, 2,
        60, 52, 44, 36, 28, 20, 12, 4,
        62, 54, 46, 38, 30, 22, 14, 6
]

def IP(plain: List[int]) -> List[int]:
    return [plain[x] for x in _IP]

__pc1 = [56, 48, 40, 32, 24, 16,  8,
          0, 57, 49, 41, 33, 25, 17,
          9,  1, 58, 50, 42, 34, 26,
         18, 10,  2, 59, 51, 43, 35,
         62, 54, 46, 38, 30, 22, 14,
          6, 61, 53, 45, 37, 29, 21,
         13,  5, 60, 52, 44, 36, 28,
         20, 12,  4, 27, 19, 11,  3
]

__pc2 = [
        13, 16, 10, 23,  0,  4,
         2, 27, 14,  5, 20,  9,
        22, 18, 11,  3, 25,  7,
        15,  6, 26, 19, 12,  1,
        40, 51, 30, 36, 46, 54,
        29, 39, 50, 44, 32, 47,
        43, 48, 38, 55, 33, 52,
        45, 41, 49, 35, 28, 31
]
ROTATIONS = [1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1]

def PC_1(key: List[int]) -> List[int]:
    return [key[x] for x in __pc1]

def PC_2(key: List[int]) -> List[int]:
    return [key[x] for x in __pc2]

def get_sub_key(key: List[int]) -> List[List[int]]:
    key = PC_1(key)
    L, R = key[:28], key[28:]

    sub_keys = []

    for i in range(16):
        for j in range(ROTATIONS[i]):
            L.append(L.pop(0))
            R.append(R.pop(0))

        combined = L + R
        sub_key = PC_2(combined)
        sub_keys.append(sub_key)
    return sub_keys

__ep = [31,  0,  1,  2,  3,  4,
                 3,  4,  5,  6,  7,  8,
                 7,  8,  9, 10, 11, 12,
                11, 12, 13, 14, 15, 16,
                15, 16, 17, 18, 19, 20,
                19, 20, 21, 22, 23, 24,
                23, 24, 25, 26, 27, 28,
                27, 28, 29, 30, 31,  0
]

__p = [15,  6, 19, 20, 28, 11, 27, 16,
                0, 14, 22, 25,  4, 17, 30,  9,
                1,  7, 23, 13, 31, 26,  2,  8,
                18, 12, 29,  5, 21, 10,  3, 24
]

def EP(data: List[int]) -> List[int]:
    return [data[x] for x in __ep]

def P(data: List[int]) -> List[int]:
    return [data[x] for x in __p]

__s_box = [

        [
                [14,  4, 13,  1,  2, 15, 11,  8,  3, 10,  6, 12,  5,  9,  0,  7],
                [ 0, 15,  7,  4, 14,  2, 13,  1, 10,  6, 12, 11,  9,  5,  3,  8],
                [ 4,  1, 14,  8, 13,  6,  2, 11, 15, 12,  9,  7,  3, 10,  5,  0],
                [15, 12,  8,  2,  4,  9,  1,  7,  5, 11,  3, 14, 10,  0,  6, 13]
        ],


        [
                [15,  1,  8, 14,  6, 11,  3,  4,  9,  7,  2, 13, 12,  0,  5, 10],
                [ 3, 13,  4,  7, 15,  2,  8, 14, 12,  0,  1, 10,  6,  9, 11,  5],
                [ 0, 14,  7, 11, 10,  4, 13,  1,  5,  8, 12,  6,  9,  3,  2, 15],
                [13,  8, 10,  1,  3, 15,  4,  2, 11,  6,  7, 12,  0,  5, 14,  9]
        ],


        [
                [10,  0,  9, 14,  6,  3, 15,  5,  1, 13, 12,  7, 11,  4,  2,  8],
                [13,  7,  0,  9,  3,  4,  6, 10,  2,  8,  5, 14, 12, 11, 15,  1],
                [13,  6,  4,  9,  8, 15,  3,  0, 11,  1,  2, 12,  5, 10, 14,  7],
                [ 1, 10, 13,  0,  6,  9,  8,  7,  4, 15, 14,  3, 11,  5,  2, 12]
        ],


        [
                [ 7, 13, 14,  3,  0,  6,  9, 10,  1,  2,  8,  5, 11, 12,  4, 15],
                [13,  8, 11,  5,  6, 15,  0,  3,  4,  7,  2, 12,  1, 10, 14,  9],
                [10,  6,  9,  0, 12, 11,  7, 13, 15,  1,  3, 14,  5,  2,  8,  4],
                [ 3, 15,  0,  6, 10,  1, 13,  8,  9,  4,  5, 11, 12,  7,  2, 14]
        ],


        [
                [ 2, 12,  4,  1,  7, 10, 11,  6,  8,  5,  3, 15, 13,  0, 14,  9],
                [14, 11,  2, 12,  4,  7, 13,  1,  5,  0, 15, 10,  3,  9,  8,  6],
                [ 4,  2,  1, 11, 10, 13,  7,  8, 15,  9, 12,  5,  6,  3,  0, 14],
                [11,  8, 12,  7,  1, 14,  2, 13,  6, 15,  0,  9, 10,  4,  5,  3]
        ],


        [
                [12,  1, 10, 15,  9,  2,  6,  8,  0, 13,  3,  4, 14,  7,  5, 11],
                [10, 15,  4,  2,  7, 12,  9,  5,  6,  1, 13, 14,  0, 11,  3,  8],
                [ 9, 14, 15,  5,  2,  8, 12,  3,  7,  0,  4, 10,  1, 13, 11,  6],
                [ 4,  3,  2, 12,  9,  5, 15, 10, 11, 14,  1,  7,  6,  0,  8, 13]
        ],


        [
                [ 4, 11,  2, 14, 15,  0,  8, 13,  3, 12,  9,  7,  5, 10,  6,  1],
                [13,  0, 11,  7,  4,  9,  1, 10, 14,  3,  5, 12,  2, 15,  8,  6],
                [ 1,  4, 11, 13, 12,  3,  7, 14, 10, 15,  6,  8,  0,  5,  9,  2],
                [ 6, 11, 13,  8,  1,  4, 10,  7,  9,  5,  0, 15, 14,  2,  3, 12]
        ],


        [
                [13,  2,  8,  4,  6, 15, 11,  1, 10,  9,  3, 14,  5,  0, 12,  7],
                [ 1, 15, 13,  8, 10,  3,  7,  4, 12,  5,  6, 11,  0, 14,  9,  2],
                [ 7, 11,  4,  1,  9, 12, 14,  2,  0,  6, 10, 13, 15,  3,  5,  8],
                [ 2,  1, 14,  7,  4, 10,  8, 13, 15, 12,  9,  0,  3,  5,  6, 11]
        ]
]

def S_box(data: List[int]) -> List[int]:
    output = []
    for i in range(0, 48, 6):
        row = data[i] * 2 + data[i + 5]
        col = reduce(add, [data[i + j] * (2 ** (4 - j)) for j in range(1, 5)])
        output += [int(x) for x in format(__s_box[i // 6][row][col], '04b')]
    return output

def fault(part):
        part = bytes2bits(long_to_bytes(bytes_to_long(bits2bytes(part))^0x20000000))
        return part

def encrypt(plain: List[int], sub_keys: List[List[int]],dance=0) -> List[int]:
    plain = IP(plain)
    L, R = plain[:32], plain[32:]
    for i in range(16):
        if i == 13 and dance:R = fault(R)
        prev_L = L
        L = R
        expanded_R = EP(R)
        xor_result = [a ^ b for a, b in zip(expanded_R, sub_keys[i])]
        substituted = S_box(xor_result)
        permuted = P(substituted)
        R = [a ^ b for a, b in zip(permuted, prev_L)]
    cipher = R + L
    cipher = [cipher[x] for x in [39,  7, 47, 15, 55, 23, 63, 31,
                                38,  6, 46, 14, 54, 22, 62, 30,
                                37,  5, 45, 13, 53, 21, 61, 29,
                                36,  4, 44, 12, 52, 20, 60, 28,
                                35,  3, 43, 11, 51, 19, 59, 27,
                                34,  2, 42, 10, 50, 18, 58, 26,
                                33,  1, 41,  9, 49, 17, 57, 25,
                                32,  0, 40,  8, 48, 16, 56, 24]]
    
    return cipher,test

def decrypt(plain: List[int], sub_keys: List[List[int]],dance=0) -> List[int]:
    sub_keys = sub_keys[::-1]
    plain = IP(plain)
    L, R = plain[:32], plain[32:]
    for i in range(16):
        if i == 13 and dance:R = fault(R)
        prev_L = L
        L = R
        expanded_R = EP(R)
        xor_result = [a ^ b for a, b in zip(expanded_R, sub_keys[i])]
        substituted = S_box(xor_result)
        permuted = P(substituted)
        R = [a ^ b for a, b in zip(permuted, prev_L)]
    cipher = R + L
    cipher = [cipher[x] for x in [39,  7, 47, 15, 55, 23, 63, 31,
                                38,  6, 46, 14, 54, 22, 62, 30,
                                37,  5, 45, 13, 53, 21, 61, 29,
                                36,  4, 44, 12, 52, 20, 60, 28,
                                35,  3, 43, 11, 51, 19, 59, 27,
                                34,  2, 42, 10, 50, 18, 58, 26,
                                33,  1, 41,  9, 49, 17, 57, 25,
                                32,  0, 40,  8, 48, 16, 56, 24]]
    
    return cipher

from operator import add

def bitxor(plain1: List[int], plain2: List[List[int]]) -> List[int]:
    return [int(i) for i in bin(int(''.join(str(i) for i in plain1),2)^int(''.join(str(i) for i in plain2),2))[2:].zfill(64)]

def bytes2bits(bytes):
        result = reduce(add, [list(map(int, bin(byte)[2:].zfill(8))) for byte in bytes])
        return result

def bits2bytes(bits):
        result = ''
        for i in bits:result += str(i) 
        return long_to_bytes(int(result,2))
```

接下来做差分分析，重点落在进入S盒前后研究的部分，以及补完线性部件的逆向函数：

```Python
from Crypto.Util.number import *
from typing import List
from functools import reduce
from operator import add
from collections import Counter

__ep = [31,  0,  1,  2,  3,  4,
                 3,  4,  5,  6,  7,  8,
                 7,  8,  9, 10, 11, 12,
                11, 12, 13, 14, 15, 16,
                15, 16, 17, 18, 19, 20,
                19, 20, 21, 22, 23, 24,
                23, 24, 25, 26, 27, 28,
                27, 28, 29, 30, 31,  0
]

__P_inv = [8, 16, 22, 30, 12, 27, 1, 17, 
                        23, 15, 29, 5, 25, 19, 9, 0, 
                        7, 13, 24, 2, 3, 28, 10, 18, 
                        31, 11, 21, 6, 4, 26, 14, 20
]

__s_box = [

        [
                [14,  4, 13,  1,  2, 15, 11,  8,  3, 10,  6, 12,  5,  9,  0,  7],
                [ 0, 15,  7,  4, 14,  2, 13,  1, 10,  6, 12, 11,  9,  5,  3,  8],
                [ 4,  1, 14,  8, 13,  6,  2, 11, 15, 12,  9,  7,  3, 10,  5,  0],
                [15, 12,  8,  2,  4,  9,  1,  7,  5, 11,  3, 14, 10,  0,  6, 13]
        ],


        [
                [15,  1,  8, 14,  6, 11,  3,  4,  9,  7,  2, 13, 12,  0,  5, 10],
                [ 3, 13,  4,  7, 15,  2,  8, 14, 12,  0,  1, 10,  6,  9, 11,  5],
                [ 0, 14,  7, 11, 10,  4, 13,  1,  5,  8, 12,  6,  9,  3,  2, 15],
                [13,  8, 10,  1,  3, 15,  4,  2, 11,  6,  7, 12,  0,  5, 14,  9]
        ],


        [
                [10,  0,  9, 14,  6,  3, 15,  5,  1, 13, 12,  7, 11,  4,  2,  8],
                [13,  7,  0,  9,  3,  4,  6, 10,  2,  8,  5, 14, 12, 11, 15,  1],
                [13,  6,  4,  9,  8, 15,  3,  0, 11,  1,  2, 12,  5, 10, 14,  7],
                [ 1, 10, 13,  0,  6,  9,  8,  7,  4, 15, 14,  3, 11,  5,  2, 12]
        ],


        [
                [ 7, 13, 14,  3,  0,  6,  9, 10,  1,  2,  8,  5, 11, 12,  4, 15],
                [13,  8, 11,  5,  6, 15,  0,  3,  4,  7,  2, 12,  1, 10, 14,  9],
                [10,  6,  9,  0, 12, 11,  7, 13, 15,  1,  3, 14,  5,  2,  8,  4],
                [ 3, 15,  0,  6, 10,  1, 13,  8,  9,  4,  5, 11, 12,  7,  2, 14]
        ],


        [
                [ 2, 12,  4,  1,  7, 10, 11,  6,  8,  5,  3, 15, 13,  0, 14,  9],
                [14, 11,  2, 12,  4,  7, 13,  1,  5,  0, 15, 10,  3,  9,  8,  6],
                [ 4,  2,  1, 11, 10, 13,  7,  8, 15,  9, 12,  5,  6,  3,  0, 14],
                [11,  8, 12,  7,  1, 14,  2, 13,  6, 15,  0,  9, 10,  4,  5,  3]
        ],


        [
                [12,  1, 10, 15,  9,  2,  6,  8,  0, 13,  3,  4, 14,  7,  5, 11],
                [10, 15,  4,  2,  7, 12,  9,  5,  6,  1, 13, 14,  0, 11,  3,  8],
                [ 9, 14, 15,  5,  2,  8, 12,  3,  7,  0,  4, 10,  1, 13, 11,  6],
                [ 4,  3,  2, 12,  9,  5, 15, 10, 11, 14,  1,  7,  6,  0,  8, 13]
        ],


        [
                [ 4, 11,  2, 14, 15,  0,  8, 13,  3, 12,  9,  7,  5, 10,  6,  1],
                [13,  0, 11,  7,  4,  9,  1, 10, 14,  3,  5, 12,  2, 15,  8,  6],
                [ 1,  4, 11, 13, 12,  3,  7, 14, 10, 15,  6,  8,  0,  5,  9,  2],
                [ 6, 11, 13,  8,  1,  4, 10,  7,  9,  5,  0, 15, 14,  2,  3, 12]
        ],


        [
                [13,  2,  8,  4,  6, 15, 11,  1, 10,  9,  3, 14,  5,  0, 12,  7],
                [ 1, 15, 13,  8, 10,  3,  7,  4, 12,  5,  6, 11,  0, 14,  9,  2],
                [ 7, 11,  4,  1,  9, 12, 14,  2,  0,  6, 10, 13, 15,  3,  5,  8],
                [ 2,  1, 14,  7,  4, 10,  8, 13, 15, 12,  9,  0,  3,  5,  6, 11]
        ]
]

def S_box(data: List[int],index) -> List[int]:
    output = []
    row = data[0] * 2 + data[5]
    col = reduce(add, [data[j] * (2 ** (4 - j)) for j in range(1, 5)])
    output += [int(x) for x in format(__s_box[index][row][col], '04b')]
    return output

def P_inv(data: List[int]) -> List[int]:
        return [data[x] for x in __P_inv]

def EP(data: List[int]) -> List[int]:
    return [data[x] for x in __ep]

def bytes2bits(bytes):
        result = reduce(add, [list(map(int, bin(byte)[2:].zfill(8))) for byte in bytes])
        return result

def bits2bytes(bits):
        result = ''
        for i in bits:result += str(i) 
        return long_to_bytes(int(result,2))

def num2bits(num):
        result = list(map(int, bin(num)[2:].zfill(6)))
        return result

def bits2num(bits):
        result = ''.join([str(i) for i in bits])
        return eval('0b'+result)


def bit2list8(bits):
        assert len(bits) == 32
        result = []
        #print(bits)
        for i in range(8):
                tmp = [str(i) for i in bits[4*i:4*(i+1)]]
                tmp = eval('0b'+''.join(tmp))
                result.append(tmp)
        return result

def out_inv(cipher):
    cipher = [cipher[x] for x in[57,  49, 41, 33, 25, 17, 9, 1,
                                59,  51, 43, 35, 27, 19, 11, 3,
                                61,  53, 45, 37, 29, 21, 13, 5,
                                63,  55, 47, 39, 31, 23, 15, 7,
                                56,  48, 40, 32, 24, 16, 8, 0,
                                58,  50, 42, 34, 26, 18, 10, 2,
                                60,  52, 44, 36, 28, 20, 12, 4,
                                62,  54, 46, 38, 30, 22, 14, 6]]
    return cipher

def Get_Out_Diff(c1,c2):
        L1 = bytes_to_long(c1[:4])
        L2 = bytes_to_long(c2[:4])
        Out_Diff = hex(L1^L2)
        return Out_Diff

def guess_keys(input1,input2,output_diff):
        input1 = EP(bytes2bits(input1))
        input2 = EP(bytes2bits(input2))
        keys = []
        output_diff = bit2list8(output_diff)
        #print(input1[0:])
        for i in range(8):
                for guess_key in range(64):
                        guess_key = num2bits(guess_key)
                        xor_result1 = [a ^ b for a, b in zip(input1[6*i:6*(i+1)], guess_key)]
                        xor_result2 = [a ^ b for a, b in zip(input2[6*i:6*(i+1)], guess_key)]

                        substituted1 = S_box(xor_result1,i)
                        substituted2 = S_box(xor_result2,i)

                        if bits2num(substituted1)^bits2num(substituted2) == output_diff[i]:
                                keys.append((bits2num(guess_key),i))

        return keys




form_diff = ['0x202', '0x8002', '0x8200', '0x8202', '0x800002', '0x800200', '0x800202', '0x808000', '0x808002', '0x808200', '0x808202']


enc1=['e392ac8bb916a1c4', '20a10deb74576ae9', 'd186e0fc220a67f9', '17ce709d69048488', 'a2f945212d4684da']
enc2=['d6f79f862e21cbc7', '2185586bf0fd7ef8', '39c735debc3793bb', 'e3fa91b0b26e358d', '4be9f65d2d85ae9d']

result = []

for _ in range(5):
        for i in form_diff:
                diff1 = i
                round0 = bytes.fromhex(enc1[_])
                round1 = bytes.fromhex(enc2[_])

                round0 = bits2bytes(out_inv(bytes2bits(round0)))
                round1 = bits2bytes(out_inv(bytes2bits(round1)))

                out_diffs = (Get_Out_Diff(round0,round1))
                output_diff = long_to_bytes(eval(out_diffs)^eval(diff1))
                output_diff = P_inv(bytes2bits(output_diff))
                result += (guess_keys(round0[4:],round1[4:],output_diff))
                #print(len(result))

print(Counter(result))

#key = [i , 41 , 6 , 62 , 14  , 44 , 25 , 62]
```

注意这里生成轮密钥的时候，由于是猜测差分我们取可能性最高的那几个位置的密钥就可，但是由于未知原因0号密钥不一定能够猜出来(多半是受错误差分影响了)，但这里可以稳定猜出一个轮密钥的7/8这样就够了。

接下来还原主密钥，并用主密钥去解密:

```Python
from operator import add
from typing import List
from functools import reduce
from gmpy2 import *
from Crypto.Util.number import long_to_bytes,bytes_to_long
from copy import copy
from DES import *

ROTATIONS = [1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1]

__pc1 = [56, 48, 40, 32, 24, 16,  8,
          0, 57, 49, 41, 33, 25, 17,
          9,  1, 58, 50, 42, 34, 26,
         18, 10,  2, 59, 51, 43, 35,
         62, 54, 46, 38, 30, 22, 14,
          6, 61, 53, 45, 37, 29, 21,
         13,  5, 60, 52, 44, 36, 28,
         20, 12,  4, 27, 19, 11,  3
]
__pc2 = [
        13, 16, 10, 23,  0,  4,
         2, 27, 14,  5, 20,  9,
        22, 18, 11,  3, 25,  7,
        15,  6, 26, 19, 12,  1,
        40, 51, 30, 36, 46, 54,
        29, 39, 50, 44, 32, 47,
        43, 48, 38, 55, 33, 52,
        45, 41, 49, 35, 28, 31
]


__pc2_inv = [
        4, 23, 6, 15, 5, 9, 19, 
        17, 11, 2, 14, 22, 0, 8, 
        18, 1, 13, 21, 10, 12, 3, 
        16, 20, 7, 46, 30, 26, 47, 
        34, 40, 45, 27, 38, 31, 24, 
        43, 36, 33, 42, 28, 35, 37, 
        44, 32, 25, 41, 29, 39
]

def PC_1(key: List[int]) -> List[int]:
    return [key[x] for x in __pc1]

def PC_2(key: List[int]) -> List[int]:
    return [key[x] for x in __pc2]

def PC_2_inv(key: List[int]) -> List[int]:
    return [key[x] for x in __pc2_inv]


def get_sub_key(key: List[int]) -> List[List[int]]:
    key = PC_1(key)
    L, R = key[:28], key[28:]

    sub_keys = []

    for i in range(16):
        for j in range(ROTATIONS[i]):
            L.append(L.pop(0))
            R.append(R.pop(0))

        combined = L + R
        if i == 15:test = combined
        sub_key = PC_2(combined)
        sub_keys.append(sub_key)
    return sub_keys,test

def bytes2bits(bytes):
        result = reduce(add, [list(map(int, bin(byte)[2:].zfill(8))) for byte in bytes])
        return result

def recover(key):
        L,R = key[:28], key[28:]
        sub_keys = []
        ROTATIONS_inv = ROTATIONS[::-1]
        sub_keys.append(PC_2(L+R))
        for i in range(15):
                for j in range(ROTATIONS_inv[i]):
                        L.insert(0,L.pop(-1))
                        R.insert(0,R.pop(-1))
                combined = L + R
                sub_key = PC_2(combined)
                sub_keys.append(sub_key)
        return sub_keys[::-1]

def explore(orin_key):
        orin_key = PC_2_inv(orin_key)
        keys = []
        for k in range(256):
                key = copy(orin_key)
                k = bin(k)[2:].zfill(8)
                key.insert(8,int(k[0]))
                key.insert(17,int(k[1]))
                key.insert(21,int(k[2]))
                key.insert(24,int(k[3]))
                key.insert(34,int(k[4]))
                key.insert(37,int(k[5]))
                key.insert(42,int(k[6]))
                key.insert(53,int(k[7]))
                keys.append(recover(key))
        return keys

def key2keys(key):
        result = []
        for i in key:
                result += [int(i) for i in bin(i)[2:].zfill(6)]
        return result
f = open('data.txt','w')

for i in range(256):
        key = [i , 41 , 6 , 62 , 14  , 44 , 25 , 62]
        key2keys(key)

        from operator import add

        result = explore(key2keys(key))
        enc1=['e392ac8bb916a1c4', '20a10deb74576ae9', 'd186e0fc220a67f9', '17ce709d69048488', 'a2f945212d4684da']
        #enc2=['d6f79f862e21cbc7', '2185586bf0fd7ef8', '39c735debc3793bb', 'e3fa91b0b26e358d', '4be9f65d2d85ae9d']

        for tmp_key in result:
                flag = b''
                for ct in enc1:
                        ct = bytes.fromhex(ct)
                        ct = bytes2bits(ct)
                        pt = decrypt(ct,tmp_key)
                        flag +=bits2bytes(pt)
                        break
                f.write(str(flag)+'\n')
        #break
f.close()
```

因为一个确定的轮密钥会对应256种不同的主密钥，加上一个未知的轮密钥要爆破(也可以从猜测值里面找，实测可行)，所以我们大概会得到65536份解密的明文——只有一份全是可打印字符是对的，从那份提取出主密钥去还原flag就可。

### CalabiYau

密钥交换方案是基于RLWE难题的DingKeyExChange，出这题也算是跟一波潮流了，虽然这个方案好像没被NIST选上，偶然看看之后决定打打试试看，于是就有了这道题。

详细题目细节篇幅有限不再阐述，直接放攻击流程：

1. 第一部分获取Alice.s，关注到有个w的信号处理函数，用来同步双方mod2时候出现“跨域”的问题，所以Alice回复的时候会有两个信息一个是Alice.pk一个是Alice.w，前一个是幌子，我们只要构造好交换的Eve.pk，交给Alice就能一次性拿到Alice.s。
2. 第二部分获取Bob.s，发现一个小细节，Bob的e参数没了，直接拿到Bob.a*Bob.s，这时候的问题就不是RLWE了，而是ahssp，而且生成公钥的时候Bob.a是静态的(甚至是可排序的)，直接用正交格打就完了，但问题是维度有点大，还是需要优化的方案，可以参考这篇文章[文章地址](https://tl2cents.github.io/2023/12/12/Orthogonal-Lattice-Attack/)，既然是ahssp，再看一篇经典论文（[论文地址](https://eprint.iacr.org/2020/461.pdf)）

接下来知道这两部分的玩法和难题之后，我感觉就没什么难度了，唯一制约的是时间。先放solution:

(其中正交格的构造和脚本可以直接在论文里面找到，之后爆改一下就行)

```Python
#sage
from sage.all import *
from Crypto.Util.number import getPrime
import random
from pwn import *

from time import time
from random import randint

def orthoLattice(b,x0):
    m=b.length()
    M=Matrix(ZZ,m,m)
 
    for i in range(1,m):
        M[i,i]=1
    M[1:m,0]=-b[1:m]*inverse_mod(b[0],x0)
    M[0,0]=x0
 
    for i in range(1,m):
        M[i,0]=mod(M[i,0],x0)
 
    return M
 
def allones(v):
    if len([vj for vj in v if vj in [0,1]])==len(v):
      return v
    if len([vj for vj in v if vj in [0,-1]])==len(v):
      return -v
    return None
 
def recoverBinary(M5):
    lv=[allones(vi) for vi in M5 if allones(vi)]
    n=M5.nrows()
    for v in lv:
        for i in range(n):
            nv=allones(M5[i]-v)
            if nv and nv not in lv:
                lv.append(nv)
            nv=allones(M5[i]+v)
            if nv and nv not in lv:
                lv.append(nv)
    return Matrix(lv)
 
def allpmones(v):
    return len([vj for vj in v if vj in [-1,0,1]])==len(v)
 

def kernelLLL(M):
    n=M.nrows()
    m=M.ncols()
    if m<2*n: return M.right_kernel().matrix()
    K=2^(m//2)*M.height()
  
    MB=Matrix(ZZ,m+n,m)
    MB[:n]=K*M
    MB[n:]=identity_matrix(m)
  
    MB2=MB.T.LLL().T
  
    assert MB2[:n,:m-n]==0
    Ke=MB2[n:,:m-n].T
 
    return Ke
 
# This is the Nguyen-Stern attack, based on BKZ in the second step
def NSattack(n,m,p,b):
    M=orthoLattice(b,p)
 
    t=cputime()
    M2=M.LLL()
    MOrtho=M2[:m-n]

    t2=cputime()
    ke=kernelLLL(MOrtho)
    print('step 1 over')
    if n>170: return
 
    beta=2
    tbk=cputime()
    while beta<n:
        if beta==2:
            M5=ke.LLL()
        else:
            M5=M5.BKZ(block_size=beta)

        if len([True for v in M5 if allpmones(v)])==n: break
 
        if beta==2:
            beta=10
        else:
            beta+=10

    print('step 2 over')
    t2=cputime()
    MB=recoverBinary(M5)
    print('step 3 over')
    TMP = (Matrix(Zmod(p),MB).T)
    alpha = sorted(TMP.solve_right(b))
    return (alpha)


def p2l(pol):
    pol = str(list(pol)).encode()
    return pol

def recv2list(res):
    res = res.decode()
    print(res)
    res = res.replace('[','')
    res = res.replace(']','')
    res = res.split(',')
    res = list(map(int,res))
    return res

context(log_level = 'debug')
io = remote('8.222.191.182',int(11110))
start = time()
N = 128
io.recvuntil(b'q = ')
q = int(io.recvline())

io.sendlineafter(b'>',b'1')
PRq.<a> = PolynomialRing(Zmod(q))
Rq = PRq.quotient(a^N - 1, 'x')

Eve_e = [0 for i in range(N)]
Eve_e[0] = 1
Eve_e[1] = int(q // 8) + 1
Eve_pk = 2*Rq(Eve_e)

print(Eve_pk)
io.sendlineafter(b'>',p2l(Eve_pk))

io.recvuntil(b'answer:\n')
io.recvline()
alice_w = recv2list(io.recvline())

alice_s = alice_w[1:] + alice_w[:1]
io.sendlineafter(b'>',str(alice_s).encode())
#part1 end
h = []
io.sendlineafter(b'>',b'1')
h += eval(io.recvline())
io.sendlineafter(b'>',b'1')
h += eval(io.recvline())

#print(len(h))
#io.close()
h = vector(h)
#print(h)
alpha = NSattack(128,256,q,h)
alpha = Rq(alpha)
alpha_inv = 1/alpha

h_ = list(map(int,h))
h_ = Rq(h_[128:])

x = list(h_*alpha_inv)
print(x)

io.sendlineafter(b'>',b'2')
io.sendline( str(x).encode() )
end = time()
print(end-start)
io.interactive()
```

本着CTF是为了相互学习知识，拓展未知领域的精神，我缩短了交互时间，与之对应的有几种推荐工具——g6k，SageMath10.2。

SageMath10.2的LLL应该是内置了加速算法flatter还有一些优化之类的，这里放几组测试结果对比一下：

![img](https://hackforfun.feishu.cn/space/api/box/stream/download/asynccode/?code=MzdmMzFiNzdmODBkNmI4NDUwMzdiN2M1ZTZhYWJhNTlfVlV0TTNDWHJZemFuU2dxZGpvVkdFb3lRem8xTE1ldEFfVG9rZW46T0pwbmJIRTBFb0pMZGJ4RHZWN2NDTUJ3bnNnXzE3MDM0Mjc0Mzc6MTcwMzQzMTAzN19WNA)

左边是在Windows本地用SageMath9.2 notebook跑的三组LLL规约(CPU:i7-10870)，

右边是在阿里云的轻量应用服务器上用SageMath10.2跑的同一个脚本，

![img](https://hackforfun.feishu.cn/space/api/box/stream/download/asynccode/?code=ZTE1ZmI5Y2FhZDg3NDJiYmQ2YTMzYzEwMTE0ZjkxNjlfc0d6YTJUQXd5SmgwTzExZFFQb05JYVVGQmgyeGR0TWJfVG9rZW46Slk3eGJCbVRLb1BKamV4NlljNWM0OEk1bjZjXzE3MDM0Mjc0Mzc6MTcwMzQzMTAzN19WNA)

这组是应用Flatter算法跑的结果，算法链接：

[Flatter算法安装与应用文档](https://github.com/keeganryan/flatter)

可以看到SageMath10.2的加速效果还是很大的，那么就在服务器上跑这个Solution就可以

![img](https://hackforfun.feishu.cn/space/api/box/stream/download/asynccode/?code=YjY1MWQ0YjYyMDA4ZTNmZmY5M2QyNGFlMGQwYjNhMDZfYk9iclJXOUpSWjVWUWZMSktKMndQV2ZQQU5nbk9vcDVfVG9rZW46QkhQM2JvN2tRbzVvaWp4OUx0SmMwNENrblljXzE3MDM0Mjc0Mzc6MTcwMzQzMTAzN19WNA)

大概280秒这样，服务器交互时间是320秒，给的挺宽松了。

另外一个办法就是用g6k，感兴趣的师傅可以用自己构造的格去放到g6k里面跑，我没试过，但是理论上肯定是可行的。推荐安装链接：

[令人躁动不安的密码博客](https://tover.xyz/p/G6k-Sage-Install/)

### CodeInfinite

题目没有提供任何曲线参数，以及基点。但是注意到曲线的倍点运算过程中，不会对“点是否在曲线上”做校验。

应用grobear基去交互两次以上(实测两次就可以)拿到曲线，然后再利用故障注入(主要是曲线的b参数不同)，去注入不同的曲线上的点(要求阶比较小)，得到信息之后求DLP再CRT就完了。

```Python
#part1
PR.<a,b> = PolynomialRing(ZZ)
fs = []

Points = [(1504506045507279311346465773007772381512657984660547838789,4130578488225601501046056663631811064903654176857402074305),(5456905820281037859191198823390307260694730874414431398113,1453400382002547044807491448625262356474889271722046728491),(3369157190983746749932999294786837203985061363351766479528,5420818021877363417659329892069605959140325330921339586332),(1570225709466522856398929258259165219330193412683012975450,3674471623793502486481847125571931939478634329517055334651)]
for (x,y) in Points:
    f = x^3 + a*x + b - y^2
    fs.append(f)
    print(f)
I = Ideal(fs)
I.groebner_basis()
```

拿到曲线参数发现是NIST192的参数，可以去试着找找文献，这里提供一篇

论文地址：[参考文献](https://link.springer.com/chapter/10.1007/978-3-319-24174-6_21)

接下来打就完了:

```Python
# Finite field prime
p = 0xfffffffffffffffffffffffffffffffeffffffffffffffff
# Create a finite field of order p
FF = GF(p)
a = p - 3
# Curve parameters for the curve equation: y^2 = x^3 + a*x +b

# Define NIST 192-P
b192 = 0x64210519e59c80e70fa7e9ab72243049feb8deecc146b9b1
n192 = 0xffffffffffffffffffffffff99def836146bc9b1b4d22831
P192 = EllipticCurve([FF(a), FF(b192)])

# small parts have kgv of 197 bits
#   0 : 2^63 * 3 * 5 * 17 * 257 * 641 * 65537 * 274177    * 6700417 * 67280421310721
# 170 : 73 * 35897 * 145069 * 188563 * 296041             * 749323 * 6286019 * 62798669238999524504299
# print_curves()

# get flag pub key
r = remote('115.159.221.202',int(11112))

r.recvline()
r.recvline()
res = r.recvline().decode()
res = res.replace('The secret is ','')

r.recvuntil(b"Alice's public key is (")
x = int(r.recvuntil(b",", drop=True).decode())
y = int(r.recvuntil(b")", drop=True).decode())
A = P192(x, y)


enc = bytes.fromhex(res)

# Find private key
mods = []
vals = []

for b in [0, 170]:
    E = EllipticCurve([FF(a), FF(b)])
    G = E.gens()[0]
    factors = sage.rings.factorint.factor_trial_division(G.order(), 300000)
    G *= factors[-1][0]

    r.sendlineafter(b"Give me your pub key's x : \n", str(G.xy()[0]).encode())
    r.sendlineafter(b"Give me your pub key's y : \n", str(G.xy()[1]).encode())
    r.recvuntil(b"(")
    x = int(r.recvuntil(b",", drop=True).decode())
    y = int(r.recvuntil(b")", drop=True).decode())
    H = E(x, y)

    # get dlog
    tmp = G.order()
    mods.append(tmp)
    vals.append(G.discrete_log(H,tmp))

r.close()
pk = CRT_list(vals, mods)
print(pk, A)

key = long_to_bytes(pk)[:16]
Cipher = AES.new(key,AES.MODE_ECB)
flag = Cipher.decrypt(enc)

print(flag)
```

### Sign

密码签到题，就扣了一个解密函数，加密方案用的是NTRU，学会SageMath的基本那几句命令就能秒，实在不行用搜索引擎查一下NTRU格密码的加密方案是怎么操作的，手动写个解密函数也可以。

```Python
# Sage
from Crypto.Util.number import *


class NTRU:
    def __init__(self, N, p, q, d):
        self.debug = False

        assert q > (6*d+1)*p
        assert is_prime(N)
        assert gcd(N, q) == 1 and gcd(p, q) == 1
        self.N = N
        self.p = p
        self.q = q
        self.d = d
      
        self.R_  = PolynomialRing(ZZ,'x')
        self.Rp_ = PolynomialRing(Zmod(p),'xp')
        self.Rq_ = PolynomialRing(Zmod(q),'xq')
        x = self.R_.gen()
        xp = self.Rp_.gen()
        xq = self.Rq_.gen()
        self.R  = self.R_.quotient(x^N - 1, 'y')
        self.Rp = self.Rp_.quotient(xp^N - 1, 'yp')
        self.Rq = self.Rq_.quotient(xq^N - 1, 'yq')

        self.RpOrder = self.p^self.N - self.p
        self.RqOrder = self.q^self.N - self.q
        self.sk, self.pk = self.keyGen()

    def T(self, d1, d2):
        assert self.N >= d1+d2
        t = [1]*d1 + [-1]*d2 + [0]*(self.N-d1-d2)
        shuffle(t)
        return self.R(t)

    def lift(self, fx):
        mod = Integer(fx.base_ring()(-1)) + 1 
        return self.R([Integer(x)-mod if x > mod//2 else x for x in list(fx)])

    def keyGen(self):
        fx = self.T(self.d+1, self.d)
        gx = self.T(self.d, self.d)

        Fp = self.Rp(list(fx)) ^ (-1)                          
        assert pow(self.Rp(list(fx)), self.RpOrder-1) == Fp    
        assert self.Rp(list(fx)) * Fp == 1                
        
        Fq = pow(self.Rq(list(fx)), self.RqOrder - 1)    
        assert self.Rq(list(fx)) * Fq == 1              
        
        hx = Fq * self.Rq(list(gx))

        sk = (fx, gx, Fp, Fq, hx)
        pk = hx
        return sk, pk


    def setKey(self, fx, gx):
        try:
          fx = self.R(fx)
          gx = self.R(gx)

          Fp = self.Rp(list(fx)) ^ (-1)
          Fq = pow(self.Rq(list(fx)), self.RqOrder - 1)
          hx = Fq * self.Rq(list(gx))

          self.sk = (fx, gx, Fp, Fq, hx)
          self.pk = hx
          return True
        except:
          return False

    def getKey(self):
        ssk = (
              self.R_(list(self.sk[0])),   # fx
              self.R_(list(self.sk[1]))    # gx
            )
        spk = self.Rq_(list(self.pk))      # hx
        return ssk, spk
     
    def pad(self,msg):
        pad_length = self.N - len(msg)
        msg += [-1 for _ in range(pad_length)]
        return msg

    def unpad(self,msg):
        length = len(msg)
        for i in range(length):
            if msg[i] == -1:
                length = i
                break
        return msg[:length]

    def encode(self,msg):
        result = []
        for i in msg:
            result += [int(_) for _ in bin(i)[2:].zfill(8)]
        if len(result) < self.N:result = self.pad(result)
        result = self.R(result)
        return result
      
    def decode(self,msg):
        result = ''.join(list(map(str,self.unpad(msg))))
        result = int(result,2)

        return long_to_bytes(result)
        

    def encrypt(self, m):
        m = self.encode(m)
        assert self.pk != None
        hx = self.pk
        mx = self.R(m)
        mx = self.Rp(list(mx))             
        mx = self.Rq(list(mx)) 

        rx = self.T(self.d, self.d)
        rx = self.Rq(list(rx))
        e = self.p * rx * hx + mx
        return list(e)


    def decrypt(self, e):
        assert self.sk != None
        fx, gx, Fp, Fq, hx = self.sk

        e = self.Rq(e)
        ax = self.Rq(list(fx)) * e
        a = self.lift(ax)  
        bx = Fp * self.Rp(list(a))
        b = self.lift(bx)
        m = self.decode(b.list())
        
        return m

    
ntru = NTRU(N=509, p=3, q=512, d=3)
ntru.setKey(fx,gx)
m = ntru.decrypt(e)
print(m)
```