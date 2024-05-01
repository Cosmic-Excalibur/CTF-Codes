from MI import *
from MI_attacks import *
import os

def test1():
    msg = b'astraflag{W0nderfu1_!_7h1S_1s_ur_fLaG_:p}'
    cipher = Cipher()
    pk, sk = cipher.keygen()
    encrypter = Encrypt(pk)
    decrypter = Decrypt(sk)
    enc = encrypter.encrypt(msg)
    print(enc)
    dec = decrypter.decrypt(enc)
    print(dec)
    input("Breakpoint...")
    
    msg = b'astraflag{7h1S_1s_ur_flAg_encRyyyyyppttteeD_w1th_IV_:)}'
    iv = os.urandom(DEFAULT_N)
    cipher = Cipher()
    pk, sk = cipher.keygen()
    encrypter = Encrypt(pk, iv)
    decrypter = Decrypt(sk, iv)
    enc = encrypter.encrypt(msg)
    print(enc)
    dec = decrypter.decrypt(enc)
    print(dec)
    input("Breakpoint...")

def test2():
    msg = b'astraflag{n0_secr3t_k3Ys_7h1s_tiM3_!}'
    cipher = Cipher()
    pk, sk = cipher.keygen()
    encrypter = Encrypt(pk)
    enc = encrypter.encrypt(msg)
    attacker = CPA_Attack(pk)
    dec = b''
    for i in range(0, len(enc), DEFAULT_N):
        tmp = next(x for x in attacker.attack(enc[i:i+DEFAULT_N]) if len(set(y for y in x if y not in range(32, 127))) <= 1)
        print(tmp)
        dec += tmp
    dec = unpad(dec, DEFAULT_N)
    print(dec)
    input("Breakpoint...")

if '__main__' == __name__:
    #test1()
    test2()