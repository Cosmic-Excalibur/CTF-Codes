from MI import *
import os

if '__main__' == __name__:
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