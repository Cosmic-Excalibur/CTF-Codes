from Cipher_1KSAf import *
from colorify import *
import os

banner = """
.____           __ /\          _________.__  .__    .___    ._.
|    |    _____/  |)/ ______  /   _____/|  | |__| __| _/____| |
|    |  _/ __ \   __\/  ___/  \_____  \ |  | |  |/ __ |/ __ \ |
|    |__\  ___/|  |  \___ \   /        \|  |_|  / /_/ \  ___/\|
|_______ \___  >__| /____  > /_______  /|____/__\____ |\___  >_
        \/   \/          \/          \/              \/    \/\/
"""

info = """
@author   Astrageldon
@version  0.1
@desc     This is a stupid stream cipher toy implementation
          (here I chose 1-KSAf for simplicity),
          and the exploiters are required to manipulate
          a special trick called the slide attack
          (https://iacr.org/archive/eurocrypt2020/12105368/12105368.pdf)
          to recover the key and get the flag 🚩
          enjoy it :)


"""

banner = colorify(banner)
info = colorify(info)

def task(flag):
    print(banner)
    print(info)
    
    n = 4
    key = os.urandom(n)
    iv = os.urandom(n)
    print("Something you will need:")
    print("key = " + colorify("WHAT IS IT? :)", red, yellow))
    print("iv  = " + iv.hex())
    print()
    
    cipher = Cipher_1KSAf(key, iv=iv)
    enc = cipher.encrypt(flag)
    print("And your encrypted Flag 🚩:")
    print('enc = ' + enc.hex())
    print()
    
    try:
        while True:
            print("Your plaintext (in hex):")
            pt = bytes.fromhex(input(">>> "))
            print()
            ct = cipher.encrypt(pt)
            print("Your plaintext/ciphertext pair:")
            print("pt  = " + pt.hex())
            print("ct  = " + ct.hex())
            print()
    except:
        pass
    print()
    print(colorify("Bye~~~ :)"))
    print()