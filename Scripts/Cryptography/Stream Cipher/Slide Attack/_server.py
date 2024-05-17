from _task import task
import sys, socket, time

s = socket.socket(family=socket.AF_INET,type=socket.SOCK_STREAM)
ip = '127.0.0.1'
port = 6677
s.bind((ip, port))

s.listen()

while 1:
    c, addr = s.accept()
    f1 = c.makefile(mode='rw', encoding='utf-8', errors='ignore')
    sys.stdout = f1
    sys.stdin = f1
    task(b'astraflag{YAY!_:)}')
    c.close()
    f1.close()

s.close()