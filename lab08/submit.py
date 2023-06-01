#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from pwn import *
import hashlib
import base64
import sys

def solve_pow(r):
    prefix = r.recvline().decode().split("'")[1]
    print(time.time(), "solving pow ...")
    solved = b''
    for i in range(1000000000):
        h = hashlib.sha1((prefix + str(i)).encode()).hexdigest()
        if h[:6] == '000000':
            solved = str(i).encode()
            print("solved =", solved)
            break;
    print(time.time(), "done.")

    r.sendlineafter(b'string S: ', base64.b64encode(solved))

if len(sys.argv) < 2:
    print("usage: {} solver/runner".format(sys.argv[0]))
    sys.exit(-1)

#r = remote('localhost', 10965)
r = remote('up23.zoolab.org', 10965)

#context.log_level = 0

def upload(fn):
    r.recvuntil(b'finish the transmission.\n\n')
    with open(fn, 'rb') as f:
        z = f.read()
    print("\x1b[1;32m** local md5({}): {}\x1b[m".format(fn, hashlib.md5(z).hexdigest()))
    z = base64.b64encode(z)
    for i in range(0, len(z), 768):
        r.sendline(z[i: i+768])
    r.sendline(b'EOF')
    while True:
        z = r.recvline()
        if b'md5' in z:
            print(z.decode().strip())
            break
solve_pow(r)
upload(sys.argv[1])
r.interactive()
r.close()

# vim: set tabstop=4 expandtab shiftwidth=4 softtabstop=4 number cindent fileencoding=utf-8 :
