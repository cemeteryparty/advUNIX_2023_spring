#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import base64
import hashlib
import time
import re
from pwn import *

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

if __name__ == '__main__':
    #r = remote('localhost', 10330);
    r = remote('up23.zoolab.org', 10363)
    solve_pow(r)
    r.recvuntil(b' complete the')
    num_q = r.recvline().decode()
    num = int(re.findall('[0-9]+', num_q)[0])

    for i in range(num):
        r.recvuntil(b': ')
        q = r.recvuntil(b' = ?').decode().split(' = ')[0]
        ans = eval(q)
        solved = ans.to_bytes(length=(ans.bit_length() + 7) // 8, byteorder='little')
        r.sendline(base64.b64encode(solved))
    r.interactive()
    r.close()

# vim: set tabstop=4 expandtab shiftwidth=4 softtabstop=4 number cindent fileencoding=utf-8 :
