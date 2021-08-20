from z3 import *
from pwn import *
'''
s1 = 'inctf{U_Sur3_m4Te?}'
a1 = []

for i in range(22):
    a1.append(BitVec('a%d'%i, 16))

solve = Solver()
solve.add(ord(s1[0]) == (a1[0] ^ 2) - 31)
solve.add(ord(s1[1]) == ((a1[1] % 2) ^ a1[0]) - 29)
solve.add(ord(s1[2]) == (4 * a1[1]) ^ 0x97)
solve.add(ord(s1[3]) == a1[2] ^ 0xA0)
solve.add(ord(s1[4]) == (a1[3] ^ 0x4D) + 7)
solve.add(ord(s1[5]) == 4 * a1[5] - 1)
solve.add(ord(s1[3]) == a1[4] + 116)
solve.add(ord(s1[6]) == a1[6] + 21)
solve.add(ord(s1[7]) == a1[7] - 20)
solve.add(ord(s1[8]) == a1[8] ^ 0x63)
solve.add(ord(s1[9]) == (a1[10] ^ 3) - a1[8] + 54)
solve.add(ord(s1[10]) == a1[9] ^ 0x42)
solve.add(ord(s1[11]) == a1[11] + 51)
solve.add(ord(s1[11]) == a1[12] ^ 0xB3)
solve.add(ord(s1[12]) == (a1[13] + 18) ^ 0x1A)
solve.add(ord(s1[13]) == a1[14] - 7)
solve.add(ord(s1[14]) == a1[15] - 37)
solve.add(ord(s1[15]) == a1[17] ^ 0xE5)
solve.add(ord(s1[16]) == (a1[18] & 0x36) + 53)
solve.add(ord(s1[14]) == a1[19] ^ 0x34)
solve.add(ord(s1[17]) == a1[20] ^ 0xFD)
solve.add(ord(s1[18]) == (a1[20] >> a1[21]) ^ 0x1C)
if solve.check() == sat:
    m = solve.model()
    for i in range(22):
        print(m[a1[i]])
else:
    print("no answer")

'''

for x in range(256):
    p = process('./chall')
    token = ''
    print('X: '+hex(x))
    a1 = [138, 61, 212, 18, 0, 31, 64, 115, 48, 48, 108, 0, 128, 51, 116, 89, x, 177, 48, 0, 194, 1]

    b = []
    for i in range(30):
        b.append(BitVec('b%d' % i, 8))
    solve = Solver()
    for i in range(30):
        solve.add(b[i]>=32)
        solve.add(b[i]<127)
    solve.add(a1[0] == b[0] - 50 + b[1])
    solve.add(a1[1] == b[1] - 100 + b[2])
    solve.add(a1[2] == 4 * b[2])
    solve.add(a1[3] == b[3] ^ 0x46)
    solve.add(a1[4] == 36 - (b[3] - b[4]))
    solve.add(a1[6] == b[6] * b[5] + 99)
    solve.add(a1[7] == b[6] ^ b[7])
    solve.add(a1[8] == (b[7] + 45) ^ b[8])
    solve.add(a1[9] == (b[9] & 0x37) - 3)
    solve.add(a1[11] == b[11] - 38)
    solve.add(a1[12] == 4 * ((b[12] ^ b[6]) + 4))
    solve.add(a1[5] == (b[21] - b[4]) ^ 0x30)
    solve.add(a1[13] == b[13] - b[14] - 1)
    solve.add(a1[10] == b[17] - b[16] + 82)
    solve.add(a1[16] == 6 * (b[18] ^ b[19]) + 54)
    solve.add(a1[17] == b[21] + 49 + (b[20] ^ 0x73))
    solve.add(a1[14] == b[22])
    solve.add(a1[18] == b[23] ^ 0x42)
    solve.add(a1[15] == b[26] + 5)
    solve.add(a1[19] == b[25] - b[26] / 2 - 55)
    solve.add(a1[20] == 4 * b[27] - (b[28] + 128))
    solve.add(a1[21] == b[29] - 32)
    if solve.check() == sat:
        m = solve.model()
        for i in range(30):
            token+=chr(m[b[i]].as_long())  
        print('token: '+token)
        p.sendline(token)
        if b'reward from nc!' in p.recv():
            break
    else:
        print("no answer")
    sleep(0.1)

#Pl5T0C_,i3@&CxD@6P@fR_tr@aTln!
#inctf{PluT0_C0m3_&_g3t_y0uR_tr3aToz!}