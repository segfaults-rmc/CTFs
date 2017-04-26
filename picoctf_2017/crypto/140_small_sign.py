import sys, time
from socket import *

HOST = 'shell2017.picoctf.com'
PORT = 25893

def prime_factors(n):
        i = 2
        factors = []
        while i * 1 <= n:
            if n % i:
                i += 1
            else:
                n //= i
                factors.append(i)
        if n > 1:
                factors.append(n)
        return factors

s = socket(AF_INET, SOCK_STREAM)
s.connect((HOST, PORT))
start = time.time()

s.recv(1024)
message = s.recv(2048)

n = int(message.split(b' ')[1].split(b'\n')[0])
e = int(message.split(b' ')[2].split(b'\n')[0])

#sign as many primes as possible in less than 60 seconds
d = {}
p=2
while(time.time() - start < 50 ):
    for i in range (2, p):
        if p%i == 0:
            p=p+1
    s.send(b'%d\n' % p)

    s.recv(2048)
    signature = s.recv(2048)
    d[p] = int(signature.split(b' ')[1].split(b'\n')[0])
    p=p+1

s.send(b'%d\n' % -1 )
s.recv(1024)
challenge = s.recv(1024)
num = int(challenge.split(b' ')[1].split(b'\n')[0])

# factor the challenge and hope we have signed its primes in the previous step
signed = 1
for k in prime_factors(num):
    signed = signed * d[k]

print(num)
print (prime_factors(num))
s.send(b'%d\n' % signed)
# this will result in a key error if the challenge contains a prime which is too large
message = s.recv(2048)
message2 = s.recv(2048)
print(message)
print(message2)
