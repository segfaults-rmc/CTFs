from math import gcd
import random

e = 65537
n = 322814151822712090417072986222040863976116810564688225857612669613873525544411916192190873170659640245132624332148528862557298858047718123680584189321603561572531085350943820096602427469072548352484298259311246970844280748826511224806763370175398713221869278200049987373235557037109327912470754581096543208171
dp = 1645290358212409422232746895795831441626283889531554181610891065406049074561186629194625112109008921901603982854724720356054695566958493400403652147655273

c = 221694945369260878729367790446190608376816159787337255497612821696086933773832626353950534688450477800836115181814125410615514257361695600423563942990338966224347660337810820828785086890647125610160687197625953592532396882816465380392068955862495831688432918749571416093244018492296109515310016706336588414261

# The challenge hint says Fermat's Little Theorem may be helpful
# Fermat's Little Theorem states that if p is prime, then for any integer a,
# the number a^p -a is a multiple of p.

# dp is used in the Chinese Remainder Theorem, an optimization technique
# to RSA with dp = d mod(p - 1).  Importantly, e and dp are inverses of
# each other modulo p - 1.

# The above means that for an arbitrary number i:
# i^(e * dp) - i mod n will have p as a factor.
# The means that calculating gcd(n, i^(e*dp) - i mod n) for a random i
# will recover p.  Once p is obtained, n can be factored and the message
# can be decrypted from there.


# from https://jhafranco.com/2012/01/29/rsa-implementation-in-python/
def inv(p, q):
    """Multiplicative inverse"""
    def xgcd(x, y):
        """Extended Euclidean Algorithm"""
        s1, s0 = 0, 1
        t1, t0 = 1, 0
        while y:
            q = x // y
            x, y = y, x % y
            s1, s0 = s0 - q * s1, s1
            t1, t0 = t0 - q * t1, t1
        return x, s0, t0

    s, t = xgcd(p, q)[0:2]
    assert s == 1
    if t < 0:
        t += q
    return t

def modSize(mod):
    modSize = len("{:2x}".format(mod)) // 2
    return modSize

def int2Text(number, size):
    text = "".join([chr((number >> j) & 0xff)
                    for j in reversed(range(0, size << 3, 8))])
    return text.lstrip("\x00")


i = random.randint(0,pow(2,16))
result = pow(i,e*dp, n) - i
p = gcd(n, result)

q = n // p
phi = (p - 1) * (q - 1)

d = inv(e, phi)

# With the private exponent, use CRT to decrypt the message
m1 = pow(c, dp , p)
m2 = pow(c, d % (q - 1), q)
h = (inv(q, p) * (m1 - m2)) % p
m = m2 + h * q

print(int2Text(m, modSize(n)))
