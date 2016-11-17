from Crypto.Util.number import getStrongPrime

# Author: Harish Kommineni
# Date: November 2, 2016

#This method is to find the inverse of given two numbers using Extended Euclidean Algorithm
def invmod(a, b):
    m = b
    x, lastx = 0, 1
    y, lasty = 1, 0
    while b:
        q = a / b
        a, b = b, a % b
        x, lastx = lastx - q * x, x
        y, lasty = lasty - q * y, y
    return lastx % m


# This method is to implement the RSA Algorithm
def implementRSA():
    """Implement RSA"""
    def encrypt(m, e, n):
        m = long(m.encode('hex'), 16)
        return pow(m, e, n)

    def decrypt(c, d, n):
        m = pow(c, d, n)
        m = hex(long(m))
        return m[2:-1].decode('hex')


    bits = 1024
    e = 3
    p, q = getStrongPrime(bits, e), getStrongPrime(bits, e)
    print 'Value of p:', p
    print 'Value of q:', q
    print q
    n = p * q
    et = (p-1) * (q-1)
    d = invmod(e, et)

    m = "No Pain No Gain!"
    print 'Encrypting:', m
    c = encrypt(m, e, n)
    print 'c:', c
    m = decrypt(c, d, n)
    print 'Decrypted: ', m


def e3RsaAttack():
    """Implement an E=3 RSA Broadcast attack"""
    #http://stackoverflow.com/a/358134
    def nth_root(x,n):
        """Finds the integer component of the n'th root of x,
        an integer such that y ** n <= x < (y + 1) ** n.
        """
        high = 1
        while high ** n < x:
            high *= 2
        low = high/2
        while low < high:
            mid = (low + high) // 2
            if low < mid and mid**n < x:
                low = mid
            elif high > mid and mid**n > x:
                high = mid
            else:
                return mid
        return mid + 1


    m = "No Pain No Gain!"
    print 'Encrypting:', m
    m = long(m.encode('hex'), 16)
    bits = 1024
    e = 3

    pubkeys = [getStrongPrime(bits, e) * getStrongPrime(bits, e) for _ in xrange(3)]
    captures = [pow(m, e, n) for n in pubkeys]

    c0, c1, c2 = [c % n for c,n in zip(captures, pubkeys)]
    n0, n1, n2 = pubkeys
    ms0 = n1 * n2
    ms1 = n0 * n2
    ms2 = n0 * n1
    N012 = n0 * n1 * n2

    result = ((c0 * ms0 * invmod(ms0, n0)) +
            (c1 * ms1 * invmod(ms1, n1)) +
            (c2 * ms2 * invmod(ms2, n2))) % N012

    m = nth_root(result, 3)
    m = hex(long(m))
    m = m[2:-1].decode('hex')
    print 'Decrypted: ', m


# This is the main method to implement Week12 exercises.
if __name__ == '__main__':
    for f in (implementRSA, e3RsaAttack):
        print f.__doc__.split('\n')[0]
        f()
        print