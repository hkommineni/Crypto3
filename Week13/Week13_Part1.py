
import hashlib
import json
import time
import random
from Crypto.Util.number import bytes_to_long, long_to_bytes, getPrime, getStrongPrime, GCD

# Author: Harish Kommineni
# Date: November 20, 2016

# This method is to convert from bytes to long for encryption
def rsa_encrypt(m, e, n):
    return pow(bytes_to_long(m), e, n)

# This methos is to convert from long to bytes after descryption
def rsa_decrypt(c, d, n):
    return long_to_bytes(pow(c, d, n))

# This method returns the inverse for given values
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

# This method generates the random keys
def rsa_genkeys(bits, e):
    bits = bits / 2
    et = e
    while GCD(e, et) != 1:
        if bits < 512:
            #getStrongPrime won't accept bits < 512
            p, q = getPrime(bits), getPrime(bits)
        else:
            p, q = getStrongPrime(bits, e), getStrongPrime(bits, e)
        et = (p-1) * (q-1)

    n = p * q
    d = invmod(e, et)
    return (e,n), (d,n)


def unpaddedRSAAttack():
    """ Implementation of unpadded RSA attack"""
    seen = set()
    keypairs = {}
    def decrypt(pubkey, C):
        h = hashlib.sha1(long_to_bytes(C)).hexdigest()
        if h in seen or pubkey not in keypairs:
            return 'ERROR'
        seen.add(h)

        privkey = keypairs[pubkey]
        return rsa_decrypt(C, *privkey)


    pubkey, privkey = rsa_genkeys(bits=1024, e=3)
    keypairs[pubkey] = privkey

    msg = json.dumps({'time': int(time.time()), 'social': '078-05-1120'})
    print 'Encrypting:', msg
    C = rsa_encrypt(msg, *pubkey)
    print 'Decrypted: ', decrypt(pubkey, C)
    print 'Replayed:  ', decrypt(pubkey, C)

    E, N = pubkey
    S = random.randint(1, N)
    C_prime = (pow(S, E, N) * C) % N

    P_prime = decrypt(pubkey, C_prime)
    P_prime = bytes_to_long(P_prime)
    P = (P_prime * invmod(S, N)) % N
    print 'Recovered: ', long_to_bytes(P)


# This is the main method to implement Week13 part-1 exercises.
if __name__ == '__main__':
    unpaddedRSAAttack()
