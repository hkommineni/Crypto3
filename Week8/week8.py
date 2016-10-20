import os
import itertools
import random

# Author: Harish Kommineni
# Date: October 20, 2016
from Crypto.Cipher import AES

# This method XOR's the given two blocks
def exclusiveOR(b1, b2):
    return ''.join(chr(ord(x) ^ ord(y)) for x,y in zip(b1, b2))

def pairwise(iterable):
    "s -> (s0,s1), (s1,s2), (s2, s3), ..."
    a, b = itertools.tee(iterable)
    next(b, None)
    return itertools.izip(a, b)

# This method is to generate a random AES key
def random_key(keylen):
    return ''.join(os.urandom(keylen))

#http://docs.python.org/2/library/itertools.html#recipes
def grouper(n, iterable, fillvalue=None):
    "Collect data into fixed-length chunks or blocks"
    # grouper(3, 'ABCDEFG', 'x') --> ABC DEF Gxx
    args = [iter(iterable)] * n
    return itertools.izip_longest(fillvalue=fillvalue, *args)

# This method strips of=f the padding if the padding is valid and throws an exception if the padding is invalid.
class PadException(Exception):
    pass

def pkcs7_strip(data):
    padchar = data[-1]
    padlen = ord(padchar)
    if padlen == 0 or not data.endswith(padchar * padlen):
        raise PadException
    return data[:-padlen]

# This method is to return data with pad length
def pkcs7_pad(blocklength, text):
    padlen = blocklength - len(text) % blocklength
    return text + chr(padlen) * padlen

def cbcPaddingOracleAttack():
    """
    Write a function that randomly selects one of the strings given in file w8.txt and encrypts it
under an unknown AES key under CBC mode. Save the AES key and the IV used.
Write another function that processes this ciphertext produced: takes the ciphertext, decrypts
it, checks its padding and returns a True/False depending on whether the padding is valid or not.
"""
    strings = """
MDAwMDAwTm93IHRoYXQgdGhlIHBhcnR5IGlzIGp1bXBpbmc=
MDAwMDAxV2l0aCB0aGUgYmFzcyBraWNrZWQgaW4gYW5kIHRoZSBWZWdhJ3MgYXJlIHB1bXBpbic=
MDAwMDAyUXVpY2sgdG8gdGhlIHBvaW50LCB0byB0aGUgcG9pbnQsIG5vIGZha2luZw==
MDAwMDAzQ29va2luZyBNQydzIGxpa2UgYSBwb3VuZCBvZiBiYWNvbg==
MDAwMDA0QnVybmluZyAnZW0sIGlmIHlvdSBhaW4ndCBxdWljayBhbmQgbmltYmxl
MDAwMDA1SSBnbyBjcmF6eSB3aGVuIEkgaGVhciBhIGN5bWJhbA==
MDAwMDA2QW5kIGEgaGlnaCBoYXQgd2l0aCBhIHNvdXBlZCB1cCB0ZW1wbw==
MDAwMDA3SSdtIG9uIGEgcm9sbCwgaXQncyB0aW1lIHRvIGdvIHNvbG8=
MDAwMDA4b2xsaW4nIGluIG15IGZpdmUgcG9pbnQgb2g=
MDAwMDA5aXRoIG15IHJhZy10b3AgZG93biBzbyBteSBoYWlyIGNhbiBibG93
""".strip().split()

    # This method encrypts the data with random key
    def encrypt(key, data):
        iv = random_key(16)
        return iv, AES.new(key, IV=iv, mode=AES.MODE_CBC).encrypt(pkcs7_pad(16, data))

    # This method checks if the padding is valid, like x01;x02x02;x03x03x03 and so on..
    def check_padding(key, iv, data):
        plain = AES.new(key, IV=iv, mode=AES.MODE_CBC).decrypt(data)
        try:
            pkcs7_strip(plain)
            return True
        except PadException:
            return False

    # This method decrypts based on the given padded data and blocklength.
    def decrypt(blocklen, fcheck, data):
        def decrypt_byte(block, known):
            known_length = len(known) + 1
            print 97 ^ known_length
            suffix = ''.join(chr(ord(x) ^ known_length) for x in known)
            attack = random_key(blocklen - known_length)
            for i in xrange(256):
                if fcheck(attack + chr(i) + suffix, block): # Here is the area where I couldn't fix.
                    return chr(known_length ^ i)

        plain = ''
        blocks = list(''.join(b) for b in grouper(blocklen, data))
        for prev, cur in pairwise(blocks):
            known = ''
            while len(known) < blocklen:
                known = decrypt_byte(cur, known) + known
            plain += exclusiveOR(prev, known)
        return pkcs7_strip(plain)

    key = random_key(16)
    data = random.choice(strings).decode('base64')
    iv, ciphertext = encrypt(key, data)
    fcheck = check_padding(key, iv, ciphertext)
    plain = decrypt(16, fcheck, iv + ciphertext)
    print plain
    print 'Match' if data == plain else 'No Match'

# This is the main method executes week exercise of CBC padding Oracle attack.
if __name__ == '__main__':
    cbcPaddingOracleAttack()