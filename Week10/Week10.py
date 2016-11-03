import os
import struct
import random
import itertools

# Author: Harish Kommineni
# Date: November 2, 2016
from Crypto.Cipher import AES

#http://docs.python.org/2/library/itertools.html#recipes
def grouper(n, iterable, fillvalue=None):
    "Collect data into fixed-length chunks or blocks"
    # grouper(3, 'ABCDEFG', 'x') --> ABC DEF Gxx
    args = [iter(iterable)] * n
    return itertools.izip_longest(fillvalue=fillvalue, *args)

# This method is to return data with pad length
def pkcs7_pad(blocklength, text):
    padlen = blocklength - len(text) % blocklength
    return text + chr(padlen) * padlen

# This method XOR's the given two blocks
def exclusiveOR(b1, b2):
    return ''.join(chr(ord(x) ^ ord(y)) for x,y in zip(b1, b2))

# This method strips of=f the padding if the padding is valid and throws an exception if the padding is invalid.
class PadException(Exception):
    pass

def pkcs7_strip(data):
    padchar = data[-1]
    padlen = ord(padchar)
    if padlen == 0 or not data.endswith(padchar * padlen):
        raise PadException
    return data[:-padlen]



# This method is to generate a random AES key
def random_key(keylen):
    return ''.join(os.urandom(keylen))

def recoverKeyFromCBC():
    """ This method recovers the key from CBC with key = IV
"""
    def encrypt(key, iv, data):
        prefix = "comment1=raining%20MCs;userdata="
        suffix = ";comment2=%20like%20a%20sunny%20day%20tomorrow"
        for c in ';=':
            data = data.replace(c, '%%%X' % ord(c))
        data = pkcs7_pad(16, prefix + data + suffix)
        return AES.new(key, mode=AES.MODE_CBC, IV=iv).encrypt(data)

    def decrypt(key, iv, data):
        plain = pkcs7_strip(AES.new(key, mode=AES.MODE_CBC, IV=iv).decrypt(data))
        if all(ord(c) < 128 for c in plain):
            return True, plain
        return False, plain

    key = iv = random_key(16)
    print "Key %s == IV %s" % (key.encode('hex'), iv.encode('hex'))

    ciphertext = encrypt(key, iv, 'Cry')
    attacktext = ''.join((ciphertext[:16], '\x00' * 16, ciphertext[:16], ciphertext[48:]))
    ok, plain = decrypt(key, iv, attacktext)
    keyiv = exclusiveOR(plain[:16], plain[32:48])
    print "Recovered Key/IV: %s" % keyiv.encode('hex')



#https://github.com/ajalt/python-sha1
def sha1(message, h0=0x67452301, h1=0xEFCDAB89, h2=0x98BADCFE, h3=0x10325476, h4=0xC3D2E1F0, offset=0):
    """SHA-1 Hashing Function
    A custom SHA-1 hashing function implemented entirely in Python.
    Arguments:
        message: The input message string to hash.
        h0 ... h4: initial variables
    Returns:
        A hex SHA-1 digest of the input message.
    """

    def _left_rotate(n, b):
        return ((n << b) | (n >> (32 - b))) & 0xffffffff

    # Pre-processing:
    original_byte_len = len(message)
    original_bit_len = original_byte_len * 8
    # append the bit '1' to the message
    message += '\x80'

    # append 0 <= k < 512 bits '0', so that the resulting message length (in bits)
    #    is congruent to 448 (mod 512)
    message += '\x00' * ((56 - (original_byte_len + 1) % 64) % 64)

    # append length of message (before pre-processing), in bits, as 64-bit big-endian integer
    message += struct.pack('>Q', original_bit_len + (offset * 8))

    # Process the message in successive 512-bit chunks:
    # break message into 512-bit chunks
    for i in xrange(0, len(message), 64):
        w = [0] * 80
        # break chunk into sixteen 32-bit big-endian words w[i]
        for j in xrange(16):
            w[j] = struct.unpack('>I', message[i + j*4:i + j*4 + 4])[0]
        # Extend the sixteen 32-bit words into eighty 32-bit words:
        for j in xrange(16, 80):
            w[j] = _left_rotate(w[j-3] ^ w[j-8] ^ w[j-14] ^ w[j-16], 1)

        # Initialize hash value for this chunk:
        a = h0
        b = h1
        c = h2
        d = h3
        e = h4

        for i in xrange(80):
            if 0 <= i <= 19:
                # Use alternative 1 for f from FIPS PB 180-1 to avoid ~
                f = d ^ (b & (c ^ d))
                k = 0x5A827999
            elif 20 <= i <= 39:
                f = b ^ c ^ d
                k = 0x6ED9EBA1
            elif 40 <= i <= 59:
                f = (b & c) | (b & d) | (c & d)
                k = 0x8F1BBCDC
            elif 60 <= i <= 79:
                f = b ^ c ^ d
                k = 0xCA62C1D6

            a, b, c, d, e = ((_left_rotate(a, 5) + f + e + k + w[i]) & 0xffffffff,
                            a, _left_rotate(b, 30), c, d)

        # sAdd this chunk's hash to result so far:
        h0 = (h0 + a) & 0xffffffff
        h1 = (h1 + b) & 0xffffffff
        h2 = (h2 + c) & 0xffffffff
        h3 = (h3 + d) & 0xffffffff
        h4 = (h4 + e) & 0xffffffff

    # Produce the final hash value (big-endian):
    return '%08x%08x%08x%08x%08x' % (h0, h1, h2, h3, h4)


def authenticate(key, mac, message):
    return sha1(key + message) == mac

def Sha1KeyedMac():
    """This method implements the SHA-1 keyed MAC
"""
    tests = [
        ('Original:', 'NO PAIN NO GAIN!', "OMG!!, these Programming Assignments are too difficult to understand"),
        ('Bad Key: ', 'NO PAIN NO GAIN', "OMG!!, these Programming Assignments are too difficult to understand")]

    comment, key, msg = tests[0]
    mac = sha1(key + msg)
    for comment, key, msg in tests:
        print '%s %s %s\t%s' % (comment, key, msg, authenticate(key, mac, msg))


def breakSha1():
    """Break a SHA-1 keyed MAC using length extension
"""
    def sha1_pad(message):
        # Pre-processing:
        original_byte_len = len(message)
        original_bit_len = original_byte_len * 8
        # append the bit '1' to the message
        pad = '\x80'

        # append 0 <= k < 512 bits '0', so that the resulting message length (in bits)
        #    is congruent to 448 (mod 512)
        pad += '\x00' * ((56 - (original_byte_len + 1) % 64) % 64)

        # append length of message (before pre-processing), in bits, as 64-bit big-endian integer
        pad += struct.pack('>Q', original_bit_len)
        return pad

    key = random_key(16)
    message = "comment1=Crypto%20Gurus;userdata=foo;comment2=%20hereAt%20UNO%20Omaha%20NE%20USA"
    mac = sha1(key + message)
    print 'Message:', message
    print 'MAC:', mac
    print 'Authenticated:', authenticate(key, mac, message)
    print

    registers = [int(''.join(h), 16) for h in grouper(8, mac)]
    suffix = ';admin=true'

    for keylen in xrange(0, 256):
        pad = sha1_pad(('A' * keylen) + message)
        offset = keylen + len(message + pad)
        attack_mac = sha1(suffix, *registers, offset=offset)
        attack_msg = message + pad + suffix
        if authenticate(key, attack_mac, attack_msg):
            print 'Message:', attack_msg
            print 'MAC:', attack_mac
            print 'Authenticated:', authenticate(key, attack_mac, attack_msg)
            break

# This is the main method for week 10 exercise.
if __name__ == '__main__':
    for f in (recoverKeyFromCBC, Sha1KeyedMac, breakSha1):
        print f.__doc__.split('\n')[0]
        f()
        print