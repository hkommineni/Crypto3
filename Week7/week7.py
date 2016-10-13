import os


# Author: Harish Kommineni
# Date: October 12, 2016

from Crypto.Cipher import AES

# This method is to generate a random AES key
def random_key(keylen):
    return ''.join(os.urandom(keylen))

# This method is to return data with pad length
def pkcs7_pad(blocklength, text):
    padlen = blocklength - len(text) % blocklength
    return text + chr(padlen) * padlen

# This method strips off the padding if the padding is valid and throws an exception if the padding is invalid.
class PadException(Exception):
    pass

def pkcs7_strip(data):
    padchar = data[-1]
    padlen = ord(padchar)
    if padlen == 0 or not data.endswith(padchar * padlen):
        raise PadException
    return data[:-padlen]

def sanitizerChecker():
    """
    Function 1: Sanitizer
        This function should take and arbitrary input string, prepend the string:
            'comment1=raining%20MCs;userdata='
        And appends the string:
            ';comment2=%20like%20a%20sunny%20day%20tomorrow'
        The function should quote out the ';' and '='characters.
        The function should encrypt the entire string using the random AES key.

    Function 2: Checker
        This function should first decrypt the string and then look for the characters
            ';admin=true;'.
        Return true or false based on whether the string exists.
"""

    key = random_key(16)
    iv = random_key(16)

    def sanitizer(key, iv, data):
        prefix = "comment1=raining%20MCs;userdata="
        suffix = ";comment2=%20like%20a%20sunny%20day%20tomorrow"
        for c in ';=':
            data = data.replace(c, '%%%X' % ord(c))
        data = pkcs7_pad(16, prefix + data + suffix)
        return AES.new(key, mode=AES.MODE_CBC, IV=iv).encrypt(data)

    def checker(key, iv, data):
        return pkcs7_strip(AES.new(key, mode=AES.MODE_CBC, IV=iv).decrypt(data))

    data = 'XXXXXXXXXXXXXXXX?admin?true'
    print 'Input:', data
    ciphertext = sanitizer(key, iv, data)

    ciphertext = list(ciphertext)
    ciphertext[32] = chr(ord(ciphertext[32]) ^ (ord('?') ^ ord(';')))
    ciphertext[38] = chr(ord(ciphertext[38]) ^ (ord('?') ^ ord('=')))
    ciphertext = ''.join(ciphertext)

    plain = checker(key, iv, ciphertext)
    print 'Output:', plain
    print "Found ';admin=true;':", ';admin=true;' in plain

# This is the main method executes week 7 exercises.
if __name__ == '__main__':
    sanitizerChecker()