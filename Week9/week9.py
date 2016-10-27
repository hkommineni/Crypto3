import struct
import itertools

from Crypto.Cipher import AES
# Author: Harish Kommineni
# Date: October 26, 2016

# This method takes the key, nonce and data as input and returns the decrypted text.
def xor_aes_ctr(key, nonce, text):
    def generate_keystream():
        aes_encryption = AES.new(key, mode=AES.MODE_ECB)
        for i in itertools.count():
            for c in aes_encryption.encrypt(struct.pack('<QQ', nonce, i)):
                yield c
    return ''.join(chr(ord(x) ^ ord(y)) for x,y in itertools.izip(text, generate_keystream()))

def counterMode():
    """To decrypt the encrypted CTR mode string."""
    key = 'NO PAIN NO GAIN!'
    text = 'njxWmONdxPe0H2qEdIj0ws8UWveJ8z+X25Slwgcjka9TkYYFRdbaR573lPpA3q9CQh+PVveM+EKsLbDBHg88ce1RposJ/el1HQpnj71t4F9j0N/SxXCgABqFnWPQr3Fr2swN3EDWj98k47TvqHrWpPigxS3AwJ7+wmlzoyLXwBYP25NyvB5Ep1mkydAPV9CjOvTHVZI23GXlmSxDzqr6GTub1VrI+/zzpGQgLrJpBPbcLYKD8K/e'.decode('base64')
    print xor_aes_ctr(key, 0, text)

# This is the main method for week 9 exercise.
if __name__ == '__main__':
    counterMode()
