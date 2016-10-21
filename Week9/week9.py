import struct
import itertools

from Crypto.Cipher import AES

def xor_aes_ctr(key, nonce, data):
    def gen_keystream():
        aes = AES.new(key, mode=AES.MODE_ECB)
        for i in itertools.count():
            for c in aes.encrypt(struct.pack('<QQ', nonce, i)):
                yield c
    return ''.join(chr(ord(x) ^ ord(y)) for x,y in itertools.izip(data, gen_keystream()))

def cc18():
    """
"""
    key = 'NO PAIN NO GAIN!'
    data = 'njxWmONdxPe0H2qEdIj0ws8UWveJ8z+X25Slwgcjka9TkYYFRdbaR573lPpA3q9CQh+PVveM+EKsLbDBHg88ce1RposJ/el1HQpnj71t4F9j0N/SxXCgABqFnWPQr3Fr2swN3EDWj98k47TvqHrWpPigxS3AwJ7+wmlzoyLXwBYP25NyvB5Ep1mkydAPV9CjOvTHVZI23GXlmSxDzqr6GTub1VrI+/zzpGQgLrJpBPbcLYKD8K/e'.decode('base64')
    print xor_aes_ctr(key, 0, data)

if __name__ == '__main__':
    cc18()
