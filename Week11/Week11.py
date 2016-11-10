import os
import hmac
import itertools
from hashlib import sha256

#modified from http://docs.python.org/2/library/itertools.html#recipes
def grouper(n, iterable, fillvalue=None):
    "Collect data into fixed-length chunks or blocks"
    # grouper(3, 'ABCDEFG', 'x') --> ABC DEF Gxx
    args = [iter(iterable)] * n
    groups = itertools.izip_longest(fillvalue=fillvalue, *args)
    return (''.join(group) for group in groups)

# Randome hardcoded password
def random_word():
    return "<Uz$2*e8(`@QEz>q";


# This method is to generate a random AES key
def random_key(keylen):
    return ''.join(os.urandom(keylen))

nist_p = int(''.join("""
ffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024
e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd
3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec
6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f
24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361
c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552
bb9ed529077096966d670c354e4abc9804f1746c08ca237327fff
fffffffffffff""".strip().split()), 16)
nist_g = 2

# Make keys using urandom
def make_keys(p, g):
    x = int(os.urandom(4).encode('hex'), 16) % p
    return x, pow(g, x, p)

def srpImplementation():
    """36. Implement Secure Remote Password"""
    p, g = nist_p, nist_g

    # Client method takes P, g, k, Username, Password as inputs and calculate u, x, S, K and h as per the algorithm
    def client(N, g, k, I, P):
        a, A = make_keys(N, g)
        salt, B = (yield I, A)

        uH = sha256(str(A) + str(B)).hexdigest()
        u = int(uH, 16)

        xH = sha256(salt + P).hexdigest()
        x = int(xH, 16)
        S = pow(B - k * pow(g, x, N), a + u * x, N)
        K = sha256(str(S)).hexdigest()
        h = hmac.new(K, salt, sha256).hexdigest()
        ok = (yield h)
        print 'Login OK' if ok == 'OK' else 'Login Failed'
        yield None

    # This method prepares the credentials as per the document
    def make_credential(N, g, P):
        salt = random_key(16)
        xH = sha256(salt + P).hexdigest()
        x = int(xH, 16)
        v = pow(g, x, N)
        return salt, v

    # This method calculates h, u, S, K that are required for key exchange
    def server(N, g, k, credentials):
        I, A = (yield)
        salt, v = credentials[I]
        b, B = make_keys(N, g)
        B += k * v
        h = (yield salt, B)

        uH = sha256(str(A) + str(B)).hexdigest()
        u = int(uH, 16)
        S = pow(A * pow(v, u, N), b, N)
        K = sha256(str(S)).hexdigest()
        yield 'OK' if h == hmac.new(K, salt, sha256).hexdigest() else 'FAIL'


    email, password = 'hkommineni@unomaha.edu', random_word()
    credentials = {email: make_credential(p, g, password)}
    c, s = client(p, g, 3, email, password), server(p, g, 3, credentials)
    c_s, _ = c.next(), s.next()
    while c_s is not None:
        print '\tC->S:', c_s
        s_c = s.send(c_s)

        print '\tS->C:', s_c
        c_s = c.send(s_c)

# This method implements the Diffie-Hellman implementation.
def diffieHellman():
    """33. Implement Diffie-Hellman"""
    p, g = nist_p, nist_g
    print 'p:', p
    print 'g:', g
    print

    a, A = make_keys(p, g)
    b, B = make_keys(p, g)

    s1 = pow(B, a, p)
    s2 = pow(A, b, p)
    print 's1:', s1
    print 's2:', s2
    print 's1 == s2:', s1 == s2
    print

    s1key, s1mac = grouper(16, sha256('%02x' % s1).digest())
    print 'key:', s1key.encode('hex'), 'mac:', s1mac.encode('hex')


# Implementation of week11 exercise problems
if __name__ == '__main__':
    for f in (diffieHellman, srpImplementation):
        print f.__doc__.split('\n')[0]
        f()
        print