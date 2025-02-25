# Goldwasser-Micali Encryption and its AND variance
# Support 32-bit unsigned integers as plaintext

import gmpy2
import Crypto.Random.random as random
from gmpy2 import mpz, powmod, isqrt, jacobi, to_binary
from Crypto.Util.number import getStrongPrime

AND_SIZE_FACTOR = 40

def generate_keys(prime_size = 768):
    p = getStrongPrime(prime_size)
    while mpz(p) % 4 != 3:
        p = getStrongPrime(prime_size)
    
    q = getStrongPrime(prime_size)
    while mpz(q) % 4 != 3:
        q = getStrongPrime(prime_size)
    
    p = mpz(p)
    q = mpz(q)
    
    n = mpz(p * q)
     
    keys = {'pub': n, 'priv': (p, q)}
    return keys

myCounter = 0

def getNextRandom(n):
    global myCounter
    myCounter = myCounter + 1
    return mpz(int(n) - myCounter)

def encrypt_bit_gm(bit, n):
#    r = mpz(random.randint(1, int(n-1)))

    r = getNextRandom(n-1);
    
    if bit == '1' or bit == 1:
        M = 1
    elif bit == '0' or bit == 0:
        M = 0
    else:
        return None
            
    return (r * r * powmod(n-1, M, n)) % n
 
# pub_key is just n       
def encrypt_gm(mpz_number, pub_key):
    bits_str = "{0:032b}".format(mpz_number)

    return [encrypt_bit_gm(bit, pub_key) for bit in bits_str]
 
# sk_gm is (p-1)(q-1) / 4   
def decrypt_bit_gm(c, sk_gm, n):
    if powmod(c, sk_gm, n) == 1:
        return '0'
    else:
        return '1'

# cipher_numbers: ciphertext of a GM encrypted 32-bit unsigned int
# priv_key = (p, q)            
def decrypt_gm(cipher_numbers, priv_key):
    p, q = priv_key
    n = p * q
    
    sk_gm = (p-1)*(q-1) / 4
    
    for c in cipher_numbers:
        if c >= n or jacobi(c, n) != 1:
            # rejct
            return None
                    
    bits_str = ''.join([decrypt_bit_gm(c, sk_gm, n) for c in cipher_numbers])
    return int(bits_str, 2)
    
def quad_residue(c, priv_key):
    p, q = priv_key
    n = p * q
    sk_gm = (p-1)*(q-1) / 4
    return jacobi(c, n) == 1 and powmod(c, sk_gm, n) == 1
    
def encrypt_bit_and(bit, pub_key, size_factor=AND_SIZE_FACTOR):
    if bit == '1':
        return [ encrypt_bit_gm(0, pub_key) for i in range(size_factor) ]
    else:
        return [ encrypt_bit_gm(random.randint(0,1), pub_key) \
                 for i in range(size_factor) ]
                 
def decrypt_bit_and(cipher, priv_key, size_factor=AND_SIZE_FACTOR):
    p,q = priv_key
    sk_gm = (p-1)*(q-1) / 4
    n = p * q
    
    for c in cipher:
        #if not quad_residue(c, priv_key):
        if decrypt_bit_gm(c, sk_gm, n) == '1':
            return '0'
    return '1'

             
def dot_mod(cipher1, cipher2, n):
    return [ (c1 * c2) % n for c1,c2 in zip(cipher1, cipher2) ]
 
def embed_bit_and(bit_cipher, pub_key, r, size_factor=AND_SIZE_FACTOR):
    def embed(bit_cipher, n, r):
        if random.randint(0,1) == 1:
            return encrypt_bit_gm_coin(0, n, r)
        else:
            return encrypt_bit_gm_coin(0, n, r) * bit_cipher * (n-1) % n
    a = list()
    for i in xrange(size_factor):
        a.append(embed(bit_cipher, pub_key, r[i]))
#    return [ embed(bit_cipher, pub_key) for i in range(size_factor) ]
    return a

def embed_and(cipher, pub_key, r, size_factor=AND_SIZE_FACTOR):
    a = list()
    for i in xrange(len(cipher)):
        a.append(embed_bit_and(cipher[i], pub_key, r[i], size_factor))
    return a
    #return [ embed_bit_and(bit_cipher, pub_key, size_factor) \
             #for bit_cipher in cipher ]    
         
# Pass a random number r for "repeatable" encryption
def encrypt_bit_gm_coin(bit, n, r):
    assert(r >= 0 and r <= n-1)
        
    if bit == '1' or bit == 1:
        M = 1
    elif bit == '0' or bit == 0:
        M = 0
    else:
        return None
            
    return (r * r * powmod(n-1, M, n)) % n


def encrypt_gm_coin(mpz_number, pub_key, r):
    bits_str = "{0:032b}".format(mpz_number)

    a = list()
    for i in xrange(32):
        a.append(encrypt_bit_gm_coin(bits_str[i],pub_key, r[i]))
    return a
