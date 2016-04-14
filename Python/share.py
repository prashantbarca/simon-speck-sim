from argon2 import PasswordHasher
from speck import SpeckCipher
from simon import SimonCipher

import bcrypt
import scrypt
import time
import hashlib
from Crypto.Cipher import AES

password = b"shared secret"

def bcrypt_test():
    start = time.time()
    hashed = hashlib.sha256(bcrypt.hashpw(password,bcrypt.gensalt(16))).digest()
    end = time.time()
    obj =AES.new(hashed,AES.MODE_CBC, 'This is an IV456')
    ciphertext = obj.encrypt("The answer is no")
    print "bcrypt : ",(end-start)

def scrypt_test():
    start = time.time()
    hashed = hashlib.sha256(scrypt.hash(password,bcrypt.gensalt(16))).digest()
    obj =AES.new(hashed,AES.MODE_CBC, 'This is an IV456')
    end = time.time()
    ciphertext = obj.encrypt("The answer is no")
    print "scrypt : ",(end-start)

def argon2_test():
    start = time.time()
    ph = PasswordHasher()
    hash = ph.hash(password)
    hashed = hashlib.sha256(hash).digest()
    end = time.time()
    print "argon2 : ",(end-start)
    start = time.time()
    obj =AES.new(hashed,AES.MODE_CBC, 'This is an IV456')
    ciphertext = obj.encrypt("The answer is no")
    end = time.time()
    print "AES Encrypt: ",(end-start)*1000
    start = time.time()
    obj =AES.new(hashed,AES.MODE_CBC, 'This is an IV456')
    plaintext = obj.decrypt(ciphertext)
    end = time.time()
    print "AES Decrypt: ",(end-start)*1000
    my_plaintext = 0xCCCCAAAA55553333
    start = time.time()
    big_cipher = SimonCipher(0x111122223333444455556666777788889999AAAABBBBCCCCDDDDEEEEFFFF0000, key_size=256, block_size=128)
    simon = big_cipher.encrypt(my_plaintext)
    end = time.time()
    print "Simon Encrypt: ",(end-start)*1000
    start = time.time()
    big_cipher1 = SpeckCipher(0x111122223333444455556666777788889999AAAABBBBCCCCDDDDEEEEFFFF0000, key_size=256, block_size=128)
    speck = big_cipher1.encrypt(my_plaintext)
    end = time.time()
    print "Speck Encrypt: ",(end-start)*1000
    start = time.time()
    big_cipher = SimonCipher(0x111122223333444455556666777788889999AAAABBBBCCCCDDDDEEEEFFFF0000, key_size=256, block_size=128)
    plain = big_cipher.decrypt(simon)
    end = time.time()
    print plain
    print "Simon Decrypt: ",(end-start)*1000
    start = time.time()
    big_cipher1 = SpeckCipher(0x111122223333444455556666777788889999AAAABBBBCCCCDDDDEEEEFFFF0000, key_size=256, block_size=128)
    plain = big_cipher1.decrypt(speck)
    end = time.time()
    print plain
    print "Speck Decrypt: ",(end-start)*1000

bcrypt_test()
scrypt_test()
argon2_test()
