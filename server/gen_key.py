from Crypto.Cipher import AES
import os

def key():
    key = os.urandom(32)
    salt = os.urandom(32)
    cipher = AES.new(key, AES.MODE_EAX, salt)
    return key, salt,cipher
# ciphertext = cipher.encrypt (b"Hello World!")
# print(ciphertext)
