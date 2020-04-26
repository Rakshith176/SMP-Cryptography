# packages required
import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

# Encryption Function
def encrypt_func(key, iv, message):
    message = padding(message)
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=backend)
    encryptor = cipher.encryptor()
    return encryptor.update(message.encode('ascii')) + encryptor.finalize()

# Decryption Function
def decrypt_func(key, iv, ct):
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=backend)
    decryptor = cipher.decryptor()
    message = decryptor.update(ct) + decryptor.finalize()
    message = depadding(message.decode('ascii'))
    return message

# Function for making the msg bits multiple of 32
def padding(message):
    message += " "*(32-len(message)%32)
    return message


# Removing the added spaces
def depadding(message):
    while message[-1] == ' ':
        message = message[:-1]
        if len(message) == 0:
            break
    return message


backend = default_backend()
key = os.urandom(32)
iv = os.urandom(16)
message = input("Enter the msg to be encrypted: ")
ciphertext = encrypt_func(key, iv, message)
print(f'Ciper Text : {ciphertext}')
decryptedmessage = decrypt_func(key, iv, ciphertext)
print(f'Decrypted Message : {decryptedmessage}')

