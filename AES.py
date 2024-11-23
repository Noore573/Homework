from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend
import os

# Padding function (PKCS7)
def pad_message(message):
    padder = padding.PKCS7(128).padder()
    padded_message = padder.update(message) + padder.finalize()
    return padded_message

# Unpadding function
def unpad_message(padded_message):
    unpadder = padding.PKCS7(128).unpadder()
    message = unpadder.update(padded_message) + unpadder.finalize()
    return message

# AES encryption
def AES_encrypt_message(key, iv, message):
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    padded_message = pad_message(message)
    encrypted_message = encryptor.update(padded_message) + encryptor.finalize()
    return encrypted_message

# AES decryption
def AES_decrypt_message(key, iv, encrypted_message):
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    decrypted_padded_message = decryptor.update(encrypted_message) + decryptor.finalize()
    message = unpad_message(decrypted_padded_message)
    return message
