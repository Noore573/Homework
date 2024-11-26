
import socket
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.backends import default_backend
import os
from colorama import *

PASSWORD = "issproject"  
SALT = b'fixed_salt_value_16'  

kdf = PBKDF2HMAC(
    algorithm=hashes.SHA256(),
    length=32,
    salt=SALT,
    iterations=100000,
    backend=default_backend()
)
symmetric_key = kdf.derive(PASSWORD.encode())

client_private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048,
    backend=default_backend()
)

def symmetric_encrypt_message(message, key):
    iv = os.urandom(16)  
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    encrypted_message = encryptor.update(message.encode('utf-8')) + encryptor.finalize()
    return iv + encrypted_message

def symmetric_decrypt_message(encrypted_message, key):
    if len(encrypted_message) < 16:
        raise ValueError("Invalid encrypted message received.")
    iv = encrypted_message[:16]
    encrypted_data = encrypted_message[16:]
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    decrypted_message = decryptor.update(encrypted_data) + decryptor.finalize()
    return decrypted_message.decode('utf-8', errors='replace')

def asymmetric_encrypt_message(message, public_key):
    encrypted_message = public_key.encrypt(
        message.encode('utf-8'),
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return encrypted_message

def asymmetric_decrypt_message(encrypted_message, private_key):
    decrypted_message = private_key.decrypt(
        encrypted_message,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return decrypted_message.decode('utf-8', errors='replace')

def start_client():
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    ip_address="127.0.0.1"
    port=5002
    client_socket.connect((ip_address, port))  
    print("Connected to the server.")

    encryption_type = client_socket.recv(4096).decode('utf-8').strip().lower()

    if encryption_type == 'asymmetric':
        server_public_key_bytes = client_socket.recv(4096)
        server_public_key = serialization.load_pem_public_key(server_public_key_bytes, backend=default_backend())

        client_public_key_bytes = client_private_key.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        client_socket.send(client_public_key_bytes)

    while True:
        message = input("Client: ")
        if message.lower() == 'exit':
            print("Connection closed by client.")
            client_socket.send(b'exit')
            break

        if encryption_type == 'symmetric':
            encrypted_message = symmetric_encrypt_message(message, symmetric_key)
            print(f"Encrypted message (symmetric): {encrypted_message}")  
        elif encryption_type == 'asymmetric':
            encrypted_message = asymmetric_encrypt_message(message, server_public_key)
            print(f"Encrypted message (asymmetric): {encrypted_message}") 
        elif encryption_type == 'none':
            encrypted_message = message.encode('utf-8')
        else:
            print("Invalid encryption type selected.")
            break

        client_socket.send(encrypted_message)

        encrypted_data = client_socket.recv(4096)
        if not encrypted_data or encrypted_data == b'exit':
            print("Connection closed by server.")
            break

        print(f"Received encrypted data: {encrypted_data}")  

        if encryption_type == 'symmetric':
            try:
                data = symmetric_decrypt_message(encrypted_data, symmetric_key)
                print(f"Decrypted message from server: {data}")
            except ValueError:
                print("Failed to decrypt message.")
        elif encryption_type == 'asymmetric':
            try:
                data = asymmetric_decrypt_message(encrypted_data, client_private_key)
                print(f"Decrypted message from server: {data}")
            except ValueError:
                print("Failed to decrypt message.")
        elif encryption_type == 'none':
            data = encrypted_data.decode('utf-8', errors='replace')
            print(f"Server: {data}")

    client_socket.close()

if __name__ == "__main__":
    init()
    start_client()
