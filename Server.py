import os
import socket
from AES import *
from RSA import *
from colorama import Fore, Back, Style, init

def server_program():
    print("server")
    # Set up socket
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    host = '127.0.0.1' 
    port = 5002
    server_socket.bind((host, port))
    server_socket.listen(1)
    print(f"{Fore.LIGHTBLACK_EX}Server is running on {host}:{port}...")

    # Generate AES key and IV
    aes_key = os.urandom(16)  # 16-byte key for AES-128
    aes_iv = os.urandom(16)   # 16-byte IV for AES

    # Generate RSA keys
    rsa_private_key, rsa_public_key = generate_rsa_keys()

    # Accept client connection
    client_socket, address = server_socket.accept()
    print(f"Connection from {address}")

    # Send public key and AES key/IV to client
    serialized_rsa_key = serialize_public_key(rsa_public_key)
    client_socket.send(serialized_rsa_key)
    client_socket.send(aes_key)
    client_socket.send(aes_iv)

    # Keep receiving messages from the client
    while True:
        try:
            # Receive encryption type
            encryption_type = client_socket.recv(1024).decode()
            if not encryption_type:  # If the client disconnects
                print("Client disconnected.")
                break
            print(f"{Fore.LIGHTBLUE_EX}Encryption type chosen by client: {Fore.RED}{encryption_type}{Style.RESET_ALL}")
            

            # Receive message
            encrypted_message = client_socket.recv(1024)
            print(f"{Fore.LIGHTBLUE_EX}Encrypted message : {Fore.LIGHTBLACK_EX}{encrypted_message}{Style.RESET_ALL}\n")
            if encryption_type == "AES":
                decrypted_message = AES_decrypt_message(aes_key, aes_iv, encrypted_message)
            elif encryption_type == "RSA":
                decrypted_message = decrypt_message_rsa(rsa_private_key, encrypted_message)
            elif encryption_type == "None":
                decrypted_message = encrypted_message
            else:
                decrypted_message = b"Invalid encryption type"

            # Display the decrypted message
            print(f"{Fore.LIGHTBLUE_EX}Received message: {Fore.CYAN} {decrypted_message.decode()}{Style.RESET_ALL}")

        except Exception as e:
            print(f"Error processing message: {e}")
            break

    # Close connection
    client_socket.close()
    server_socket.close()

if __name__ == "__main__":
    init()
    server_program()
