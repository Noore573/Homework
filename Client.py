import socket,os
from AES import *
from RSA import *
from colorama import Fore, Back, Style, init
def client_program():
    # Set up socket
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    host = '127.0.0.1'
    port = 5002
    client_socket.connect((host, port))

    # Receive RSA public key and AES key/IV
    serialized_rsa_key = client_socket.recv(1024)
    rsa_public_key = serialization.load_pem_public_key(serialized_rsa_key)
    aes_key = client_socket.recv(16)
    aes_iv = client_socket.recv(16)

    # Keep sending messages
    try:
        while True:
            # Get user input
            message = input(Fore.LIGHTGREEN_EX+"Enter your message (type 'exit' to quit): "+Style.RESET_ALL).encode()
            if message.decode().lower() == "exit":
                print("Disconnecting from server...")
                break

            print()
            choice = input(Fore.LIGHTGREEN_EX+"Choose encryption type:\n1. AES\n2. RSA\n3.No encryption\n")
            if choice == "1":
                encryption_type = "AES" 
            elif choice=='2': 
                encryption_type = "RSA" 
            else :
                encryption_type = "None"


            if encryption_type == "AES":
                encrypted_message = AES_encrypt_message(aes_key, aes_iv, message)
            elif encryption_type == "RSA":
                encrypted_message = encrypt_message_rsa(rsa_public_key, message)
            elif encryption_type == "None":
                encrypted_message = message
            else:
                print("Invalid choice. Try again.")
                continue

            # Send encryption type and encrypted message
            client_socket.send(encryption_type.encode())
            client_socket.send(encrypted_message)
            print(f"Encrypted message sent using {encryption_type}")

    except Exception as e:
        print(f"Error during communication: {e}")

    # Close connection
    client_socket.close()
if __name__=="__main__":
    init()
    client_program()
