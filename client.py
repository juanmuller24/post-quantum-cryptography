"""
QSocket 2 - Client Component
----------------------------
This module implements a quantum-safe secure client that can exchange encrypted messages
and media with a compatible server. It uses a hybrid approach combining classical 
elliptic curve cryptography with post-quantum algorithms (Kyber).

The client performs the following key operations:
1. Generate cryptographic keys (ECDSA, ECDH, Kyber)
2. Exchange keys securely with server
3. Establish shared encryption keys
4. Provide encrypted text messaging and file transfer capabilities

For details on the cryptographic protocols, see the crypt.py module.
"""

import base64  # For encoding binary data to text for JSON transmission
import json    # For serializing data structures for network transmission
import os      # For file system operations
import socket  # For network communication
import client_data  # Client-specific key exchange functions
import crypt  # Core cryptographic operations

# Get the current working directory for file operations
current_directory = os.getcwd()


def send_media(client_socket):
    """
    Encrypts and sends a media file (JPG image) to the server.
    
    Args:
        client_socket: An established socket connection to the server
        
    Note: Uses the global derived_key for AES encryption
    """
    try:
        asset_name = input("Enter asset name (without extension): ")

        # Loop through files in the assets directory
        for file_name in os.listdir(f"{current_directory}/assets"):
            # Check if the file has a .JPG extension and matches the requested name
            if (file_name.endswith('.JPG')) and (file_name.strip('.JPG') == asset_name):
                with open(f"{current_directory}/assets/{file_name}", "rb") as file:
                    file_data = file.read()
                
                # Encrypt the file data using AES-CTR
                ciphertext, iv = crypt.encrypt_message(file_data, derived_key)
                
                # Prepare the encrypted data for transmission
                enc_data = {
                    "iv": base64.b64encode(iv).decode('utf-8'),  # IV needs to be sent for decryption
                    "ciphertext": base64.b64encode(ciphertext).decode('utf-8'),
                }

                data_string = json.dumps(enc_data)
                client_socket.sendall(data_string.encode('utf-8'))
                print("Sent image successfully!")
    except Exception as error:
        print(f"Error sending media: {error}")
    finally:
        client_socket.close()  # Ensure socket is closed even if an error occurs


def send_text(client_socket):
    """
    Implements an encrypted text chat client using AES encryption.
    
    This function creates a loop where the user can input messages, which are
    encrypted and sent to the server. It then waits for and decrypts the server's response.
    
    Args:
        client_socket: An established socket connection to the server
        
    Note: Uses the global derived_key for AES encryption
    """
    try:
        while True:
            # Get user input, encrypt it, and send to server
            plaintext = input("Client: ")
            plaintext_bytes = plaintext.encode()
            ciphertext, iv = crypt.encrypt_message(plaintext_bytes, derived_key)
            enc_data = {
                "iv": base64.b64encode(iv).decode('utf-8'),
                "ciphertext": base64.b64encode(ciphertext).decode('utf-8'),
            }
            data_string = json.dumps(enc_data)
            client_socket.sendall(data_string.encode('utf-8'))

            # Receive encrypted response from server
            ciphertext_bytes = client_socket.recv(1024)
            if not ciphertext_bytes:
                print("Server disconnected")
                break

            # Parse and decrypt the server's message
            server_json = json.loads(ciphertext_bytes)
            iv_bytes = base64.b64decode(server_json['iv'])
            ciphertext_bytes = base64.b64decode(server_json['ciphertext'])
            plaintext_bytes = crypt.decrypt_message(ciphertext_bytes, derived_key, iv_bytes)

            # Check for quit command or display the message
            if plaintext_bytes.decode() == "quit":
                print("Received 'quit' command. Closing connection.")
                break
            else:
                print(f"Server: {plaintext_bytes.decode()}")

    except socket.error as e:
        print(f"Client: Socket error during text exchange: {e}")
    except Exception as e:
        print(f"Client: Unexpected error during text exchange: {e}")
    finally:
        client_socket.close()  # Ensure socket is closed on exit


def message_exchange():
    """
    Establishes a connection with the server and manages the message/media exchange workflow.
    
    This function:
    1. Initializes a socket connection to the server
    2. Prompts the user to choose between sending an image or text
    3. Redirects to the appropriate handler function based on user choice
    
    Error handling is implemented for socket errors and invalid user input.
    """
    try:
        # client socket init
        client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        client_socket.connect(('localhost', 12344))
        choice = int(input("Send Image (1) (or) Send Text (2): "))  # Added colon for better UI
        client_socket.send(choice.to_bytes(4, byteorder='big'))
        if choice == 1:
            send_media(client_socket)
        elif choice == 2:
            send_text(client_socket)
        else:
            print("Invalid choice. Exiting.")

    except socket.error as e:
        print(f"Client: Socket error: {e}")
    except ValueError:
        print("Client: Invalid input, please enter 1 or 2.")
    except Exception as e:
        print(f"Client: Error during message exchange: {e}")


if __name__ == "__main__":
    keys = crypt.generate_keys()
    payload = client_data.payload_data(keys)
    crypt.send_prekeys("localhost", 12346, payload)
    server_ephemeral_pk, server_kem_ciphertext = client_data.receive_prekeys("localhost", 12345) # type: ignore
    shared_keys = client_data.generate_shared_keys(
        server_ephemeral_pk,
        server_kem_ciphertext,
        keys['ephemeral_sk'],
        keys['kem']
    )
    derived_key = crypt.key_derivation(shared_keys['shared_key_ecc'], shared_keys['shared_key_kyber'])
    message_exchange()
