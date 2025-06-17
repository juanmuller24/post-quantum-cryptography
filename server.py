"""
QSocket 2 - Server Component
----------------------------
This module implements a quantum-safe secure server that can exchange encrypted messages
and media with compatible clients. It employs a hybrid cryptographic approach combining 
classical elliptic curve cryptography with post-quantum algorithms (Kyber).

The server performs the following key operations:
1. Receive and verify client pre-keys
2. Generate cryptographic keys (ECDSA, ECDH, Kyber)
3. Establish shared encryption keys
4. Handle encrypted text messaging and file transfer requests

For details on the cryptographic protocols, see the crypt.py module.
"""

import os          # For file system operations
import json        # For data serialization
import crypt       # Core cryptographic operations
import base64      # For encoding/decoding binary data
import socket      # For network communication
import server_data # Server-specific key exchange functions

current_directory = os.getcwd()  # Get current working directory for file operations


def receive_media(conn):
    """
    Receives an encrypted media file from the client, decrypts it and saves it.
    
    This function:
    1. Receives chunks of encrypted data from the connection
    2. Decrypts the data using the global derived_key
    3. Saves the decrypted file as a JPG image in the received_assets directory
    
    Args:
        conn: The active socket connection with the client
    """
    try:
        data = b""
        while True:
            chunk = conn.recv(1024)
            if not chunk:
                break
            data += chunk
        enc_data = json.loads(data.decode('utf-8'))

        iv = base64.b64decode(enc_data['iv'])
        ciphertext = base64.b64decode(enc_data['ciphertext'])
        plaintext = crypt.decrypt_message(ciphertext, derived_key, iv)

        with open(f"{current_directory}/received_assets/photo.jpg", "wb") as file:
            file.write(plaintext)
        print("File received successfully!!")
    except socket.error as error:
        print(f"Socket error receive_media: {error}")
    except Exception as error:
        print(f"Error receiving media: {error}")


def receive_text(conn):
    """
    Implements an encrypted text chat server using AES encryption.
    
    This function:
    1. Receives encrypted messages from the client
    2. Decrypts them using the shared encryption key
    3. Allows the server to respond with encrypted messages
    4. Handles disconnection and quit commands
    
    Args:
        conn: The active socket connection with the client
    """
    try:
        while True:
            # Receive encrypted message from client
            ciphertext_bytes = conn.recv(1024)
            server_json = json.loads(ciphertext_bytes)
            iv_bytes = base64.b64decode(server_json['iv'])
            ciphertext_bytes = base64.b64decode(server_json['ciphertext'])
            plaintext_bytes = crypt.decrypt_message(ciphertext_bytes, derived_key, iv_bytes)
            
            # Check for disconnection
            if not ciphertext_bytes:
                print("Client disconnected")
                break
                
            # Display decrypted message
            print(f"Client: {plaintext_bytes.decode('utf-8')}")

            # Get server response, encrypt it, and send to client
            plaintext = input("Server: ")
            plaintext_bytes = plaintext.encode()
            ciphertext, iv = crypt.encrypt_message(plaintext_bytes, derived_key)
            enc_data = {
                "iv": base64.b64encode(iv).decode('utf-8'),
                "ciphertext": base64.b64encode(ciphertext).decode('utf-8'),
            }
            data_string = json.dumps(enc_data)
            conn.sendall(data_string.encode('utf-8'))
            
            # Check for quit command
            if plaintext == "quit":
                break

    except socket.error as e:
        print(f"Server: Socket error during text exchange: {e}")
    except Exception as e:
        print(f"Server: Unexpected error during text exchange: {e}")
    finally:
        conn.close()  # Ensure connection is closed on exit


def message_exchange():
    """
    Establishes a server socket, listens for client connections, and handles message/media exchange.
    
    This function:
    1. Sets up a socket server on localhost:12344
    2. Waits for client connection
    3. Receives the client's choice between image or text message
    4. Calls the appropriate handler function based on client choice
    
    Error handling is implemented for socket errors and invalid choices.
    """
    try:
        # server socket init
        server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_socket.bind(('localhost', 12344))
        server_socket.listen(1)
        print("Server started, waiting for connection...")
        conn, addr = server_socket.accept()
        print(f"Connected by {addr}")
        choice_bytes = conn.recv(1024)
        choice = int.from_bytes(choice_bytes, byteorder='big')
        if choice == 1:
            receive_media(conn)
        elif choice == 2:
            receive_text(conn)
        else:
            print("Invalid choice. Exiting.")

    except socket.error as e:
        print(f"Client: Socket error: {e}")
    except ValueError:
        print("Client: Invalid input, please enter 1 or 2.")
    except Exception as e:
        print(f"Client: Error during message exchange: {e}")


if __name__ == "__main__":
    client_ephemeral_pk, client_kem_pk = server_data.receive_prekeys("localhost", 12346) # type: ignore
    keys = crypt.generate_keys()
    shared_keys = server_data.generate_shared_keys(
        client_ephemeral_pk,
        client_kem_pk,
        keys['ephemeral_sk'],
        keys['kem'])
    payload = server_data.payload_data(keys, shared_keys)
    crypt.send_prekeys("localhost", 12345, payload)
    derived_key = crypt.key_derivation(shared_keys['shared_key_ecc'], shared_keys['shared_key_kyber'])
    message_exchange()
