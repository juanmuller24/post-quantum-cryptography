"""
QSocket 2 - Server Data Component
---------------------------------
This module handles server-side cryptographic operations for key exchange.
It includes functions for:
- Receiving pre-keys from the client
- Generating shared keys from exchanged cryptographic material  
- Creating payload data for key exchange with the client

The implementation uses both classical and post-quantum cryptography.
"""

import oqs        # Open Quantum Safe library for post-quantum algorithms
import json       # For data serialization
import crypt      # Core cryptographic operations
import base64     # For encoding/decoding binary data
import socket     # For network communication
from cryptography.hazmat.primitives import serialization  # For key serialization
from cryptography.hazmat.backends import default_backend  # Cryptographic backend
from cryptography.hazmat.primitives.asymmetric import ec  # Elliptic curve cryptography


def receive_prekeys(host, port):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.bind((host, port))
            s.listen(1)
            print("Server listening...")

            conn, addr = s.accept()
            with conn:
                print(f"Connected by {addr}")

                data = b""
                while True:
                    chunk = conn.recv(1024)
                    if not chunk:
                        break
                    data += chunk

                print(f"Received {len(data)} bytes of data.")

                # Deserialize received data
                payload = json.loads(data.decode('utf-8'))

                prekeys = payload['prekeys']
                signature = base64.b64decode(payload['signature'])

                # Base64 decode public keys from the client
                identity_pk = base64.b64decode(prekeys['identity_pk'])
                ephemeral_pk = base64.b64decode(prekeys['ephemeral_pk'])
                kem_pk = base64.b64decode(prekeys['kem_pk'])

                # Verify the signature
                if crypt.verify_signature(identity_pk, signature, prekeys):
                    print("Prekeys verified successfully.")
                    return ephemeral_pk, kem_pk
                else:
                    print("Prekey verification failed.")

    except socket.error as e:
        print(f"Socket error: {e}")
    except json.JSONDecodeError as e:
        print(f"JSON Decode Error: {e}")
    except Exception as e:
        print(f"Error receiving prekeys: {e}")


def payload_data(keys, shared_keys):
    """
    Create a signed payload with the server's keys for secure key exchange.
    
    Args:
        keys: Dictionary containing the server's keys
        shared_keys: Dictionary containing shared keys generated with the client's public keys
    
    Returns:
        dict: A payload containing signed prekeys for transmission to the client
    """
    # Prepare the prekeys to be sent
    prekeys = {
        'identity_pk': base64.b64encode(keys['identity_pk']).decode('utf-8'),
        'ephemeral_pk': base64.b64encode(keys['ephemeral_pk']).decode('utf-8'),
        'ciphertext': base64.b64encode(shared_keys['ciphertext']).decode('utf-8'),
    }
    # Create a digest of the prekeys and sign it using the identity private key
    prekeys_digest = crypt.sign_data(keys['identity_sk'], prekeys)

    # Combine the prekeys and signature into one payload
    payload = {
        'prekeys': prekeys,
        'signature': base64.b64encode(prekeys_digest).decode('utf-8')
    }
    return payload


def generate_shared_keys(client_public_key_ecc, client_public_key_kyber, ephemeral_sk, kem):
    # calculate cipher/shared key for kyber and shared key for ecc
    ciphertext, shared_key_kyber = kem.encap_secret(client_public_key_kyber)
    shared_key_ecc = ephemeral_sk.exchange(ec.ECDH(), serialization.load_der_public_key(client_public_key_ecc))
    shared_keys = {
        'shared_key_ecc': shared_key_ecc,
        'ciphertext': ciphertext,
        'shared_key_kyber': shared_key_kyber
    }
    return shared_keys
