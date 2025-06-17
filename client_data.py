"""
QSocket 2 - Client Data Component
---------------------------------
This module handles client-side cryptographic operations for key exchange.
It includes functions for:
- Generating shared keys from exchanged cryptographic material
- Receiving pre-keys from the server
- Creating payload data for key exchange

The hybrid encryption approach combines ECC and Kyber for quantum-resistant security.
"""

import base64  # For encoding binary data
import json    # For data serialization
import socket  # For network communication

# Cryptography imports for key operations
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec

import crypt  # Custom cryptography functions


def generate_shared_keys(server_public_key_ecc, server_kyber_ciphertext, ephemeral_sk, kem):
    """
    Generate shared cryptographic keys using both classical and quantum-resistant algorithms.
    
    Args:
        server_public_key_ecc: Server's public ECDH key for classical key exchange
        server_kyber_ciphertext: Encapsulated Kyber key from server
        ephemeral_sk: Client's ephemeral private key for ECDH
        kem: Client's Kyber KEM object for decapsulation
        
    Returns:
        dict: Dictionary containing both shared keys (ECC and Kyber)
    """
    # Decapsulate the Kyber shared key (post-quantum)
    shared_key_kyber = kem.decap_secret(server_kyber_ciphertext)
    
    # Generate the ECDH shared key (classical)
    shared_key_ecc = ephemeral_sk.exchange(ec.ECDH(), serialization.load_der_public_key(server_public_key_ecc))
    
    # Combine both for hybrid security
    shared_keys = {
        'shared_key_ecc': shared_key_ecc,
        'ciphertext': server_kyber_ciphertext,
        'shared_key_kyber': shared_key_kyber
    }
    return shared_keys


def receive_prekeys(host, port):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.bind((host, port))
            s.listen(1)
            print("Client listening...")

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
                kem_ciphertext = base64.b64decode(prekeys['ciphertext'])

                # Verify the signature
                if crypt.verify_signature(identity_pk, signature, prekeys):
                    print("Prekeys verified successfully.")
                    return ephemeral_pk, kem_ciphertext
                else:
                    print("Prekey verification failed.")

    except socket.error as e:
        print(f"Socket error: {e}")
    except json.JSONDecodeError as e:
        print(f"JSON Decode Error: {e}")
    except Exception as e:
        print(f"Error receiving prekeys: {e}")


def payload_data(keys):
    # Prepare the prekeys to be sent
    prekeys = {
        'identity_pk': base64.b64encode(keys['identity_pk']).decode('utf-8'),
        'ephemeral_pk': base64.b64encode(keys['ephemeral_pk']).decode('utf-8'),
        'kem_pk': base64.b64encode(keys['kem_pk']).decode('utf-8'),
    }
    # Create a digest of the prekeys and sign it using the identity private key
    prekeys_digest = crypt.sign_data(keys['identity_sk'], prekeys)

    # Combine the prekeys and signature into one payload
    payload = {
        'prekeys': prekeys,
        'signature': base64.b64encode(prekeys_digest).decode('utf-8')
    }
    return payload
