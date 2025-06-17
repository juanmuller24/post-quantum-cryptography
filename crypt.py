"""
QSocket 2 - Core Cryptography Module
-----------------------------------
This module implements the cryptographic functionality used by both the client and server.
It provides:
1. Key generation for classical (ECC) and post-quantum (Kyber) cryptography
2. Digital signature creation and verification
3. Key exchange mechanisms
4. Symmetric encryption (AES-CTR) for secure messaging
5. Key derivation functions

This implementation follows a hybrid cryptographic approach, combining:
- ECDSA for signatures
- ECDH for classical key exchange
- Kyber for post-quantum key encapsulation
- AES-CTR with HKDF for symmetric encryption
"""

import os          # For secure random number generation
import json        # For data serialization 
import socket      # For network communication
from cryptography.hazmat.primitives.asymmetric import ec  # Elliptic curve cryptography
from cryptography.hazmat.primitives import hashes        # Cryptographic hash functions
from cryptography.hazmat.primitives import serialization # Key serialization
from cryptography.hazmat.backends import default_backend # Cryptographic backend
from cryptography.hazmat.primitives.asymmetric.utils import Prehashed # For signature generation
import hashlib     # For message digests
import oqs        # Open Quantum Safe library for post-quantum algorithms
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes  # For AES encryption
from cryptography.hazmat.primitives.kdf.hkdf import HKDF  # Key derivation function


def generate_keys():
    """
    Generate cryptographic key pairs for secure communication.
    
    This function generates three types of keys:
    1. Identity keys (ECDSA) - For authentication via signatures
    2. Ephemeral keys (ECDH) - For classical key exchange
    3. KEM keys (Kyber1024) - For post-quantum key encapsulation
    
    Returns:
        dict: Dictionary containing all generated keys and their public parts
    """
    # Generate classical ECC keys
    identity_key = ec.generate_private_key(ec.SECP256R1(), default_backend())
    ephemeral_key = ec.generate_private_key(ec.SECP256R1(), default_backend())

    # Generate post-quantum KEM keys using Kyber1024
    kem_alg = "Kyber1024"  # NIST-approved PQC algorithm
    kem = oqs.KeyEncapsulation(kem_alg)
    kem_key = kem.generate_keypair()

    # Organize all key material into a dictionary
    keys = {
        'identity_sk': identity_key,
        'identity_pk': identity_key.public_key().public_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ),
        'ephemeral_sk': ephemeral_key,
        'ephemeral_pk': ephemeral_key.public_key().public_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ),
        'kem': kem,
        'kem_pk': kem_key
    }
    return keys


# Function to sign data using the identity private key
def sign_data(identity_sk, prekeys):
    prekeys_json = json.dumps(prekeys).encode('utf-8')
    digest = hashlib.sha256(prekeys_json).digest()

    signature = identity_sk.sign(digest, ec.ECDSA(Prehashed(hashes.SHA256())))
    return signature


# Function to verify signature on the server-side
def verify_signature(public_key_bytes, signature, data):
    try:
        public_key = serialization.load_der_public_key(public_key_bytes, backend=default_backend())
        digest = hashlib.sha256(json.dumps(data).encode('utf-8')).digest()

        public_key.verify(signature, digest, ec.ECDSA(Prehashed(hashes.SHA256()))) # type: ignore
        return True
    except Exception as e:
        print(f"Verification failed: {e}")
        return False


def send_prekeys(host, port, payload):
    try:
        # Connect to server
        with socket.create_connection((host, port)) as s:
            # Send the data as a JSON object
            s.sendall(json.dumps(payload).encode('utf-8'))
            print("Prekeys sent successfully.")

    except socket.error as e:
        print(f"Socket error: {e}")
    except Exception as e:
        print(f"Error during prekey sending: {e}")


def key_derivation(shared_key_kyber, shared_key_ecc):
    """
    Derive a symmetric encryption key from two shared secrets.
    
    This function combines the classical ECDH shared key with the post-quantum
    Kyber shared key using HKDF to derive a single AES key.
    
    Args:
        shared_key_kyber: The shared secret from Kyber key encapsulation
        shared_key_ecc: The shared secret from ECDH key exchange
        
    Returns:
        bytes: A 32-byte (256-bit) derived key for AES encryption
    """
    shared_key_combined = shared_key_kyber + shared_key_ecc
    derived_key = HKDF(algorithm=hashes.SHA256(),
                       length=32,
                       salt=None,
                       info=b'handshake data',
                       ).derive(shared_key_combined)
    return derived_key


def encrypt_message(plaintext, key):
    """
    Encrypt a message using AES-CTR mode.
    
    Args:
        plaintext: The binary data to encrypt
        key: The 32-byte AES key
        
    Returns:
        tuple: (ciphertext, initialization vector) - Both needed for decryption
    """
    iv = os.urandom(16)  # Generate a random 128-bit initialization vector
    cipher = Cipher(algorithms.AES(key), modes.CTR(iv))
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(plaintext) + encryptor.finalize()
    return ciphertext, iv


def decrypt_message(ciphertext, key, iv):
    """
    Decrypt a message using AES-CTR mode.
    
    Args:
        ciphertext: The encrypted data
        key: The 32-byte AES key used for encryption
        iv: The initialization vector used during encryption
        
    Returns:
        bytes: The decrypted plaintext
    """
    cipher = Cipher(algorithms.AES(key), modes.CTR(iv))
    decryptor = cipher.decryptor()
    plaintext = decryptor.update(ciphertext) + decryptor.finalize()
    return plaintext
