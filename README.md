# QSocket 2: Quantum-Safe Secure Messaging & File Transfer

QSocket is a proof-of-concept Python project that demonstrates secure, quantum-resistant communication between a client and a server. It uses a hybrid cryptographic approach, combining classical elliptic curve cryptography (ECC) with post-quantum Kyber KEM, to ensure both present and future security against quantum attacks.

## Features

- **Quantum-safe key exchange** using ECDH (SECP256R1) and Kyber1024
- **Authenticated key exchange** with ECDSA signatures
- **AES-CTR encrypted text chat** between client and server
- **AES-CTR encrypted file transfer** (JPG images)
- **Simple, interactive command-line interface**

## Project Structure

```
client.py         # Client application
server.py         # Server application
crypt.py          # Core cryptographic operations
client_data.py    # Client-side key exchange helpers
server_data.py    # Server-side key exchange helpers
assets/           # Place JPG files here for sending
received_assets/  # Received files are saved here
```

## Requirements

- Python 3.8+
- [cryptography](https://pypi.org/project/cryptography/)
- [oqs-python](https://github.com/open-quantum-safe/oqs-python) (for Kyber)

Install dependencies:

```sh
pip install cryptography oqs
```

## How It Works

1. **Key Exchange:**
   - Both client and server generate ECC and Kyber key pairs.
   - They exchange public keys and verify each other's identity using ECDSA signatures.
   - Both sides derive a shared AES key using both ECDH and Kyber for hybrid security.
2. **Secure Communication:**
   - After key exchange, all messages and files are encrypted with AES-CTR using the derived key.
   - Each message/file uses a fresh IV for security.

## Usage

### 1. Start the Server

In one terminal:

```sh
python server.py
```

### 2. Start the Client

In another terminal:

```sh
python client.py
```

### 3. Send Messages or Files

- When prompted, choose to send a text message or a JPG image.
- For images, place your `.JPG` files in the `assets/` directory.
- Received images are saved in `received_assets/`.

## Security Notes

- This project is for educational and research purposes only.
- It demonstrates hybrid post-quantum cryptography but is not production-hardened.
- Always review and adapt cryptographic code for real-world use.

## References

- [Open Quantum Safe Project](https://openquantumsafe.org/)
- [cryptography Python library](https://cryptography.io/)

---

**Author:** Juan Muller
