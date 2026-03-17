# -*- coding: utf-8 -*-
# ==============================================================================
# FILE: src/core/crypto.py
# DESCRIPTION: Core Cryptography Module for Sys-Inspector v0.70
#              Implements Hybrid Encryption (RSA + AES-GCM).
#
# CONCEPTS:
#   1. Session Key: Random AES-256 key generated per snapshot.
#   2. Data Encryption: Data is encrypted with Session Key (AES-GCM).
#   3. Key Envelope: Session Key is encrypted with Analyst's Public Key (RSA).
#   4. Storage: DB stores [Encrypted Session Key] + [Encrypted Data] + [IV/Tag].
#
# DEPENDENCIES: pip install cryptography
# AUTHOR: Mario Luz (Sys-Inspector Project)
# VERSION: 0.70.01
# ==============================================================================

import os
import json
import base64
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend


# ------------------------------------------------------------------------------
# KEY MANAGEMENT
# ------------------------------------------------------------------------------
def generate_key_pair(private_key_path="private_key.pem", public_key_path="public_key.pem"):
    """
    Generates a new RSA 4096-bit key pair for the Analyst.
    WARNING: This should be run ONCE on the Analyst's secure machine, NOT on the agent.
    """
    print("[*] Generating RSA-4096 Key Pair...")
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=4096,
        backend=default_backend()
    )

    # Save Private Key
    with open(private_key_path, "wb") as f:
        f.write(private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()  # Can add password here later
        ))

    # Save Public Key
    public_key = private_key.public_key()
    with open(public_key_path, "wb") as f:
        f.write(public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ))

    print(f"[+] Keys generated: {private_key_path}, {public_key_path}")
    print("[!] KEEP THE PRIVATE KEY SAFE! The Agent only needs the PUBLIC key.")


def load_public_key(path):
    """Loads the Public Key from config/file to encrypt Session Keys."""
    with open(path, "rb") as key_file:
        return serialization.load_pem_public_key(
            key_file.read(),
            backend=default_backend()
        )


def load_private_key(path):
    """Loads the Private Key (Server-Side Decryption mode)."""
    with open(path, "rb") as key_file:
        return serialization.load_pem_private_key(
            key_file.read(),
            password=None,
            backend=default_backend()
        )


# ------------------------------------------------------------------------------
# HYBRID ENCRYPTION (AES-GCM + RSA)
# ------------------------------------------------------------------------------
def encrypt_data(data_dict, public_key):
    """
    Encrypts a dictionary object using Hybrid Encryption.

    Args:
        data_dict (dict): The forensic data to encrypt.
        public_key: The RSA Public Key object.

    Returns:
        dict: {
            'enc_session_key': base64_string,  # AES key encrypted with RSA
            'iv': base64_string,               # Initialization Vector
            'ciphertext': base64_string,       # The data encrypted with AES
            'tag': base64_string               # GCM Auth Tag
        }
    """
    # 1. Prepare Data
    json_data = json.dumps(data_dict).encode('utf-8')

    # 2. Generate Ephemeral Session Key (AES-256)
    session_key = os.urandom(32)  # 256 bits
    iv = os.urandom(12)          # GCM standard IV size

    # 3. Encrypt Data with AES-GCM
    cipher = Cipher(algorithms.AES(session_key), modes.GCM(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(json_data) + encryptor.finalize()

    # 4. Encrypt Session Key with RSA Public Key
    encrypted_session_key = public_key.encrypt(
        session_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    # 5. Return Bundle (All encoded as Base64 for safe storage/JSON)
    return {
        'enc_session_key': base64.b64encode(encrypted_session_key).decode('utf-8'),
        'iv': base64.b64encode(iv).decode('utf-8'),
        'ciphertext': base64.b64encode(ciphertext).decode('utf-8'),
        'tag': base64.b64encode(encryptor.tag).decode('utf-8')
    }


def decrypt_data(encrypted_bundle, private_key):
    """
    Decrypts the bundle using the Private Key.
    Used in Server-Side Decryption mode or by the HTML Generator.
    """
    try:
        # 1. Decode Base64 components
        enc_session_key = base64.b64decode(encrypted_bundle['enc_session_key'])
        iv = base64.b64decode(encrypted_bundle['iv'])
        ciphertext = base64.b64decode(encrypted_bundle['ciphertext'])
        tag = base64.b64decode(encrypted_bundle['tag'])

        # 2. Decrypt Session Key using RSA Private Key
        session_key = private_key.decrypt(
            enc_session_key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )

        # 3. Decrypt Data using AES-GCM
        cipher = Cipher(algorithms.AES(session_key), modes.GCM(iv, tag), backend=default_backend())
        decryptor = cipher.decryptor()
        json_data = decryptor.update(ciphertext) + decryptor.finalize()

        return json.loads(json_data.decode('utf-8'))

    except Exception as e:
        print(f"[!] Decryption Failed: {e}")
        return None


# ------------------------------------------------------------------------------
# SELF-TEST (Run this file directly to verify)
# ------------------------------------------------------------------------------
if __name__ == "__main__":
    print("--- Running Crypto Module Self-Test ---")

    # 1. Setup Keys (Simulation)
    generate_key_pair("test_priv.pem", "test_pub.pem")

    # 2. Simulate Config Load
    pub_k = load_public_key("test_pub.pem")
    priv_k = load_private_key("test_priv.pem")

    # 3. Dummy Data
    secret_data = {
        "hostname": "critical-server",
        "processes": [{"pid": 1, "name": "systemd"}, {"pid": 666, "name": "malware"}]
    }
    print(f"\n[1] Original Data: {secret_data}")

    # 4. Encrypt
    bundle = encrypt_data(secret_data, pub_k)
    print(f"\n[2] Encrypted Bundle (What goes to DB):")
    print(f"    - AES Key (Enveloped): {bundle['enc_session_key'][:30]}...")
    print(f"    - Ciphertext: {bundle['ciphertext'][:30]}...")

    # 5. Decrypt
    restored_data = decrypt_data(bundle, priv_k)
    print(f"\n[3] Decrypted Data: {restored_data}")

    # 6. Validate
    assert secret_data == restored_data
    print("\n[SUCCESS] Integrity Check Passed.")

    # Cleanup
    os.remove("test_priv.pem")
    os.remove("test_pub.pem")
