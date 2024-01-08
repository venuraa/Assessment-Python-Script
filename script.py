from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding, ec
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import os
import base64

def generate_aes_key():
    return os.urandom(32)  # 256-bit key

def encrypt_data_aes(key, data):
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(data.encode()) + encryptor.finalize()
    return base64.b64encode(iv + ciphertext).decode()

def generate_rsa_keys():
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    public_key = private_key.public_key()
    return private_key, public_key

def encrypt_aes_key_rsa(aes_key, rsa_public_key):
    encrypted_key = rsa_public_key.encrypt(
        aes_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return base64.b64encode(encrypted_key).decode()

def generate_ecc_keys():
    private_key = ec.generate_private_key(ec.SECP256R1(), default_backend())
    public_key = private_key.public_key()
    return private_key, public_key

def sign_data_ecc(data, ecc_private_key):
    signature = ecc_private_key.sign(
        data,
        ec.ECDSA(hashes.SHA256())
    )
    return base64.b64encode(signature).decode()

def verify_signature_ecc(data, signature, ecc_public_key):
    try:
        ecc_public_key.verify(
            base64.b64decode(signature),
            data,
            ec.ECDSA(hashes.SHA256())
        )
        return True
    except Exception:
        return False

if __name__ == "__main__":
    data = input("Enter data to encrypt: ")

    # Symmetric Encryption (AES)
    aes_key = generate_aes_key()
    encrypted_data = encrypt_data_aes(aes_key, data)
    print("Encrypted Data:", encrypted_data)

    # Asymmetric Encryption (RSA)
    rsa_private_key, rsa_public_key = generate_rsa_keys()
    encrypted_aes_key = encrypt_aes_key_rsa(aes_key, rsa_public_key)
    print("Encrypted AES Key:", encrypted_aes_key)

    # Digital Signatures (ECC)
    ecc_private_key, ecc_public_key = generate_ecc_keys()
    signature = sign_data_ecc(encrypted_data.encode(), ecc_private_key)
    print("Digital Signature:", signature)
    signature_verified = verify_signature_ecc(encrypted_data.encode(), signature, ecc_public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    ))
    print("Signature Verified:", signature_verified)
