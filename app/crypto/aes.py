"""
AES-128 ECB + PKCS#7 pad/unpad with cryptography
Note: Assignment requests AES-128 block. We use ECB mode per skeleton.
"""
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend
import base64

BLOCK_SIZE = 128  # bits

def pkcs7_pad(data: bytes) -> bytes:
    padder = padding.PKCS7(BLOCK_SIZE).padder()
    return padder.update(data) + padder.finalize()

def pkcs7_unpad(data: bytes) -> bytes:
    unpadder = padding.PKCS7(BLOCK_SIZE).unpadder()
    return unpadder.update(data) + unpadder.finalize()

def encrypt_ecb(key16: bytes, plaintext: bytes) -> bytes:
    assert len(key16) == 16
    pt = pkcs7_pad(plaintext)
    cipher = Cipher(algorithms.AES(key16), modes.ECB(), backend=default_backend())
    encryptor = cipher.encryptor()
    enc = encryptor.update(pt) + encryptor.finalize()  # CORRECT - one instance
    return enc

def decrypt_ecb(key16: bytes, ciphertext: bytes) -> bytes:
    assert len(key16) == 16
    cipher = Cipher(algorithms.AES(key16), modes.ECB(), backend=default_backend())
    decryptor = cipher.decryptor()
    dec = decryptor.update(ciphertext) + decryptor.finalize()
    return pkcs7_unpad(dec)

def encrypt_b64(key16: bytes, plaintext: bytes) -> str:
    return base64.b64encode(encrypt_ecb(key16, plaintext)).decode()

def decrypt_b64(key16: bytes, ct_b64: str) -> bytes:
    return decrypt_ecb(key16, base64.b64decode(ct_b64))


# Wrapper functions for compatibility with client.py and server.py
def aes_encrypt(key16: bytes, plaintext: bytes) -> bytes:
    """AES encrypt using ECB mode."""
    return encrypt_ecb(key16, plaintext)


def aes_decrypt(key16: bytes, ciphertext: bytes) -> bytes:
    """AES decrypt using ECB mode."""
    return decrypt_ecb(key16, ciphertext)
