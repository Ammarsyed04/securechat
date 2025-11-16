"""
RSA PKCS#1 v1.5 sign/verify over SHA-256 with cryptography.
"""
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography import x509
import base64
import os

def sign_bytes(private_key_pem: bytes, data: bytes) -> str:
    priv = serialization.load_pem_private_key(private_key_pem, password=None)
    sig = priv.sign(data, padding.PKCS1v15(), hashes.SHA256())
    return base64.b64encode(sig).decode()

def verify_sig(public_key_pem: bytes, data: bytes, sig_b64: str) -> bool:
    from cryptography.hazmat.primitives.asymmetric import rsa
    pub = serialization.load_pem_public_key(public_key_pem)
    sig = base64.b64decode(sig_b64)
    try:
        pub.verify(sig, data, padding.PKCS1v15(), hashes.SHA256())
        return True
    except Exception:
        return False


# Convenience functions for client.py and server.py
def rsa_sign_b64(data: bytes, key_path: str = "certs/private/client_cert_key.pem") -> str:
    """
    Sign data with RSA private key and return base64-encoded signature.
    Default key path is for client; server should specify its own key path.
    """
    with open(key_path, "rb") as f:
        key_pem = f.read()
    return sign_bytes(key_pem, data)


def rsa_verify_b64(data: bytes, sig_b64: str, cert=None, cert_path: str = None) -> bool:
    """
    Verify RSA signature using public key from certificate.
    Either provide cert (x509.Certificate object) or cert_path (path to PEM file).
    If neither is provided, tries to load from default client cert path.
    """
    if cert is None:
        if cert_path is None:
            cert_path = "certs/client_cert.pem"
        if os.path.exists(cert_path):
            with open(cert_path, "rb") as f:
                cert = x509.load_pem_x509_certificate(f.read())
        else:
            raise ValueError(f"Certificate not found at {cert_path}")
    
    pub_key = cert.public_key()
    sig = base64.b64decode(sig_b64)
    try:
        pub_key.verify(sig, data, padding.PKCS1v15(), hashes.SHA256())
        return True
    except Exception:
        return False
