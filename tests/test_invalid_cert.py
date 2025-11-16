#!/usr/bin/env python3
"""
Test 2: Invalid Certificate Test
Tests: BAD CERT error for forged/self-signed/expired certificates
"""

import sys
import os
# Add project root to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import socket
import json
from app.common.protocol import Hello
from app.common.utils import b64e
from cryptography import x509
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
import datetime

def create_self_signed_cert():
    """Create a self-signed certificate (not signed by CA)"""
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, u"forged_client"),
    ])
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.datetime.utcnow())
        .not_valid_after(datetime.datetime.utcnow() + datetime.timedelta(days=365))
        .sign(key, hashes.SHA256())
    )
    return cert.public_bytes(serialization.Encoding.PEM).decode()

def create_expired_cert():
    """Create an expired certificate"""
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, u"expired_client"),
    ])
    # Load CA cert to get issuer
    with open("certs/ca.pem", "rb") as f:
        ca_cert = x509.load_pem_x509_certificate(f.read())
    
    with open("certs/private/ca_key.pem", "rb") as f:
        ca_key = serialization.load_pem_private_key(f.read(), password=None)
    
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(ca_cert.subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.datetime.utcnow() - datetime.timedelta(days=365))
        .not_valid_after(datetime.datetime.utcnow() - datetime.timedelta(days=1))  # Expired yesterday
        .sign(ca_key, hashes.SHA256())
    )
    return cert.public_bytes(serialization.Encoding.PEM).decode()

def test_invalid_cert(cert_pem, test_name):
    """Test connection with invalid certificate"""
    print(f"\n{'='*60}")
    print(f"TEST: {test_name}")
    print(f"{'='*60}")
    
    sock = socket.socket()
    try:
        sock.connect(("127.0.0.1", 9000))
        print("✓ Connected to server")
    except ConnectionRefusedError:
        print("❌ Server not running. Start server first: python -m app.server")
        return False
    
    # Send Hello with invalid certificate
    my_nonce = b64e(b"test123")
    hello = Hello(cert=cert_pem, nonce=my_nonce)
    sock.sendall((json.dumps(hello.model_dump()) + "\n").encode())
    
    # Wait for response
    try:
        response = sock.makefile().readline()
        print(f"Server response: {response[:200]}")
    except Exception as e:
        print(f"Connection closed by server (expected)")
        print(f"✓ Server correctly rejected invalid certificate")
        return True
    
    sock.close()
    return False

def main():
    print("="*60)
    print("INVALID CERTIFICATE TEST")
    print("="*60)
    print("\nThis test verifies that the server rejects:")
    print("1. Self-signed certificates (not signed by CA)")
    print("2. Expired certificates")
    print("\nExpected: BAD CERT error")
    print("="*60)
    
    # Test 1: Self-signed certificate
    print("\n[Test 1] Self-signed certificate (forged)")
    self_signed = create_self_signed_cert()
    test_invalid_cert(self_signed, "Self-signed Certificate")
    
    # Test 2: Expired certificate
    print("\n[Test 2] Expired certificate")
    expired = create_expired_cert()
    test_invalid_cert(expired, "Expired Certificate")
    
    print("\n" + "="*60)
    print("TEST COMPLETE")
    print("="*60)
    print("\nCheck server output for 'BAD CERT' messages")
    print("Expected server output:")
    print("  ❌ Certificate verification error: BAD CERT: UNTRUSTED...")
    print("  OR")
    print("  ❌ Certificate verification error: BAD CERT: EXPIRED...")

if __name__ == "__main__":
    main()

