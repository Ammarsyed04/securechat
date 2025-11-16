#!/usr/bin/env python3
"""
Issue an entity cert signed by the local root CA.
Usage: python gen_cert.py server localhost
Produces certs/<name>.pem and certs/private/<name>_key.pem
"""
import os
import sys
import datetime
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa

if len(sys.argv) < 3:
    print("Usage: gen_cert.py <server|client> <common_name>")
    sys.exit(1)

role = sys.argv[1]
cn = sys.argv[2]

CA_CERT = "certs/ca.pem"
CA_KEY = "certs/private/ca_key.pem"
OUT_DIR = "certs"
PRIV_DIR = os.path.join(OUT_DIR, "private")
os.makedirs(PRIV_DIR, exist_ok=True)

def load_ca():
    with open(CA_KEY, "rb") as f:
        ca_key = serialization.load_pem_private_key(f.read(), password=None)
    with open(CA_CERT, "rb") as f:
        ca_cert = x509.load_pem_x509_certificate(f.read())
    return ca_key, ca_cert

def main():
    ca_key, ca_cert = load_ca()
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, cn),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"SecureChat"),
    ])
    builder = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(ca_cert.subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.datetime.utcnow() - datetime.timedelta(minutes=1))
        .not_valid_after(datetime.datetime.utcnow() + datetime.timedelta(days=365))
    )
    if role.lower() == "server":
        builder = builder.add_extension(x509.SubjectAlternativeName([x509.DNSName(cn)]), critical=False)
    cert = builder.sign(private_key=ca_key, algorithm=hashes.SHA256())

    key_pem = key.private_bytes(serialization.Encoding.PEM,
                                serialization.PrivateFormat.TraditionalOpenSSL,
                                serialization.NoEncryption())
    cert_pem = cert.public_bytes(serialization.Encoding.PEM)
    key_path = os.path.join(PRIV_DIR, f"{cn}_key.pem")
    cert_path = os.path.join(OUT_DIR, f"{cn}.pem")
    with open(key_path, "wb") as f:
        f.write(key_pem)
    with open(cert_path, "wb") as f:
        f.write(cert_pem)
    print(f"Wrote {cert_path} and {key_path}")

if __name__ == "__main__":
    main()
