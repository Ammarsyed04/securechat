#!/usr/bin/env python3
"""
Generate a root CA (RSA key + self-signed X.509 cert).
Writes:
  certs/ca.pem
  certs/private/ca_key.pem
"""
import os
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography import x509
from cryptography.x509.oid import NameOID
import datetime

OUT_DIR = "certs"
PRIV_DIR = os.path.join(OUT_DIR, "private")
os.makedirs(PRIV_DIR, exist_ok=True)

def main():
    key = rsa.generate_private_key(public_exponent=65537, key_size=4096)
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, u"PK"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"FAST-NUCES-CA"),
        x509.NameAttribute(NameOID.COMMON_NAME, u"FAST-NUCES Root CA"),
    ])
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.datetime.utcnow() - datetime.timedelta(days=1))
        .not_valid_after(datetime.datetime.utcnow() + datetime.timedelta(days=3650))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(key, hashes.SHA256())
    )

    key_pem = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
    )
    cert_pem = cert.public_bytes(serialization.Encoding.PEM)

    with open(os.path.join(PRIV_DIR, "ca_key.pem"), "wb") as f:
        f.write(key_pem)
    with open(os.path.join(OUT_DIR, "ca.pem"), "wb") as f:
        f.write(cert_pem)

    print("Wrote certs/ca.pem and certs/private/ca_key.pem")

if __name__ == "__main__":
    main()
