"""
X.509 validation helpers.
Provides verify_cert(peer_pem_bytes, ca_pem_path, expected_cn)
"""
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding
import datetime

def load_cert(pem_bytes):
    """Load certificate from PEM bytes (string or bytes)."""
    if isinstance(pem_bytes, str):
        pem_bytes = pem_bytes.encode()
    return x509.load_pem_x509_certificate(pem_bytes)

def get_cn(cert: x509.Certificate):
    attrs = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
    return attrs[0].value if attrs else None

def get_cert_fingerprint(cert: x509.Certificate) -> str:
    """Return SHA-256 fingerprint of certificate as hex string."""
    from cryptography.hazmat.primitives import hashes
    return cert.fingerprint(hashes.SHA256()).hex()

def verify_cert(peer_cert_or_pem, ca_pem_path: str = "certs/ca.pem", expected_cn: str = None):
    """
    Verify a certificate.
    peer_cert_or_pem: Either a x509.Certificate object or PEM bytes/string
    ca_pem_path: Path to CA certificate (default: "certs/ca.pem")
    expected_cn: Optional expected common name
    """
    # Handle both certificate object and PEM bytes
    if isinstance(peer_cert_or_pem, x509.Certificate):
        peer_cert = peer_cert_or_pem
    else:
        peer_cert = load_cert(peer_cert_or_pem)
    
    ca_cert = x509.load_pem_x509_certificate(open(ca_pem_path, "rb").read())
    # verify signature chain: try verifying peer signature with CA pubkey
    try:
        # Get the signature algorithm from the certificate
        sig_algorithm = peer_cert.signature_algorithm_oid
        hash_algorithm = peer_cert.signature_hash_algorithm
        
        # Use appropriate padding and hash algorithm
        if hash_algorithm is None:
            # Fallback to SHA256 if not specified
            hash_algorithm = hashes.SHA256()
        
        ca_cert.public_key().verify(
            peer_cert.signature,
            peer_cert.tbs_certificate_bytes,
            padding.PKCS1v15(),
            hash_algorithm
        )
    except Exception as e:
        raise ValueError(f"BAD CERT: UNTRUSTED or signature invalid ({e})")
    # validity period
    now = datetime.datetime.now(datetime.timezone.utc)
    if peer_cert.not_valid_before_utc > now or peer_cert.not_valid_after_utc < now:
        raise ValueError("BAD CERT: EXPIRED/NOT YET VALID")
    # CN match if provided
    if expected_cn:
        cn = get_cn(peer_cert)
        if cn != expected_cn:
            raise ValueError(f"BAD CERT: CN MISMATCH (got {cn}, expected {expected_cn})")
    return True
