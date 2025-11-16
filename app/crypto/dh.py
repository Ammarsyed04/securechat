"""
Classic DH helpers and key derivation:
K = Trunc16(SHA256(big-endian(Ks)))
"""
import secrets
from hashlib import sha256

# Use a 2048-bit safe prime (RFC 3526 group 14) simplified as integer literal for brevity.
# For production choose verified primes; here we use a moderately sized prime for assignment.
RFC_2048_P = int(
    "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA6"
    "3B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245"
    "E485B576625E7EC6F44C42E9A63A36210000000000090563", 16
)
G = 2
P = RFC_2048_P

def gen_private():
    return secrets.randbits(256)  # sufficient for assignment

def pub_from_priv(priv):
    return pow(G, priv, P)

def compute_session_key(their_pub: int, my_priv: int, p: int) -> bytes:
    """Compute session key using the provided prime p."""
    ks = pow(their_pub, my_priv, p)
    # big-endian bytes of ks
    b = ks.to_bytes((ks.bit_length() + 7) // 8 or 1, "big")
    k = sha256(b).digest()[:16]
    return k
    
def dh_generate(dp=None):
    """
    Generate a private/public key pair.
    If dp is provided as (g, p), use those values; otherwise use default G, P.
    Returns: (g, p, priv, pub)
    """
    if dp is not None:
        g, p = dp
    else:
        g, p = G, P
    
    priv = gen_private()
    pub = pow(g, priv, p)
    return g, p, priv, pub

def dh_derive_key(my_priv: int, their_pub: int, p: int = None) -> bytes:
    """
    Derive a session key from private and peer public key.
    If p is not provided, uses the default global P.
    """
    if p is None:
        p = P
    return compute_session_key(their_pub, my_priv, p)
