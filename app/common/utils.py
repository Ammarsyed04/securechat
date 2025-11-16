"""Helper signatures: now_ms, b64e, b64d, sha256_hex."""

import time
import base64
import hashlib


def now_ms() -> int:
    """Return current timestamp in milliseconds."""
    return int(time.time() * 1000)


def b64e(b: bytes) -> str:
    """Base64-encode bytes → UTF-8 string."""
    return base64.b64encode(b).decode()


def b64d(s: str) -> bytes:
    """Base64-decode UTF-8 string → bytes."""
    return base64.b64decode(s)


def sha256_hex(data: bytes) -> str:
    """Return SHA-256 hex digest of bytes."""
    return hashlib.sha256(data).hexdigest()
