"""MySQL users table + salted hashing (no chat storage)."""

import os
import hmac
import hashlib
import secrets
import mysql.connector
from mysql.connector import Error


# -------------------- CONNECTION HELPERS -------------------- #

def get_conn():
    """Create a new MySQL connection using environment variables."""
    return mysql.connector.connect(
        host=os.getenv("DB_HOST", "127.0.0.1"),
        port=int(os.getenv("DB_PORT", 3306)),
        user=os.getenv("DB_USER", "root"),
        password=os.getenv("DB_PASS", ""),
        database=os.getenv("DB_NAME", "securechat")
    )


# -------------------- SCHEMA INITIALIZATION -------------------- #

def init_schema():
    """Create users table if it doesn't exist."""
    conn = get_conn()
    cur = conn.cursor()
    cur.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INT AUTO_INCREMENT PRIMARY KEY,
            email VARCHAR(255),
            username VARCHAR(100) UNIQUE,
            salt BINARY(16),
            pwd_hash CHAR(64)
        )
    """)
    conn.commit()
    cur.close()
    conn.close()


# -------------------- PASSWORD HASHING (salt || password) -------------------- #

def hash_password(salt: bytes, password: str) -> str:
    """Return hex(SHA256(salt || password))."""
    return hashlib.sha256(salt + password.encode()).hexdigest()


# -------------------- USER MANAGEMENT -------------------- #

def create_user(email: str, username: str, password: str) -> bool:
    """
    Create a new user with:
      • random 16-byte salt
      • store hex(SHA256(salt||password))
    """
    salt = secrets.token_bytes(16)
    pwd_hash = hash_password(salt, password)

    conn = get_conn()
    cur = conn.cursor()

    try:
        cur.execute(
            "INSERT INTO users (email, username, salt, pwd_hash) VALUES (%s, %s, %s, %s)",
            (email, username, salt, pwd_hash)
        )
        conn.commit()
        return True
    except Error:
        return False
    finally:
        cur.close()
        conn.close()


def get_user(username: str):
    """Return user record or None."""
    conn = get_conn()
    cur = conn.cursor()

    cur.execute(
        "SELECT id, email, username, salt, pwd_hash FROM users WHERE username = %s",
        (username,)
    )

    row = cur.fetchone()
    cur.close()
    conn.close()

    if not row:
        return None

    return {
        "id": row[0],
        "email": row[1],
        "username": row[2],
        "salt": row[3],
        "pwd_hash": row[4]
    }


def verify_password(user_record: dict, provided_password: str) -> bool:
    """
    Constant-time password verification.
    Recompute SHA256(salt || provided_password)
    and compare with stored hex hash safely.
    """
    salt = user_record["salt"]
    stored_hash = user_record["pwd_hash"]

    recomputed = hash_password(salt, provided_password)
    return hmac.compare_digest(stored_hash, recomputed)
