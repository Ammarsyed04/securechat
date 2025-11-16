"""Pydantic models: hello, server_hello, register, login, dh_client, dh_server, msg, receipt."""

from pydantic import BaseModel
from typing import Optional


# -------------------- HELLO PHASE -------------------- #

class Hello(BaseModel):
    type: str = "hello"
    cert: str          # PEM certificate as string
    nonce: str         # base64 nonce


class ServerHello(BaseModel):
    type: str = "server_hello"
    cert: str          # PEM certificate as string
    nonce: str         # base64 nonce


# -------------------- REGISTRATION / LOGIN -------------------- #

class Register(BaseModel):
    type: str = "register"
    email: str
    username: str
    pwd_hash_b64: str    # base64(sha256(salt||pwd))
    salt_b64: str        # base64(salt)


class Login(BaseModel):
    type: str = "login"
    email: Optional[str] = None
    username: str
    pwd_hash_b64: str
    salt_b64: Optional[str] = None


# -------------------- DIFFIE–HELLMAN -------------------- #

class DhClient(BaseModel):
    type: str = "dh_client"
    g: int
    p: int
    A: int    # client public value


class DhServer(BaseModel):
    type: str = "dh_server"
    B: int    # server public value


# -------------------- SECURE MESSAGE -------------------- #

class Msg(BaseModel):
    type: str = "msg"
    seqno: int
    ts: int
    ct: str     # base64 ciphertext
    sig: str    # base64 RSA signature


# -------------------- RECEIPT (NON-REPUDIATION) -------------------- #

class Receipt(BaseModel):
    type: str = "receipt"
    peer: str               # "client" or "server"
    first_seq: int
    last_seq: int
    transcript_sha256: str
    sig: str                # base64 RSA signature
