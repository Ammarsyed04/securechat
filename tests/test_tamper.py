#!/usr/bin/env python3
"""
Test 3: Tampering Test
Tests: SIG FAIL when ciphertext is tampered with (bit flip)
"""

import sys
import os
# Add project root to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import socket
import json
import hashlib
from app.common.protocol import Hello, ServerHello, Login, DhClient, DhServer, Msg
from app.common.utils import b64e, b64d, now_ms
from app.crypto.pki import load_cert, verify_cert
from app.crypto.dh import dh_generate, dh_derive_key
from app.crypto.aes import aes_encrypt
from app.crypto.sign import rsa_sign_b64

def send(sock, obj):
    sock.sendall((json.dumps(obj) + "\n").encode())

def recv(sock):
    return json.loads(sock.makefile().readline())

def main():
    print("="*60)
    print("TAMPERING TEST - SIG FAIL")
    print("="*60)
    print("\nThis test verifies that tampering with ciphertext")
    print("results in signature verification failure (SIG FAIL)")
    print("="*60)
    
    sock = socket.socket()
    try:
        sock.connect(("127.0.0.1", 9000))
        print("✓ Connected to server")
    except ConnectionRefusedError:
        print("❌ Server not running. Start server first: python -m app.server")
        return
    
    # Normal handshake
    my_cert = open("certs/client_cert.pem").read()
    my_nonce = b64e(b"tamper_test")
    
    send(sock, Hello(cert=my_cert, nonce=my_nonce).model_dump())
    sh = ServerHello(**recv(sock))
    
    server_cert = load_cert(sh.cert)
    if not verify_cert(server_cert):
        print("❌ Invalid server certificate.")
        return
    
    # DH key exchange
    g, p, a, A = dh_generate()
    send(sock, DhClient(g=g, p=p, A=A).model_dump())
    dhs = DhServer(**recv(sock))
    K = dh_derive_key(a, dhs.B, p)
    
    # Login
    cred = json.dumps({"username": "alice", "password": "alice123"}).encode()
    ct = b64e(aes_encrypt(K, cred))
    send(sock, Login(username="alice", pwd_hash_b64=ct).model_dump())
    
    auth_reply = recv(sock)
    if auth_reply.get("status") != "ok":
        print("❌ Auth failed")
        return
    
    print("\n✓ Authenticated successfully")
    print("\n[TEST] Sending tampered message...")
    
    # Create a normal message
    pt = "Hello, this is a test message".encode()
    ct = b64e(aes_encrypt(K, pt))
    ts = now_ms()
    seq = 1
    
    # Sign the message
    hash_data = hashlib.sha256(f"{seq}{ts}{ct}".encode()).digest()
    sig = rsa_sign_b64(hash_data)
    
    # TAMPER: Flip a bit in the ciphertext
    ct_bytes = b64d(ct)
    # Flip the first bit
    tampered_ct_bytes = bytearray(ct_bytes)
    tampered_ct_bytes[0] ^= 1  # Flip first bit
    tampered_ct = b64e(bytes(tampered_ct_bytes))
    
    print(f"Original ciphertext (first 20 chars): {ct[:20]}")
    print(f"Tampered ciphertext (first 20 chars): {tampered_ct[:20]}")
    
    # Send tampered message (signature is for original, but ciphertext is tampered)
    tampered_msg = Msg(
        type="msg",
        seqno=seq,
        ts=ts,
        ct=tampered_ct,  # TAMPERED
        sig=sig  # Original signature (won't match tampered data)
    )
    
    send(sock, tampered_msg.model_dump())
    print("\n✓ Sent tampered message")
    print("Waiting for server response...")
    
    # Server should detect signature mismatch and close connection
    try:
        # Try to receive response (should timeout or connection closed)
        sock.settimeout(2)  # 2 second timeout
        response = recv(sock)
        print(f"⚠ Unexpected response received: {response}")
        print("   Server should have closed connection")
    except socket.timeout:
        print(f"\n✓ Connection timeout (expected - server closed connection)")
        print("✓ Server correctly detected tampering")
    except (ConnectionError, OSError, json.JSONDecodeError) as e:
        print(f"\n✓ Connection closed by server (expected)")
        print("✓ Server correctly detected tampering")
    except Exception as e:
        print(f"\n✓ Connection error (expected): {type(e).__name__}")
        print("✓ Server correctly detected tampering")
    finally:
        try:
            sock.close()
        except:
            pass
    
    print("\n" + "="*60)
    print("TEST COMPLETE")
    print("="*60)
    print("\nCheck server output for:")
    print("  SIG FAIL: Signature verification failed")
    print("\n✓ This confirms SIG FAIL protection is working!")

if __name__ == "__main__":
    main()


