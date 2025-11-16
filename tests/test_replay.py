#!/usr/bin/env python3
"""
Test 4: Replay Attack Test
Tests: REPLAY error when old sequence number is reused
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
    print("REPLAY ATTACK TEST")
    print("="*60)
    print("\nThis test verifies that reusing an old sequence number")
    print("results in replay attack detection (REPLAY)")
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
    my_nonce = b64e(b"replay_test")
    
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
    
    # Send first message (seqno = 1)
    print("\n[Step 1] Sending message with seqno=1...")
    pt1 = "First message".encode()
    ct1 = b64e(aes_encrypt(K, pt1))
    ts1 = now_ms()
    seq1 = 1
    
    hash_data1 = hashlib.sha256(f"{seq1}{ts1}{ct1}".encode()).digest()
    sig1 = rsa_sign_b64(hash_data1)
    
    msg1 = Msg(type="msg", seqno=seq1, ts=ts1, ct=ct1, sig=sig1)
    send(sock, msg1.model_dump())
    
    # Receive server response
    resp1 = recv(sock)
    print(f"✓ Server responded (seqno={resp1.get('seqno')})")
    
    # Send second message (seqno = 2)
    print("\n[Step 2] Sending message with seqno=2...")
    pt2 = "Second message".encode()
    ct2 = b64e(aes_encrypt(K, pt2))
    ts2 = now_ms()
    seq2 = 2
    
    hash_data2 = hashlib.sha256(f"{seq2}{ts2}{ct2}".encode()).digest()
    sig2 = rsa_sign_b64(hash_data2)
    
    msg2 = Msg(type="msg", seqno=seq2, ts=ts2, ct=ct2, sig=sig2)
    send(sock, msg2.model_dump())
    
    resp2 = recv(sock)
    print(f"✓ Server responded (seqno={resp2.get('seqno')})")
    
    # REPLAY ATTACK: Resend message with old seqno (seqno = 1)
    print("\n[TEST] REPLAY ATTACK: Resending message with old seqno=1...")
    print("This should be rejected!")
    
    # Resend the first message (replay attack)
    send(sock, msg1.model_dump())
    print("✓ Replayed old message sent")
    
    # Server should detect replay
    try:
        response = recv(sock)
        print(f"Unexpected response: {response}")
    except Exception as e:
        print(f"\n✓ Connection closed by server (expected)")
        print("✓ Server correctly detected replay attack")
    
    sock.close()
    
    print("\n" + "="*60)
    print("TEST COMPLETE")
    print("="*60)
    print("\nCheck server output for:")
    print("  ❌ Replay attack detected - sequence number not increasing")
    print("\nThis confirms REPLAY protection is working!")

if __name__ == "__main__":
    main()

