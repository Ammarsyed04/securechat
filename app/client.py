"""Client skeleton — plain TCP; no TLS. See assignment spec."""

import socket
import json
from app.common.protocol import (
    Hello, ServerHello, Register, Login, DhClient, DhServer, Msg
)
import hashlib
from app.common.utils import now_ms, b64e, b64d
from app.crypto.pki import load_cert, verify_cert, get_cert_fingerprint
from app.crypto.dh import dh_generate, dh_derive_key
from app.crypto.aes import aes_encrypt, aes_decrypt
from app.crypto.sign import rsa_sign_b64, rsa_verify_b64
from app.storage.transcript import Transcript
from app.common.protocol import Receipt


def send(sock, obj):
    sock.sendall((json.dumps(obj) + "\n").encode())


def recv(sock):
    try:
        line = sock.makefile().readline()
        if not line or line.strip() == "":
            raise ConnectionError("Server closed connection or sent empty response")
        return json.loads(line)
    except json.JSONDecodeError as e:
        print(f"❌ Failed to parse server response: {e}")
        print(f"   Received: {line[:100] if line else 'empty'}")
        raise


def main():
    host = "127.0.0.1"
    port = 9000
    username = "alice"
    password = "alice123"

    sock = socket.socket()
    try:
        sock.connect((host, port))
        print("✓ Connected to server")
    except ConnectionRefusedError:
        print("❌ Connection refused. Is the server running?")
        print("   Start the server with: python -m app.server")
        return
    except Exception as e:
        print(f"❌ Connection error: {e}")
        return

    # -------------------- HELLO + CERT -------------------- #
    try:
        my_cert = open("certs/client_cert.pem").read()
    except FileNotFoundError:
        print("❌ Certificate not found: certs/client_cert.pem")
        print("   Generate certificates with: python setup_certs.py")
        return
    my_nonce = b64e(b"xyz123")

    send(sock, Hello(cert=my_cert, nonce=my_nonce).model_dump())
    sh = ServerHello(**recv(sock))

    server_cert = load_cert(sh.cert)
    if not verify_cert(server_cert):
        print("❌ Invalid server certificate.")
        return

    # -------------------- DIFFIE–HELLMAN -------------------- #
    g, p, a, A = dh_generate()
    send(sock, DhClient(g=g, p=p, A=A).model_dump())

    dhs = DhServer(**recv(sock))
    K = dh_derive_key(a, dhs.B, p)  # my_priv=a, their_pub=B

    # -------------------- AUTH -------------------- #
    cred = json.dumps({"username": username, "password": password}).encode()
    ct = b64e(aes_encrypt(K, cred))

    send(sock, Login(username=username, pwd_hash_b64=ct).model_dump())

    auth_reply = recv(sock)
    if auth_reply.get("status") != "ok":
        print("❌ auth failed")
        return

    # -------------------- CHAT LOOP -------------------- #
    t = Transcript("client_session")
    seq = 1
    last_server_seq = 0  # Track server sequence numbers for replay protection

    while True:
        m = input("msg> ")
        if m == "exit":
            break

        # Encrypt message
        pt = m.encode()
        ct = b64e(aes_encrypt(K, pt))
        ts = now_ms()
        
        # Sign SHA256(seqno || timestamp || ciphertext) as per spec
        hash_data = hashlib.sha256(f"{seq}{ts}{ct}".encode()).digest()
        sig = rsa_sign_b64(hash_data)

        msg = Msg(type="msg", seqno=seq, ts=ts, ct=ct, sig=sig)
        send(sock, msg.model_dump())

        # Append to transcript: seqno | timestamp | ciphertext | sig | peer-cert-fingerprint
        server_fingerprint = get_cert_fingerprint(server_cert)
        t.append(seq, ts, ct, sig, server_fingerprint)
        seq += 1

        # Receive and verify server response
        resp = recv(sock)
        if resp.get("type") == "msg":
            # Verify sequence number is strictly increasing
            if resp["seqno"] <= last_server_seq:
                print("❌ Replay attack detected - server sequence number not increasing")
                break
            last_server_seq = resp["seqno"]
            
            # Verify timestamp (reject stale messages - 5 minute window)
            current_time = now_ms()
            time_diff = abs(current_time - resp["ts"])
            if time_diff > 5 * 60 * 1000:  # 5 minutes
                print("❌ Stale message detected")
                break
            
            # Verify signature over SHA256(seqno || ts || ct)
            resp_hash = hashlib.sha256(f"{resp['seqno']}{resp['ts']}{resp['ct']}".encode()).digest()
            if not rsa_verify_b64(resp_hash, resp["sig"], cert=server_cert):
                print("❌ Server signature verification failed")
                break
            
            # Decrypt and display
            dec = aes_decrypt(K, b64d(resp["ct"])).decode()
            
            # Append server message to transcript
            t.append(resp["seqno"], resp["ts"], resp["ct"], resp["sig"], server_fingerprint)
            print("[server]", dec)

    # -------------------- SESSION RECEIPT (NON-REPUDIATION) -------------------- #
    first_seq, last_seq = t.seq_range()
    transcript_hash = t.final_hash_hex()
    
    # Sign the transcript hash
    transcript_hash_bytes = bytes.fromhex(transcript_hash)
    receipt_sig = rsa_sign_b64(transcript_hash_bytes)
    
    receipt = Receipt(
        peer="client",
        first_seq=first_seq,
        last_seq=last_seq,
        transcript_sha256=transcript_hash,
        sig=receipt_sig
    )
    
    # Send receipt to server
    send(sock, receipt.model_dump())
    print(f"\n✓ Client SessionReceipt sent:")
    print(f"  First seq: {first_seq}, Last seq: {last_seq}")
    print(f"  Transcript hash: {transcript_hash}")
    
    # Receive and verify server receipt
    try:
        server_receipt_data = recv(sock)
        if server_receipt_data.get("type") == "receipt":
            server_receipt = Receipt(**server_receipt_data)
            server_receipt_hash = bytes.fromhex(server_receipt.transcript_sha256)
            if rsa_verify_b64(server_receipt_hash, server_receipt.sig, cert=server_cert):
                print(f"✓ Server SessionReceipt verified:")
                print(f"  First seq: {server_receipt.first_seq}, Last seq: {server_receipt.last_seq}")
                print(f"  Transcript hash: {server_receipt.transcript_sha256}")
            else:
                print("❌ Server receipt signature verification failed")
    except:
        pass  # Server may have closed connection
    
    sock.close()


if __name__ == "__main__":
    main()
