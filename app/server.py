"""Server skeleton — plain TCP; no TLS. See assignment spec."""

import socket
import json
import hashlib
from dotenv import load_dotenv
from app.common.protocol import (
    Hello, ServerHello, Register, Login, DhClient, DhServer, Msg, Receipt
)
from app.common.utils import b64d, b64e, now_ms
from app.crypto.pki import load_cert, verify_cert, get_cert_fingerprint
from app.crypto.dh import dh_generate, dh_derive_key
from app.crypto.aes import aes_encrypt, aes_decrypt
from app.crypto.sign import rsa_verify_b64, rsa_sign_b64
from app.storage.db import get_user, verify_password, create_user
from app.storage.transcript import Transcript

# Load environment variables from .env file if it exists
load_dotenv()


def send(sock, obj):
    sock.sendall((json.dumps(obj) + "\n").encode())


def recv(sock):
    return json.loads(sock.makefile().readline())


def main():
    host = "0.0.0.0"
    port = 9000

    srv = socket.socket()
    srv.bind((host, port))
    srv.listen(5)
    print("Server ready.")

    while True:
        conn, addr = srv.accept()
        print("Client:", addr)

        f = conn.makefile()

        # -------------------- HELLO -------------------- #
        try:
            h = Hello(**json.loads(f.readline()))
        except Exception as e:
            print(f"❌ Failed to parse Hello message: {e}")
            conn.close()
            continue
            
        try:
            client_cert = load_cert(h.cert)
        except Exception as e:
            print(f"❌ Failed to load client certificate: {e}")
            conn.close()
            continue
            
        try:
            if not verify_cert(client_cert):
                print("❌ Client certificate verification failed")
                conn.close()
                continue
        except Exception as e:
            error_msg = str(e)
            if "BAD CERT" in error_msg.upper() or "UNTRUSTED" in error_msg.upper() or "EXPIRED" in error_msg.upper():
                print(f"BAD CERT: {e}")
            else:
                print(f"❌ Certificate verification error: {e}")
            conn.close()
            continue

        try:
            my_cert = open("certs/server_cert.pem").read()
        except FileNotFoundError:
            print("❌ Server certificate not found: certs/server_cert.pem")
            print("   Generate certificates with: python setup_certs.py")
            conn.close()
            continue
            
        send(conn, ServerHello(cert=my_cert, nonce=h.nonce).model_dump())
        print("✓ Sent ServerHello")

        # -------------------- DH -------------------- #
        dc = DhClient(**recv(conn))
        g, p, b, B = dh_generate(dp=(dc.g, dc.p))
        send(conn, DhServer(B=B).model_dump())

        K = dh_derive_key(b, dc.A, p)  # my_priv=b, their_pub=A

        # -------------------- AUTH -------------------- #
        auth_msg = recv(conn)
        
        if auth_msg.get("type") == "register":
            # Handle registration
            register_msg = Register(**auth_msg)
            creds = json.loads(aes_decrypt(K, b64d(register_msg.pwd_hash_b64)))
            email = creds.get("email", register_msg.email)
            username = creds.get("username", register_msg.username)
            password = creds.get("password", "")
            
            # Check if user already exists
            if get_user(username):
                send(conn, {"status": "fail", "error": "Username already exists"})
                conn.close()
                continue
            
            # Create new user
            if create_user(email, username, password):
                send(conn, {"status": "ok", "message": "Registration successful"})
                print(f"✓ New user registered: {username}")
            else:
                send(conn, {"status": "fail", "error": "Registration failed"})
                conn.close()
                continue
                
        elif auth_msg.get("type") == "login":
            # Handle login
            login_msg = Login(**auth_msg)
            creds = json.loads(aes_decrypt(K, b64d(login_msg.pwd_hash_b64)))
            username = creds["username"]
            password = creds["password"]

            user = get_user(username)
            if not user or not verify_password(user, password):
                send(conn, {"status": "fail"})
                conn.close()
                continue
        else:
            send(conn, {"status": "fail", "error": "Invalid auth message type"})
            conn.close()
            continue

        send(conn, {"status": "ok"})

        # -------------------- CHAT LOOP -------------------- #
        t = Transcript(f"server_{username}")
        last_client_seq = 0  # Track client sequence numbers for replay protection
        client_fingerprint = get_cert_fingerprint(client_cert)
        
        while True:
            try:
                incoming = recv(conn)
            except:
                break

            if incoming.get("type") == "receipt":
                # Client sent receipt, verify it
                receipt = Receipt(**incoming)
                receipt_hash = bytes.fromhex(receipt.transcript_sha256)
                if rsa_verify_b64(receipt_hash, receipt.sig, cert=client_cert):
                    print(f"✓ Client SessionReceipt verified:")
                    print(f"  First seq: {receipt.first_seq}, Last seq: {receipt.last_seq}")
                break

            if incoming["type"] != "msg":
                break

            msg = Msg(**incoming)

            # Verify sequence number is strictly increasing (replay protection)
            if msg.seqno <= last_client_seq:
                print("REPLAY: Sequence number not increasing (replay attack detected)")
                break
            last_client_seq = msg.seqno

            # Verify timestamp (reject stale messages - 5 minute window)
            current_time = now_ms()
            time_diff = abs(current_time - msg.ts)
            if time_diff > 5 * 60 * 1000:  # 5 minutes
                print("❌ Stale message detected")
                break

            # Verify signature over SHA256(seqno || ts || ct)
            hash_data = hashlib.sha256(f"{msg.seqno}{msg.ts}{msg.ct}".encode()).digest()
            if not rsa_verify_b64(hash_data, msg.sig, cert=client_cert):
                print("SIG FAIL: Signature verification failed")
                break

            # Decrypt message
            pt = aes_decrypt(K, b64d(msg.ct))
            mtext = pt.decode()
            
            # Append to transcript: seqno | timestamp | ciphertext | sig | peer-cert-fingerprint
            t.append(msg.seqno, msg.ts, msg.ct, msg.sig, client_fingerprint)

            # Prepare server reply
            reply = f"echo: {mtext}"
            reply_ct = b64e(aes_encrypt(K, reply.encode()))
            reply_ts = now_ms()
            reply_seq = msg.seqno + 1
            
            # Sign server message: SHA256(seqno || ts || ct)
            reply_hash = hashlib.sha256(f"{reply_seq}{reply_ts}{reply_ct}".encode()).digest()
            reply_sig = rsa_sign_b64(reply_hash, key_path="certs/private/server_cert_key.pem")
            
            out = Msg(type="msg", seqno=reply_seq, ts=reply_ts, ct=reply_ct, sig=reply_sig)
            send(conn, out.model_dump())
            
            # Append server message to transcript
            server_cert_obj = load_cert(open("certs/server_cert.pem").read())
            server_fingerprint = get_cert_fingerprint(server_cert_obj)
            t.append(reply_seq, reply_ts, reply_ct, reply_sig, server_fingerprint)

        # -------------------- SESSION RECEIPT (NON-REPUDIATION) -------------------- #
        # Generate and send server receipt (only if there are messages in transcript)
        first_seq, last_seq = t.seq_range()
        
        # Only generate receipt if we have messages in transcript
        if first_seq is not None and last_seq is not None:
            transcript_hash = t.final_hash_hex()
            
            # Sign the transcript hash (convert hex string to bytes for signing)
            transcript_hash_bytes = bytes.fromhex(transcript_hash)
            receipt_sig = rsa_sign_b64(transcript_hash_bytes, key_path="certs/private/server_cert_key.pem")
            
            receipt = Receipt(
                peer="server",
                first_seq=first_seq,
                last_seq=last_seq,
                transcript_sha256=transcript_hash,
                sig=receipt_sig
            )
            
            # Send receipt to client
            try:
                send(conn, receipt.model_dump())
                print(f"✓ Server SessionReceipt generated and sent:")
                print(f"  First seq: {first_seq}, Last seq: {last_seq}")
                print(f"  Transcript hash: {transcript_hash}")
            except:
                pass  # Connection may be closed
        else:
            print("⚠ No messages in transcript - skipping receipt generation")

        conn.close()


if __name__ == "__main__":
    main()
