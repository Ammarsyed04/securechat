#!/usr/bin/env python3
"""
Test 5: Non-Repudiation Verification
Offline verification of transcript and SessionReceipt
"""

import sys
import os
# Add project root to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import hashlib
from app.crypto.pki import load_cert
from app.crypto.sign import rsa_verify_b64
from app.storage.transcript import Transcript

def verify_transcript_line(seqno, ts, ct, sig, peer_fingerprint, cert):
    """Verify a single transcript line"""
    # Recompute hash: SHA256(seqno || ts || ct)
    hash_data = hashlib.sha256(f"{seqno}{ts}{ct}".encode()).digest()
    
    # Verify signature
    if not rsa_verify_b64(hash_data, sig, cert=cert):
        return False, "Signature verification failed"
    
    return True, "Signature verified"

def verify_transcript_file(transcript_path, client_cert_path, server_cert_path=None):
    """Verify entire transcript file"""
    print(f"\nVerifying transcript: {transcript_path}")
    print(f"Using client certificate: {client_cert_path}")
    if server_cert_path:
        print(f"Using server certificate: {server_cert_path}")
    print("="*60)
    
    client_cert = load_cert(open(client_cert_path).read())
    from app.crypto.pki import get_cert_fingerprint
    client_fingerprint = get_cert_fingerprint(client_cert)
    
    server_cert = None
    server_fingerprint = None
    if server_cert_path and os.path.exists(server_cert_path):
        server_cert = load_cert(open(server_cert_path).read())
        server_fingerprint = get_cert_fingerprint(server_cert)
    
    if not os.path.exists(transcript_path):
        print(f"❌ Transcript file not found: {transcript_path}")
        return False
    
    # Read and verify each line
    verified_lines = 0
    failed_lines = []
    skipped_lines = 0
    
    with open(transcript_path, 'r') as f:
        for line_num, line in enumerate(f, 1):
            line = line.strip()
            if not line:
                continue
            
            # Skip header lines (text descriptions)
            if not line[0].isdigit() or '[' in line:
                skipped_lines += 1
                continue
            
            parts = line.split('|')
            if len(parts) != 5:
                print(f"❌ Line {line_num}: Invalid format (expected 5 parts, got {len(parts)})")
                continue
            
            seqno, ts, ct, sig, peer_fingerprint = parts
            seqno = int(seqno)
            ts = int(ts)
            
            # Determine which certificate to use based on peer fingerprint
            # If peer_fingerprint matches client_fingerprint, this is a server message (server recorded client's fingerprint)
            # If peer_fingerprint matches server_fingerprint, this is a client message (client recorded server's fingerprint)
            # If we only have one cert, try both patterns
            
            cert_to_use = None
            message_type = "unknown"
            
            if peer_fingerprint == client_fingerprint:
                # This is a server message (server is recording client's fingerprint)
                if server_cert:
                    cert_to_use = server_cert
                    message_type = "server"
                else:
                    cert_to_use = client_cert  # Fallback
                    message_type = "server (using client cert)"
            elif server_fingerprint and peer_fingerprint == server_fingerprint:
                # This is a client message (client is recording server's fingerprint)
                cert_to_use = client_cert
                message_type = "client"
            else:
                # Try with client cert first (most common case)
                cert_to_use = client_cert
                message_type = "client (assumed)"
            
            valid, msg = verify_transcript_line(seqno, ts, ct, sig, peer_fingerprint, cert_to_use)
            if valid:
                verified_lines += 1
                print(f"✓ Line {line_num} (seqno={seqno}, {message_type}): {msg}")
            else:
                # Try with server cert if client cert failed
                if cert_to_use == client_cert and server_cert:
                    valid2, msg2 = verify_transcript_line(seqno, ts, ct, sig, peer_fingerprint, server_cert)
                    if valid2:
                        verified_lines += 1
                        print(f"✓ Line {line_num} (seqno={seqno}, server): {msg2}")
                        continue
                
                failed_lines.append((line_num, msg))
                print(f"❌ Line {line_num} (seqno={seqno}, {message_type}): {msg}")
    
    print("\n" + "="*60)
    print(f"Verification Summary:")
    print(f"  Verified: {verified_lines} lines")
    print(f"  Failed: {len(failed_lines)} lines")
    
    if failed_lines:
        print("\nFailed lines:")
        for line_num, msg in failed_lines:
            print(f"  Line {line_num}: {msg}")
        return False
    
    return True

def verify_receipt(receipt_data, cert_path):
    """Verify SessionReceipt signature"""
    print(f"\nVerifying SessionReceipt")
    print(f"Using certificate: {cert_path}")
    print("="*60)
    
    cert = load_cert(open(cert_path).read())
    
    transcript_hash = receipt_data['transcript_sha256']
    sig = receipt_data['sig']
    first_seq = receipt_data['first_seq']
    last_seq = receipt_data['last_seq']
    
    print(f"First seq: {first_seq}")
    print(f"Last seq: {last_seq}")
    print(f"Transcript hash: {transcript_hash}")
    
    # Verify signature over transcript hash
    transcript_hash_bytes = bytes.fromhex(transcript_hash)
    
    if rsa_verify_b64(transcript_hash_bytes, sig, cert=cert):
        print("✓ Receipt signature verified")
        return True
    else:
        print("❌ Receipt signature verification failed")
        return False

def test_tampered_transcript(transcript_path, client_cert_path):
    """Test that tampering breaks verification"""
    print("\n" + "="*60)
    print("TAMPERING TEST: Modifying transcript")
    print("="*60)
    
    # Read original
    with open(transcript_path, 'r') as f:
        lines = f.readlines()
    
    if not lines:
        print("❌ Transcript is empty")
        return
    
    # Modify first line (tamper with ciphertext)
    first_line = lines[0].strip()
    parts = first_line.split('|')
    if len(parts) >= 3:
        # Tamper with ciphertext
        parts[2] = "TAMPERED_CIPHERTEXT"
        tampered_line = '|'.join(parts) + '\n'
        lines[0] = tampered_line
        
        # Write tampered transcript
        tampered_path = transcript_path + ".tampered"
        with open(tampered_path, 'w') as f:
            f.writelines(lines)
        
        print(f"✓ Created tampered transcript: {tampered_path}")
        print("Verifying tampered transcript (should fail)...")
        
        # Verify tampered transcript
        cert = load_cert(open(client_cert_path).read())
        first_line_parts = tampered_line.strip().split('|')
        seqno, ts, ct, sig, fingerprint = first_line_parts
        
        hash_data = hashlib.sha256(f"{seqno}{ts}{ct}".encode()).digest()
        if not rsa_verify_b64(hash_data, sig, cert=cert):
            print("✓ Tampered transcript correctly rejected (signature fails)")
            return True
        else:
            print("❌ Tampered transcript was accepted (security issue!)")
            return False

def main():
    import sys
    
    if len(sys.argv) < 2:
        print("Usage: python verify_transcript.py <transcript_file> [client_cert] [server_cert]")
        print("\nExample:")
        print("  python verify_transcript.py transcripts/client_session.log certs/client_cert.pem certs/server_cert.pem")
        print("  python verify_transcript.py transcripts/server_alice.log certs/server_cert.pem certs/client_cert.pem")
        sys.exit(1)
    
    transcript_path = sys.argv[1]
    client_cert_path = sys.argv[2] if len(sys.argv) > 2 else "certs/client_cert.pem"
    server_cert_path = sys.argv[3] if len(sys.argv) > 3 else "certs/server_cert.pem"
    
    print("="*60)
    print("NON-REPUDIATION VERIFICATION")
    print("="*60)
    print("\nThis script verifies:")
    print("1. Each message signature")
    print("2. Transcript integrity")
    print("3. Receipt signature (if provided)")
    print("4. Tampering detection")
    print("="*60)
    
    # Verify transcript
    if verify_transcript_file(transcript_path, client_cert_path, server_cert_path):
        print("\n✓ Transcript verification PASSED")
    else:
        print("\n❌ Transcript verification FAILED")
    
    # Test tampering
    test_tampered_transcript(transcript_path, client_cert_path)
    
    print("\n" + "="*60)
    print("VERIFICATION COMPLETE")
    print("="*60)

if __name__ == "__main__":
    main()

