#!/usr/bin/env python3
"""
Generate all required certificates for the secure chat application.
Run this script once before starting the server/client.
"""

import subprocess
import sys
import os

def run_script(script_path, *args):
    """Run a Python script and check for errors."""
    cmd = [sys.executable, script_path] + list(args)
    print(f"Running: {' '.join(cmd)}")
    result = subprocess.run(cmd, capture_output=True, text=True)
    if result.returncode != 0:
        print(f"ERROR: {result.stderr}")
        return False
    print(result.stdout)
    return True

def main():
    print("=" * 60)
    print("Certificate Generation Script")
    print("=" * 60)
    
    # Check if certs directory exists
    os.makedirs("certs/private", exist_ok=True)
    
    # Step 1: Generate CA
    print("\n[1/3] Generating Root CA certificate...")
    if not run_script("scripts/gen_ca.py"):
        print("Failed to generate CA certificate")
        return 1
    
    # Step 2: Generate Server Certificate
    print("\n[2/3] Generating Server certificate...")
    if not run_script("scripts/gen_cert.py", "server", "server_cert"):
        print("Failed to generate server certificate")
        return 1
    
    # Step 3: Generate Client Certificate
    print("\n[3/3] Generating Client certificate...")
    if not run_script("scripts/gen_cert.py", "client", "client_cert"):
        print("Failed to generate client certificate")
        return 1
    
    print("\n" + "=" * 60)
    print("✓ All certificates generated successfully!")
    print("=" * 60)
    print("\nCertificate files created:")
    print("  - certs/ca.pem")
    print("  - certs/server_cert.pem")
    print("  - certs/client_cert.pem")
    print("  - certs/private/*_key.pem (private keys)")
    print("\nYou can now run the server and client.")
    return 0

if __name__ == "__main__":
    sys.exit(main())

