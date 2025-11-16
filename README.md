
# SecureChat – Assignment #2 (CS-3002 Information Security, Fall 2025)

This repository is the **official code skeleton** for your Assignment #2.  
You will build a **console-based, PKI-enabled Secure Chat System** in **Python**, demonstrating how cryptographic primitives combine to achieve:

**Confidentiality, Integrity, Authenticity, and Non-Repudiation (CIANR)**.


## 🧩 Overview

You are provided only with the **project skeleton and file hierarchy**.  
Each file contains docstrings and `TODO` markers describing what to implement.

Your task is to:
- Implement the **application-layer protocol**.
- Integrate cryptographic primitives correctly to satisfy the assignment spec.
- Produce evidence of security properties via Wireshark, replay/tamper tests, and signed session receipts.

## 🏗️ Folder Structure
```
securechat-skeleton/
├─ app/
│  ├─ client.py              # Client workflow (plain TCP, no TLS)
│  ├─ server.py              # Server workflow (plain TCP, no TLS)
│  ├─ crypto/
│  │  ├─ aes.py              # AES-128(ECB)+PKCS#7 (use cryptography lib)
│  │  ├─ dh.py               # Classic DH helpers + key derivation
│  │  ├─ pki.py              # X.509 validation (CA signature, validity, CN)
│  │  └─ sign.py             # RSA SHA-256 sign/verify (PKCS#1 v1.5)
│  ├─ common/
│  │  ├─ protocol.py         # Pydantic message models (hello/login/msg/receipt)
│  │  └─ utils.py            # Helpers (base64, now_ms, sha256_hex)
│  └─ storage/
│     ├─ db.py               # MySQL user store (salted SHA-256 passwords)
│     └─ transcript.py       # Append-only transcript + transcript hash
├─ scripts/
│  ├─ gen_ca.py              # Create Root CA (RSA + self-signed X.509)
│  └─ gen_cert.py            # Issue client/server certs signed by Root CA
├─ tests/manual/NOTES.md     # Manual testing + Wireshark evidence checklist
├─ certs/.keep               # Local certs/keys (gitignored)
├─ transcripts/.keep         # Session logs (gitignored)
├─ .env.example              # Sample configuration (no secrets)
├─ .gitignore                # Ignore secrets, binaries, logs, and certs
├─ requirements.txt          # Minimal dependencies
└─ .github/workflows/ci.yml  # Compile-only sanity check (no execution)
```

## ⚙️ Execution Steps

### Prerequisites
- Python 3.8 or higher
- MySQL database (or Docker for MySQL)
- Git (for version control)

### Step 1: Install Dependencies
```bash
pip install -r requirements.txt
```

### Step 2: Set Up MySQL Database
**Option A: Using Docker (Recommended)**
```bash
docker run -d --name securechat-db \
  -e MYSQL_ROOT_PASSWORD=rootpass \
  -e MYSQL_DATABASE=securechat \
  -e MYSQL_USER=scuser \
  -e MYSQL_PASSWORD=scpass \
  -p 3306:3306 mysql:8
```

**Option B: Using Local MySQL**
- Create a database named `securechat`
- Update `.env` file with your MySQL credentials (if using)

### Step 3: Initialize Database Schema
```bash
python init_db.py
```
This creates the users table and a test user (alice/alice123).

### Step 4: Generate Certificates
```bash
python setup_certs.py
```
This generates:
- Root CA certificate (`certs/ca.pem`)
- Server certificate (`certs/server_cert.pem`)
- Client certificate (`certs/client_cert.pem`)
- Private keys (in `certs/private/`)

### Step 5: Run the Server
```bash
python -m app.server
```
The server will start on port 9000 and display "Server ready."

### Step 6: Run the Client (in a new terminal)
```bash
python -m app.client
```
You can now send messages. Type `exit` to end the session.

### Step 7: Run Tests (Optional)
```bash
# Test invalid certificates
python tests/test_invalid_cert.py

# Test tampering detection
python tests/test_tamper.py

# Test replay attack detection
python tests/test_replay.py

# Verify transcript and non-repudiation
python tests/verify_transcript.py transcripts/client_session.log certs/client_cert.pem certs/server_cert.pem
```

**Note:** Make sure the server is running before executing test scripts.

## 🚫 Important Rules

- **Do not use TLS/SSL or any secure-channel abstraction**  
  (e.g., `ssl`, HTTPS, WSS, OpenSSL socket wrappers).  
  All crypto operations must occur **explicitly** at the application layer.

- You are **not required** to implement AES, RSA, or DH math, Use any of the available libraries.
- Do **not commit secrets** (certs, private keys, salts, `.env` values).
- Your commits must reflect progressive development — at least **10 meaningful commits**.

## 🧾 Deliverables

When submitting on Google Classroom (GCR):

1. A ZIP of your **GitHub fork** (repository).
2. MySQL schema dump and a few sample records.
3. Updated **README.md** explaining setup, usage, and test outputs.
4. `RollNumber-FullName-Report-A02.docx`
5. `RollNumber-FullName-TestReport-A02.docx`

## 🧪 Test Evidence Checklist

✔ Wireshark capture (encrypted payloads only)  
✔ Invalid/self-signed cert rejected (`BAD_CERT`)  
✔ Tamper test → signature verification fails (`SIG_FAIL`)  
✔ Replay test → rejected by seqno (`REPLAY`)  
✔ Non-repudiation → exported transcript + signed SessionReceipt verified offline  
