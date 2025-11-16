# Complete Testing Guide for SecureChat

This guide provides step-by-step instructions for all required tests.

## Prerequisites

1. **Start MySQL database** (if using Docker):
   ```bash
   docker run -d --name securechat-db \
     -e MYSQL_ROOT_PASSWORD=rootpass \
     -e MYSQL_DATABASE=securechat \
     -e MYSQL_USER=scuser \
     -e MYSQL_PASSWORD=scpass \
     -p 3306:3306 mysql:8
   ```

2. **Initialize database**:
   ```bash
   python init_db.py
   ```

3. **Generate certificates**:
   ```bash
   python setup_certs.py
   ```

---

## Test 1: Wireshark - Encrypted Payloads

**Objective:** Show that all payloads are encrypted (no plaintext visible)

**Steps:**
1. Start Wireshark and begin capture
2. Start server: `python -m app.server`
3. Start client: `python -m app.client`
4. Send a few messages
5. Stop capture
6. Apply filter: `tcp.port == 9000`
7. Examine packets - verify `ct` field contains encrypted data

**Evidence needed:**
- Screenshot of Wireshark showing encrypted payloads
- Display filter used: `tcp.port == 9000`
- Note that plaintext is NOT visible

**See:** `WIRESHARK_INSTRUCTIONS.md` for detailed steps

---

## Test 2: Invalid Certificate Test (BAD CERT)

**Objective:** Verify server rejects invalid certificates

**Run test:**
```bash
python tests/test_invalid_cert.py
```

**Expected output:**
- Server should print: `❌ Certificate verification error: BAD CERT: UNTRUSTED...`
- OR: `❌ Certificate verification error: BAD CERT: EXPIRED...`
- Connection should be closed

**What it tests:**
- Self-signed certificates (not signed by CA)
- Expired certificates

**Evidence needed:**
- Screenshot/terminal output showing "BAD CERT" error
- Note which type of invalid cert was tested

---

## Test 3: Tampering Test (SIG FAIL)

**Objective:** Verify signature verification fails when ciphertext is tampered

**Run test:**
```bash
python tests/test_tamper.py
```

**Expected output:**
- Server should print: `❌ Signature verification failed`
- Connection should be closed

**What it tests:**
- Bit flip in ciphertext
- Signature verification catches the tampering

**Evidence needed:**
- Screenshot/terminal output showing "Signature verification failed"
- Note that tampered message was rejected

---

## Test 4: Replay Attack Test (REPLAY)

**Objective:** Verify old sequence numbers are rejected

**Run test:**
```bash
python tests/test_replay.py
```

**Expected output:**
- Server should print: `❌ Replay attack detected - sequence number not increasing`
- Connection should be closed

**What it tests:**
- Reusing an old sequence number
- Sequence number tracking prevents replay attacks

**Evidence needed:**
- Screenshot/terminal output showing "Replay attack detected"
- Note that old seqno was rejected

---

## Test 5: Non-Repudiation Verification

**Objective:** Verify transcript and receipt signatures offline

### Step 5a: Run a normal session

1. Start server: `python -m app.server`
2. Start client: `python -m app.client`
3. Send a few messages (e.g., "Hello", "Test", "Message 3")
4. Type "exit" to end session
5. Transcript files will be created in `transcripts/` directory

### Step 5b: Verify transcript

**Verify client transcript:**
```bash
python tests/verify_transcript.py transcripts/client_session.log certs/client_cert.pem
```

**Verify server transcript:**
```bash
python tests/verify_transcript.py transcripts/server_alice.log certs/server_cert.pem
```

**Expected output:**
- Each line should show: `✓ Line X (seqno=Y): Signature verified`
- All signatures should verify successfully

### Step 5c: Verify receipt

The receipt is sent at the end of the session. Check server/client output for:
- Receipt with `first_seq`, `last_seq`, `transcript_sha256`, and `sig`
- Server/client should print: `✓ Client/Server SessionReceipt verified`

### Step 5d: Test tampering detection

The verification script automatically tests tampering:
- Creates a tampered transcript
- Verifies that tampered transcript fails signature verification

**Evidence needed:**
1. Screenshot showing transcript verification (all lines verified)
2. Screenshot showing receipt verification
3. Screenshot showing tampered transcript is rejected
4. Show that any edit breaks verification

---

## Running All Tests

### Quick Test Sequence

1. **Start server** (in terminal 1):
   ```bash
   python -m app.server
   ```

2. **Test Invalid Cert** (in terminal 2):
   ```bash
   python tests/test_invalid_cert.py
   ```
   Check terminal 1 for "BAD CERT" message

3. **Test Tampering** (in terminal 2):
   ```bash
   python tests/test_tamper.py
   ```
   Check terminal 1 for "Signature verification failed"

4. **Test Replay** (in terminal 2):
   ```bash
   python tests/test_replay.py
   ```
   Check terminal 1 for "Replay attack detected"

5. **Test Non-Repudiation** (in terminal 2):
   ```bash
   python -m app.client
   # Send a few messages, then exit
   python tests/verify_transcript.py transcripts/client_session.log certs/client_cert.pem
   ```

6. **Wireshark Test** (separate):
   - Follow `WIRESHARK_INSTRUCTIONS.md`
   - Capture during a normal client-server session

---

## Evidence Checklist

For your report, you need:

- [ ] **Wireshark capture**
  - [ ] Screenshot showing encrypted payloads
  - [ ] Display filter documented: `tcp.port == 9000`
  - [ ] Evidence that no plaintext is visible

- [ ] **Invalid Certificate Test**
  - [ ] Screenshot/output showing "BAD CERT" error
  - [ ] Note which type of invalid cert was tested

- [ ] **Tampering Test**
  - [ ] Screenshot/output showing "Signature verification failed" or "SIG FAIL"
  - [ ] Evidence that tampered message was rejected

- [ ] **Replay Test**
  - [ ] Screenshot/output showing "Replay attack detected" or "REPLAY"
  - [ ] Evidence that old seqno was rejected

- [ ] **Non-Repudiation**
  - [ ] Transcript file exported
  - [ ] Receipt exported (from server/client output)
  - [ ] Verification script output showing all signatures verified
  - [ ] Tampering test showing verification fails when transcript is edited

---

## Troubleshooting

**Server not starting:**
- Check MySQL is running
- Check certificates exist: `ls certs/*.pem`
- Check database is initialized: `python init_db.py`

**Tests failing:**
- Make sure server is running before running tests
- Check that certificates are valid and not expired
- Check that user "alice" exists in database

**Wireshark not capturing:**
- Try different network interface
- On Windows, may need to install Npcap
- Try capturing on "localhost" or "127.0.0.1"

---

## Notes

- All tests should be run with server running
- Keep server terminal open to see error messages
- Transcript files are created automatically in `transcripts/` directory
- Receipts are printed in server/client output at end of session

