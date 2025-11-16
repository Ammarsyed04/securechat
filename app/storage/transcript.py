"""Append-only transcript + TranscriptHash helpers."""

import os
import hashlib
from typing import Optional


class Transcript:
    """
    Append-only transcript logger.
    Each line written exactly in the order messages are processed.

    Transcript hash = SHA256 over the concatenation of all lines (UTF-8).
    """

    def __init__(self, session_id: str, directory: str = "transcripts"):
        self.session_id = session_id
        self.dir = directory
        os.makedirs(directory, exist_ok=True)

        self.path = os.path.join(directory, f"{session_id}.log")

        # Internal accumulator for computing final transcript hash
        self._acc = hashlib.sha256()

        # Create the file (if not present)
        open(self.path, "a").close()

        self.first_seq: Optional[int] = None
        self.last_seq: Optional[int] = None

    # -------------------- Append operations -------------------- #

    def append(self, seqno: int, timestamp: int, ciphertext: str, signature: str, peer_cert_fingerprint: str):
        """
        Append a new entry to the transcript.
        Format: seqno | timestamp | ciphertext | signature | peer-cert-fingerprint
        """
        line = f"{seqno}|{timestamp}|{ciphertext}|{signature}|{peer_cert_fingerprint}\n"

        # Update rolling hash
        self._acc.update(line.encode())

        # Track seqno bounds
        if self.first_seq is None:
            self.first_seq = seqno
        self.last_seq = seqno

        # Append to file
        with open(self.path, "a", encoding="utf-8") as f:
            f.write(line)

    # -------------------- Hash operations -------------------- #

    def final_hash_hex(self) -> str:
        """
        Return final transcript hash as hex string.
        Used inside SessionReceipt.
        """
        return self._acc.hexdigest()
    
    def get_transcript_hash_for_signing(self) -> bytes:
        """
        Return the transcript hash as bytes for signing.
        This is the hash that gets signed in the SessionReceipt.
        """
        return bytes.fromhex(self._acc.hexdigest())

    # -------------------- Metadata helpers -------------------- #

    def seq_range(self):
        """Return (first_seq, last_seq)."""
        return self.first_seq, self.last_seq

