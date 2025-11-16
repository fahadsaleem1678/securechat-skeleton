# app/storage/transcript.py
import os
import json
import hashlib
from typing import Optional

TRANSCRIPTS_DIR = "transcripts"
os.makedirs(TRANSCRIPTS_DIR, exist_ok=True)

def _line_to_bytes(seqno: int, ts: int, ct_b64: str, sig_b64: str, peer_fp: str) -> bytes:
    s = f"{seqno}|{ts}|{ct_b64}|{sig_b64}|{peer_fp}"
    return s.encode()

def append_line(session_id: str, seqno: int, ts: int, ct_b64: str, sig_b64: str, peer_fp: str):
    fname = os.path.join(TRANSCRIPTS_DIR, f"session_{session_id}.log")
    entry = {
        "seqno": seqno,
        "ts": ts,
        "ct": ct_b64,
        "sig": sig_b64,
        "peer_fp": peer_fp
    }
    with open(fname, "a", encoding="utf-8") as f:
        f.write(json.dumps(entry, separators=(",", ":")) + "\n")

def compute_transcript_hash(session_id: str) -> str:
    """
    Compute chained transcript hash:
      prev = b""
      for each line:
        h = SHA256(line_bytes + prev)
        prev = h.digest()
    Return final digest as hex.
    """
    fname = os.path.join(TRANSCRIPTS_DIR, f"session_{session_id}.log")
    if not os.path.exists(fname):
        # empty file -> hash of empty input
        return hashlib.sha256(b"").hexdigest()

    prev = b""
    with open(fname, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            obj = json.loads(line)
            line_bytes = _line_to_bytes(obj["seqno"], obj["ts"], obj["ct"], obj["sig"], obj["peer_fp"])
            hasher = hashlib.sha256()
            hasher.update(line_bytes)
            hasher.update(prev)
            prev = hasher.digest()
    return prev.hex()

def get_transcript_path(session_id: str) -> str:
    return os.path.abspath(os.path.join(TRANSCRIPTS_DIR, f"session_{session_id}.log"))
