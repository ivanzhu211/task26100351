"""Hash-chain and per-subject PII encryption primitives (stdlib only).

Confidentiality: HMAC-SHA256 in counter mode as a keystream, XORed with the
plaintext. Each entry uses a fresh random nonce, so identical plaintexts
produce unrelated ciphertexts and the chain hash cannot be used to confirm
a guessed PII value. Integrity comes from the SHA-256 hash chain itself.
"""

import hashlib
import hmac
import json
import os
import struct

HASH_SIZE = 32
NONCE_SIZE = 16
GENESIS = b"\x00" * HASH_SIZE
_DOMAIN = b"AUDITLOG1"


def new_key() -> bytes:
    return os.urandom(32)


def new_nonce() -> bytes:
    return os.urandom(NONCE_SIZE)


def _keystream(key: bytes, nonce: bytes, n: int) -> bytes:
    out = bytearray()
    counter = 0
    while len(out) < n:
        block = hmac.new(key, nonce + struct.pack(">Q", counter), hashlib.sha256).digest()
        out += block
        counter += 1
    return bytes(out[:n])


def encrypt(key: bytes, nonce: bytes, plaintext: bytes) -> bytes:
    ks = _keystream(key, nonce, len(plaintext))
    return bytes(a ^ b for a, b in zip(plaintext, ks))


def decrypt(key: bytes, nonce: bytes, ciphertext: bytes) -> bytes:
    return encrypt(key, nonce, ciphertext)


def canonical_payload(ts, actor, action, session_id, subject_id, nonce, pii) -> bytes:
    """Deterministic serialization of every hashed field of an entry."""
    return json.dumps(
        [ts, actor, action, session_id, subject_id, nonce.hex(), pii.hex()],
        separators=(",", ":"),
        ensure_ascii=True,
    ).encode("ascii")


def entry_hash(prev_hash: bytes, payload: bytes) -> bytes:
    return hashlib.sha256(_DOMAIN + prev_hash + payload).digest()
