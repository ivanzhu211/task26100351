"""Stdlib-only symmetric encryption used for PII fields.

Construction: HMAC-SHA256 in counter mode (keystream =
HMAC(key, nonce || counter)). Random 128-bit nonce per message, so
ciphertexts are randomized and cannot be used to confirm guesses.
"""

from __future__ import annotations

import hashlib
import hmac
import os

KEY_SIZE = 32
NONCE_SIZE = 16


def generate_key() -> bytes:
    """Return a fresh random key."""
    return os.urandom(KEY_SIZE)


def _keystream(key: bytes, nonce: bytes, nbytes: int) -> bytes:
    out = bytearray()
    counter = 0
    while len(out) < nbytes:
        out += hmac.new(
            key, nonce + counter.to_bytes(8, "big"), hashlib.sha256
        ).digest()
        counter += 1
    return bytes(out[:nbytes])


def encrypt(key: bytes, plaintext: bytes) -> tuple[bytes, bytes]:
    """Return (nonce, ciphertext)."""
    if len(key) != KEY_SIZE:
        raise ValueError("bad key size")
    nonce = os.urandom(NONCE_SIZE)
    stream = _keystream(key, nonce, len(plaintext))
    ciphertext = bytes(a ^ b for a, b in zip(plaintext, stream))
    return nonce, ciphertext


def decrypt(key: bytes, nonce: bytes, ciphertext: bytes) -> bytes:
    """Inverse of encrypt."""
    if len(key) != KEY_SIZE:
        raise ValueError("bad key size")
    if len(nonce) != NONCE_SIZE:
        raise ValueError("bad nonce size")
    stream = _keystream(key, nonce, len(ciphertext))
    return bytes(a ^ b for a, b in zip(ciphertext, stream))
