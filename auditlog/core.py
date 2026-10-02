"""Hash-chained audit log on SQLite with crypto-shredding erasure."""

from __future__ import annotations

import base64
import contextlib
import fcntl
import hashlib
import json
import os
import sqlite3
import time
from dataclasses import dataclass

from . import crypto

GENESIS_HASH = "0" * 64
ERASE_ACTION = "erase"


class VerifyError(Exception):
    """Raised when chain verification fails.

    Attributes:
        seq: sequence number of the offending entry, if applicable.
    """

    def __init__(self, message: str, seq: int | None = None) -> None:
        super().__init__(message)
        self.seq = seq


@dataclass(frozen=True)
class Entry:
    """Public fields of one log entry."""

    actor: str
    action: str
    session_id: str
    subject_id: str | None = None
    pii: dict[str, str] | None = None
    ts: float | None = None  # defaults to time.time() at append


@dataclass(frozen=True)
class Head:
    """Chain tip: sequence number and hash (hex)."""

    seq: int
    hash: str


class AuditLog:
    def __init__(self, path: str) -> None:
        self.dir = os.path.abspath(path)
        self.db_path = os.path.join(self.dir, "audit.db")
        self.keys_dir = os.path.join(self.dir, "keys")
        self.locks_dir = os.path.join(self.dir, "locks")
        os.makedirs(self.keys_dir, exist_ok=True)
        os.makedirs(self.locks_dir, exist_ok=True)
        self._conn = sqlite3.connect(self.db_path, isolation_level=None)
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.execute("PRAGMA synchronous=FULL")
        self._conn.execute("PRAGMA busy_timeout=60000")
        self._conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS entries(
                seq INTEGER PRIMARY KEY,
                subject_id TEXT,
                action TEXT NOT NULL,
                erased INTEGER NOT NULL DEFAULT 0,
                payload TEXT NOT NULL,
                prev_hash TEXT NOT NULL,
                hash TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_entries_subject
                ON entries(subject_id, erased);
            CREATE TABLE IF NOT EXISTS tombstones(
                subject_id TEXT PRIMARY KEY
            );
            """
        )

    # -- internal helpers -------------------------------------------------

    @staticmethod
    def _subject_digest(subject_id: str) -> str:
        return hashlib.sha256(subject_id.encode("utf-8")).hexdigest()

    def _key_path(self, subject_id: str) -> str:
        return os.path.join(self.keys_dir, self._subject_digest(subject_id) + ".key")

    @contextlib.contextmanager
    def _subject_lock(self, subject_id: str):
        lock_path = os.path.join(
            self.locks_dir, self._subject_digest(subject_id) + ".lock"
        )
        fd = os.open(lock_path, os.O_RDWR | os.O_CREAT, 0o600)
        try:
            fcntl.flock(fd, fcntl.LOCK_EX)
            yield
        finally:
            fcntl.flock(fd, fcntl.LOCK_UN)
            os.close(fd)

    def _is_tombstoned(self, subject_id: str) -> bool:
        row = self._conn.execute(
            "SELECT 1 FROM tombstones WHERE subject_id=?", (subject_id,)
        ).fetchone()
        return row is not None

    def _load_or_create_key(self, subject_id: str) -> bytes:
        path = self._key_path(subject_id)
        try:
            with open(path, "rb") as f:
                data = f.read()
            if len(data) == crypto.KEY_SIZE:
                return data
        except FileNotFoundError:
            pass
        key = crypto.generate_key()
        tmp = f"{path}.tmp.{os.getpid()}"
        with open(tmp, "wb") as f:
            f.write(key)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, path)
        return key

    def _seal_pii(self, subject_id: str, pii: dict[str, str]) -> dict[str, str]:
        """Encrypt PII for storage. Caller sees only nonce+ciphertext."""
        plaintext = json.dumps(
            pii, sort_keys=True, ensure_ascii=False, separators=(",", ":")
        ).encode("utf-8")
        with self._subject_lock(subject_id):
            if self._is_tombstoned(subject_id):
                # Subject already erased: encrypt with an ephemeral key that
                # is never persisted, so the PII is unrecoverable by design.
                key = crypto.generate_key()
            else:
                key = self._load_or_create_key(subject_id)
            nonce, ct = crypto.encrypt(key, plaintext)
        return {
            "nonce": base64.b64encode(nonce).decode("ascii"),
            "ct": base64.b64encode(ct).decode("ascii"),
        }

    @staticmethod
    def _chain_hash(prev_hash: str, payload: str) -> str:
        return hashlib.sha256((prev_hash + payload).encode("utf-8")).hexdigest()

    # -- public API -------------------------------------------------------

    def append(self, entry: Entry) -> int:
        ts = entry.ts if entry.ts is not None else time.time()
        sealed = None
        if entry.subject_id is not None and entry.pii:
            sealed = self._seal_pii(entry.subject_id, entry.pii)
        payload = json.dumps(
            {
                "ts": ts,
                "actor": entry.actor,
                "action": entry.action,
                "session_id": entry.session_id,
                "subject_id": entry.subject_id,
                "pii": sealed,
            },
            sort_keys=True,
            ensure_ascii=False,
            separators=(",", ":"),
        )
        cur = self._conn.cursor()
        cur.execute("BEGIN IMMEDIATE")
        try:
            row = cur.execute(
                "SELECT seq, hash FROM entries ORDER BY seq DESC LIMIT 1"
            ).fetchone()
            prev_seq, prev_hash = row if row else (0, GENESIS_HASH)
            seq = prev_seq + 1
            digest = self._chain_hash(prev_hash, payload)
            cur.execute(
                "INSERT INTO entries(seq, subject_id, action, erased, payload,"
                " prev_hash, hash) VALUES (?,?,?,0,?,?,?)",
                (seq, entry.subject_id, entry.action, payload, prev_hash, digest),
            )
            self._conn.commit()
        except BaseException:
            self._conn.rollback()
            raise
        return seq

    def head(self) -> Head:
        row = self._conn.execute(
            "SELECT seq, hash FROM entries ORDER BY seq DESC LIMIT 1"
        ).fetchone()
        if row is None:
            return Head(0, GENESIS_HASH)
        return Head(row[0], row[1])

    def erase(self, subject_id: str, batch_size: int = 500) -> None:
        """Crypto-shred all PII of `subject_id` and record the erasure.

        Crash-safe ordering (every intermediate state verifies, and a
        re-run converges):
          1. ensure an erasure record exists on the chain;
          2. under the subject lock: set tombstone, destroy the key file;
          3. mark the subject's entries erased, in small batches so other
             processes can keep appending between batches.
        """
        # Step 1: erasure record on the chain (idempotent).
        row = self._conn.execute(
            "SELECT 1 FROM entries WHERE action=? AND subject_id=? LIMIT 1",
            (ERASE_ACTION, subject_id),
        ).fetchone()
        if row is None:
            self.append(
                Entry(
                    actor="system",
                    action=ERASE_ACTION,
                    session_id="erase",
                    subject_id=subject_id,
                )
            )
        # Step 2: tombstone + key destruction, serialized against appends
        # for this subject via the subject lock.
        with self._subject_lock(subject_id):
            self._conn.execute(
                "INSERT OR IGNORE INTO tombstones(subject_id) VALUES (?)",
                (subject_id,),
            )
            self._destroy_key_file(subject_id)
        # Step 3: batch-mark entries (bookkeeping; small transactions).
        while True:
            cur = self._conn.cursor()
            cur.execute("BEGIN IMMEDIATE")
            try:
                rows = cur.execute(
                    "SELECT seq FROM entries WHERE subject_id=? AND erased=0"
                    " LIMIT ?",
                    (subject_id, batch_size),
                ).fetchall()
                if rows:
                    cur.executemany(
                        "UPDATE entries SET erased=1 WHERE seq=?", rows
                    )
                self._conn.commit()
            except BaseException:
                self._conn.rollback()
                raise
            if not rows:
                break
        # Step 4: fold WAL into the main db so shredded key material does
        # not linger in companion files (best effort under concurrency).
        try:
            self._conn.execute("PRAGMA wal_checkpoint(TRUNCATE)")
        except sqlite3.OperationalError:
            pass

    def _destroy_key_file(self, subject_id: str) -> None:
        path = self._key_path(subject_id)
        try:
            size = os.path.getsize(path)
        except FileNotFoundError:
            return
        with open(path, "r+b") as f:
            f.write(b"\x00" * size)
            f.flush()
            os.fsync(f.fileno())
        os.unlink(path)
        dfd = os.open(self.keys_dir, os.O_RDONLY)
        try:
            os.fsync(dfd)
        finally:
            os.close(dfd)

    def verify(self, known_heads: tuple[Head, ...] | list[Head] = ()) -> None:
        """Stream the whole chain and raise VerifyError on any tampering.

        Checks: sequence contiguity, prev_hash linkage, hash of each
        payload, column/payload consistency, every known head, chain not
        truncated before a known head, and that every subject whose key
        file is gone has an erasure record on the chain.
        """
        heads = sorted((h for h in known_heads if h.seq > 0), key=lambda h: h.seq)
        head_idx = 0
        prev_hash = GENESIS_HASH
        expected_seq = 1
        last_seq = 0
        erased_subjects: set[str] = set()
        missing_key_subjects: set[str] = set()
        key_cache: dict[str, bool] = {}
        cur = self._conn.execute(
            "SELECT seq, subject_id, action, payload, prev_hash, hash"
            " FROM entries ORDER BY seq"
        )
        for seq, subject_id, action, payload, row_prev, row_hash in cur:
            if seq != expected_seq:
                raise VerifyError(
                    f"chain discontinuity: expected seq {expected_seq},"
                    f" found {seq}",
                    seq=expected_seq,
                )
            if row_prev != prev_hash:
                raise VerifyError(f"prev_hash mismatch", seq=seq)
            if row_hash != self._chain_hash(row_prev, payload):
                raise VerifyError("hash mismatch (entry content altered)", seq=seq)
            try:
                body = json.loads(payload)
            except json.JSONDecodeError:
                raise VerifyError("malformed payload", seq=seq)
            if body.get("subject_id") != subject_id or body.get("action") != action:
                raise VerifyError("column/payload mismatch", seq=seq)
            if action == ERASE_ACTION and subject_id is not None:
                erased_subjects.add(subject_id)
            if subject_id is not None:
                if subject_id not in key_cache:
                    key_cache[subject_id] = os.path.exists(
                        self._key_path(subject_id)
                    )
                if not key_cache[subject_id]:
                    missing_key_subjects.add(subject_id)
            while head_idx < len(heads) and heads[head_idx].seq == seq:
                if heads[head_idx].hash != row_hash:
                    raise VerifyError("known head mismatch", seq=seq)
                head_idx += 1
            prev_hash = row_hash
            expected_seq += 1
            last_seq = seq
        if head_idx < len(heads):
            raise VerifyError(
                "chain truncated before known head", seq=heads[head_idx].seq
            )
        unrecorded = missing_key_subjects - erased_subjects
        if unrecorded:
            raise VerifyError(
                f"PII shredded without erasure record for:"
                f" {sorted(unrecorded)!r}"
            )

    def close(self) -> None:
        self._conn.close()
