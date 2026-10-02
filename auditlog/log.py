"""Tamper-evident audit log: append / head / erase / verify.

Design notes:
- Every entry's hash covers prev_hash + public fields + nonce + PII
  ciphertext. The `erased` flag is deliberately NOT hashed, so erase() can
  mark entries without touching the chain.
- PII is encrypted with a per-subject key stored in `subject_keys`.
  erase() destroys the key (crypto-shredding): ciphertext stays in the chain
  (hashes unchanged) but can never be decrypted or used to confirm guesses.
- Appends for an already-erased subject use an ephemeral in-memory key that
  is never persisted, so those entries carry unrecoverable PII too.
"""

import json
import os
import sqlite3
import time

from . import crypto, store

ERASE_ACTION = "__erase__"
_MAX_RETRIES = 50


class AuditLog:
    def __init__(self, path):
        self.path = os.fspath(path)
        store.init(self.path)
        self.con = store.connect(self.path)

    # -- internal helpers -------------------------------------------------

    def _subject_key(self, subject_id):
        """Return (key, ephemeral). Must be called inside a write txn."""
        row = self.con.execute(
            "SELECT key FROM subject_keys WHERE subject_id=?", (subject_id,)
        ).fetchone()
        if row is not None:
            return row[0], False
        erased = self.con.execute(
            "SELECT 1 FROM erased_subjects WHERE subject_id=?", (subject_id,)
        ).fetchone()
        if erased is not None:
            return crypto.new_key(), True
        key = crypto.new_key()
        self.con.execute(
            "INSERT OR IGNORE INTO subject_keys(subject_id, key) VALUES (?,?)",
            (subject_id, key),
        )
        row = self.con.execute(
            "SELECT key FROM subject_keys WHERE subject_id=?", (subject_id,)
        ).fetchone()
        return row[0], False

    def _insert_entry(self, ts, actor, action, session_id, subject_id, pii_plain):
        """Append one entry inside the current transaction; return seq."""
        nonce = crypto.new_nonce()
        erased = 0
        if subject_id is not None:
            key, ephemeral = self._subject_key(subject_id)
            ciphertext = crypto.encrypt(key, nonce, pii_plain)
            if ephemeral:
                erased = 1
        else:
            ciphertext = pii_plain
        row = self.con.execute(
            "SELECT seq, hash FROM entries ORDER BY seq DESC LIMIT 1"
        ).fetchone()
        prev_seq, prev_hash = (row[0], row[1]) if row else (0, crypto.GENESIS)
        seq = prev_seq + 1
        payload = crypto.canonical_payload(
            ts, actor, action, session_id, subject_id, nonce, ciphertext
        )
        h = crypto.entry_hash(prev_hash, payload)
        self.con.execute(
            "INSERT INTO entries(seq, ts, actor, action, session_id, subject_id,"
            " nonce, pii, erased, prev_hash, hash) VALUES (?,?,?,?,?,?,?,?,?,?,?)",
            (seq, ts, actor, action, session_id, subject_id,
             nonce, ciphertext, erased, prev_hash, h),
        )
        return seq

    def _write_txn(self, fn):
        """Run fn inside BEGIN IMMEDIATE with busy retry; never drop entries."""
        for attempt in range(_MAX_RETRIES):
            try:
                self.con.execute("BEGIN IMMEDIATE")
                result = fn()
                self.con.execute("COMMIT")
                return result
            except sqlite3.OperationalError as exc:
                self.con.execute("ROLLBACK")
                if "locked" not in str(exc).lower() and "busy" not in str(exc).lower():
                    raise
                time.sleep(min(0.05 * (attempt + 1), 1.0))
        raise sqlite3.OperationalError("could not acquire write lock")

    # -- public API ---------------------------------------------------------

    def append(self, actor, action, session_id, subject_id=None, pii=None, ts=None):
        if ts is None:
            ts = time.time()
        if subject_id is None and pii:
            raise ValueError("PII requires a subject_id")
        pii_plain = json.dumps(pii or {}, sort_keys=True).encode("utf-8")
        return self._write_txn(
            lambda: self._insert_entry(ts, actor, action, session_id, subject_id, pii_plain)
        )

    def head(self):
        row = self.con.execute(
            "SELECT seq, hash FROM entries ORDER BY seq DESC LIMIT 1"
        ).fetchone()
        return (row[0], row[1]) if row else (0, crypto.GENESIS)

    def read_pii(self, seq):
        """Decrypt an entry's PII; returns None if the key was destroyed."""
        row = self.con.execute(
            "SELECT subject_id, nonce, pii FROM entries WHERE seq=?", (seq,)
        ).fetchone()
        if row is None:
            raise KeyError(seq)
        subject_id, nonce, ciphertext = row
        if subject_id is None:
            return json.loads(ciphertext.decode("utf-8"))
        key_row = self.con.execute(
            "SELECT key FROM subject_keys WHERE subject_id=?", (subject_id,)
        ).fetchone()
        if key_row is None:
            return None
        plain = crypto.decrypt(key_row[0], nonce, ciphertext)
        return json.loads(plain.decode("utf-8"))

    def erase(self, subject_id, actor="system", batch_size=1000, batch_hook=None):
        """Crypto-shred a subject's PII. Crash-safe and idempotent.

        Order matters: the on-chain erase record is committed FIRST, so any
        intermediate state after SIGKILL still verifies. Re-running erase()
        after a crash simply resumes and converges.
        """
        # 1. On-chain erase record + erased_subjects marker, atomically.
        ts = time.time()
        pii_plain = json.dumps({}, sort_keys=True).encode("utf-8")

        def record():
            seq = self._insert_entry(ts, actor, ERASE_ACTION, "", subject_id, pii_plain)
            self.con.execute(
                "INSERT OR IGNORE INTO erased_subjects(subject_id) VALUES (?)",
                (subject_id,),
            )
            return seq

        self._write_txn(record)

        # 2. Destroy the subject's key (secure_delete zeroes the bytes).
        self._write_txn(
            lambda: self.con.execute(
                "DELETE FROM subject_keys WHERE subject_id=?", (subject_id,)
            )
        )

        # 3. Mark existing entries in small batches so other processes can
        #    keep appending between batches.
        while True:
            rows = self.con.execute(
                "SELECT seq FROM entries WHERE subject_id=? AND erased=0 AND action<>? LIMIT ?",
                (subject_id, ERASE_ACTION, batch_size),
            ).fetchall()
            if not rows:
                break
            seqs = [r[0] for r in rows]
            marks = ",".join("?" * len(seqs))

            def mark(seqs=seqs, marks=marks):
                self.con.execute(
                    f"UPDATE entries SET erased=1 WHERE seq IN ({marks})", seqs
                )

            self._write_txn(mark)
            if batch_hook is not None:
                batch_hook()

        # 4. Truncate the WAL so no stale frames retain key material.
        self.con.execute("PRAGMA wal_checkpoint(TRUNCATE)")

    def verify(self, known_heads=()):
        """Stream the whole chain and check integrity. Returns a list of
        human-readable issues; empty list means the chain is valid.

        Detects: modified fields of non-erased entries, deleted/inserted/
        reordered entries, truncation before a known head, and entries in
        erased state without a matching on-chain erase record.
        """
        issues = []
        expected_heads = {int(seq): bytes(h) for seq, h in known_heads}
        matched_heads = set()
        erased_subjects = set()
        erase_records = set()
        prev_hash, prev_seq = crypto.GENESIS, 0
        cur = self.con.execute(
            "SELECT seq, ts, actor, action, session_id, subject_id, nonce, pii,"
            " erased, prev_hash, hash FROM entries ORDER BY seq"
        )
        while True:
            rows = cur.fetchmany(1000)
            if not rows:
                break
            for (seq, ts, actor, action, session_id, subject_id,
                 nonce, pii, erased, stored_prev, stored_hash) in rows:
                if seq != prev_seq + 1:
                    issues.append(
                        f"entry sequence gap: expected seq {prev_seq + 1}, found {seq}"
                    )
                if bytes(stored_prev) != prev_hash:
                    issues.append(f"entry {seq}: prev_hash link broken")
                payload = crypto.canonical_payload(
                    ts, actor, action, session_id, subject_id, nonce, pii
                )
                h = crypto.entry_hash(prev_hash, payload)
                if bytes(stored_hash) != h:
                    issues.append(f"entry {seq}: hash mismatch (content tampered)")
                if erased and subject_id is not None:
                    erased_subjects.add(subject_id)
                if action == ERASE_ACTION and subject_id is not None:
                    erase_records.add(subject_id)
                if seq in expected_heads:
                    if h == expected_heads[seq]:
                        matched_heads.add(seq)
                    else:
                        issues.append(f"entry {seq}: does not match recorded head")
                prev_hash, prev_seq = h, seq
        for seq in expected_heads:
            if seq > prev_seq:
                issues.append(
                    f"chain truncated: recorded head seq {seq} is beyond current tip {prev_seq}"
                )
        for subject_id in sorted(erased_subjects - erase_records):
            issues.append(
                f"subject {subject_id!r}: entries in erased state but no erase record on chain"
            )
        return issues

    def close(self):
        self.con.close()

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()
