"""SQLite connection and schema management.

WAL mode lets readers (verify) run concurrently with the single writer.
secure_delete=ON makes SQLite zero out deleted bytes in place, which is what
makes key destruction (crypto-shredding) real rather than logical.
"""

import sqlite3

SCHEMA = """
CREATE TABLE IF NOT EXISTS entries (
    seq        INTEGER PRIMARY KEY,
    ts         REAL    NOT NULL,
    actor      TEXT    NOT NULL,
    action     TEXT    NOT NULL,
    session_id TEXT    NOT NULL,
    subject_id TEXT,
    nonce      BLOB    NOT NULL,
    pii        BLOB    NOT NULL,
    erased     INTEGER NOT NULL DEFAULT 0,
    prev_hash  BLOB    NOT NULL,
    hash       BLOB    NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_entries_subject ON entries(subject_id, erased);
CREATE TABLE IF NOT EXISTS subject_keys (
    subject_id TEXT PRIMARY KEY,
    key        BLOB NOT NULL
) WITHOUT ROWID;
CREATE TABLE IF NOT EXISTS erased_subjects (
    subject_id TEXT PRIMARY KEY
) WITHOUT ROWID;
"""


def connect(path):
    con = sqlite3.connect(path, timeout=60.0, isolation_level=None)
    con.execute("PRAGMA journal_mode=WAL")
    con.execute("PRAGMA busy_timeout=60000")
    con.execute("PRAGMA synchronous=NORMAL")
    con.execute("PRAGMA secure_delete=ON")
    return con


def init(path):
    con = connect(path)
    try:
        con.executescript(SCHEMA)
    finally:
        con.close()
