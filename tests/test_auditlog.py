import json
import multiprocessing as mp
import os
import shutil
import signal
import sqlite3
import tempfile
import time
import unittest

from auditlog import AuditLog, Entry, Head, VerifyError

SUBJECT = "user-777"
PHONE = "13800138000"
NAME = "张三"


def _pii():
    return {"name": NAME, "phone": PHONE}


def _scan_dir_for(path, needles):
    """Return list of (file, needle) where a needle's bytes appear."""
    hits = []
    for root, _, files in os.walk(path):
        for fn in files:
            with open(os.path.join(root, fn), "rb") as f:
                data = f.read()
            for n in needles:
                if n in data:
                    hits.append((os.path.join(root, fn), n))
    return hits


def _appender(path, subject, stop, counter, tag):
    """Worker: append entries for `subject` until `stop` is set."""
    log = AuditLog(path)
    n = 0
    try:
        while not stop.is_set():
            log.append(
                Entry(
                    actor=f"actor-{tag}",
                    action="update",
                    session_id=f"sess-{tag}-{n}",
                    subject_id=subject,
                    pii=_pii(),
                )
            )
            n += 1
            time.sleep(0.001)
    finally:
        counter.put((tag, n))
        log.close()


def _eraser(path, subject, batch_size=500):
    log = AuditLog(path)
    try:
        log.erase(subject, batch_size=batch_size)
    finally:
        log.close()


class AuditLogBasicTest(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp(prefix="auditlog-")
        self.addCleanup(shutil.rmtree, self.dir, True)

    def test_append_head_verify_roundtrip(self):
        log = AuditLog(self.dir)
        heads = []
        for i in range(20):
            log.append(
                Entry(actor="a", action=f"op{i}", session_id="s",
                      subject_id=SUBJECT, pii=_pii())
            )
            heads.append(log.head())
        self.assertEqual(log.head().seq, 20)
        log.verify(heads)
        log.verify([heads[0], heads[-1]])
        log.close()
        # reopen and verify again
        log2 = AuditLog(self.dir)
        self.assertEqual(log2.head(), heads[-1])
        log2.verify(heads)
        log2.close()

    def test_verify_detects_field_tamper_with_seq(self):
        log = AuditLog(self.dir)
        for i in range(5):
            log.append(Entry(actor="a", action=f"op{i}", session_id="s"))
        log.close()
        con = sqlite3.connect(os.path.join(self.dir, "audit.db"))
        con.execute(
            "UPDATE entries SET payload=replace(payload,'op2','opX')"
            " WHERE seq=3"
        )
        con.commit()
        con.close()
        log = AuditLog(self.dir)
        with self.assertRaises(VerifyError) as ctx:
            log.verify()
        self.assertEqual(ctx.exception.seq, 3)
        log.close()

    def test_verify_detects_deletion_insertion_truncation(self):
        log = AuditLog(self.dir)
        heads = []
        for i in range(6):
            log.append(Entry(actor="a", action=f"op{i}", session_id="s"))
            heads.append(log.head())
        log.close()
        # deletion
        con = sqlite3.connect(os.path.join(self.dir, "audit.db"))
        con.execute("DELETE FROM entries WHERE seq=3")
        con.commit()
        con.close()
        log = AuditLog(self.dir)
        with self.assertRaises(VerifyError):
            log.verify()
        log.close()
        # restore, then truncate the tail before a known head
        shutil.rmtree(self.dir)
        os.makedirs(self.dir)
        log = AuditLog(self.dir)
        heads = []
        for i in range(6):
            log.append(Entry(actor="a", action=f"op{i}", session_id="s"))
            heads.append(log.head())
        log.close()
        con = sqlite3.connect(os.path.join(self.dir, "audit.db"))
        con.execute("DELETE FROM entries WHERE seq>=5")
        con.commit()
        con.close()
        log = AuditLog(self.dir)
        with self.assertRaises(VerifyError) as ctx:
            log.verify([heads[5]])
        self.assertEqual(ctx.exception.seq, 6)
        log.close()

    def test_verify_detects_insertion_and_reorder(self):
        # forged tail entry with valid-looking linkage but bogus content
        log = AuditLog(self.dir)
        for i in range(5):
            log.append(Entry(actor="a", action=f"op{i}", session_id="s"))
        head = log.head()
        log.close()
        con = sqlite3.connect(os.path.join(self.dir, "audit.db"))
        con.execute(
            "INSERT INTO entries(seq, subject_id, action, erased, payload,"
            " prev_hash, hash) VALUES (6, NULL, 'forged', 0, '{}', ?, 'ff'*0)",
            (head.hash,),
        )
        con.commit()
        con.close()
        log = AuditLog(self.dir)
        with self.assertRaises(VerifyError) as ctx:
            log.verify()
        self.assertEqual(ctx.exception.seq, 6)
        log.close()
        # reorder: swap payloads of two entries
        shutil.rmtree(self.dir)
        os.makedirs(self.dir)
        log = AuditLog(self.dir)
        for i in range(5):
            log.append(Entry(actor="a", action=f"op{i}", session_id="s"))
        log.close()
        con = sqlite3.connect(os.path.join(self.dir, "audit.db"))
        rows = con.execute(
            "SELECT seq, payload FROM entries WHERE seq IN (2,3)"
        ).fetchall()
        con.execute("UPDATE entries SET payload=? WHERE seq=?",
                    (rows[0][1], rows[1][0]))
        con.execute("UPDATE entries SET payload=? WHERE seq=?",
                    (rows[1][1], rows[0][0]))
        con.commit()
        con.close()
        log = AuditLog(self.dir)
        with self.assertRaises(VerifyError) as ctx:
            log.verify()
        self.assertEqual(ctx.exception.seq, 2)
        log.close()

    def test_verify_detects_shredded_key_without_record(self):
        log = AuditLog(self.dir)
        log.append(Entry(actor="a", action="op", session_id="s",
                         subject_id=SUBJECT, pii=_pii()))
        log.close()
        keys = os.path.join(self.dir, "keys")
        for fn in os.listdir(keys):
            os.unlink(os.path.join(keys, fn))
        log = AuditLog(self.dir)
        with self.assertRaises(VerifyError) as ctx:
            log.verify()
        self.assertIn("erasure record", str(ctx.exception))
        log.close()

    def test_erase_removes_pii_and_preserves_chain(self):
        log = AuditLog(self.dir)
        heads = []
        for i in range(10):
            log.append(Entry(actor="a", action=f"op{i}", session_id="s",
                             subject_id=SUBJECT, pii=_pii()))
            heads.append(log.head())
        log.erase(SUBJECT, batch_size=3)
        log.verify(heads)
        # erase is idempotent
        log.erase(SUBJECT)
        log.verify(heads)
        # post-erase append for the same subject works and keeps no key
        seq = log.append(Entry(actor="b", action="post", session_id="s",
                               subject_id=SUBJECT, pii=_pii()))
        self.assertEqual(seq, 12)
        log.verify(heads)
        log.close()
        hits = _scan_dir_for(self.dir, [PHONE.encode(), NAME.encode("utf-8")])
        self.assertEqual(hits, [])
        self.assertEqual(os.listdir(os.path.join(self.dir, "keys")), [])


class AuditLogConcurrencyTest(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp(prefix="auditlog-mp-")
        self.addCleanup(shutil.rmtree, self.dir, True)
        self.ctx = mp.get_context("spawn")

    def _assert_no_pii_left(self):
        hits = _scan_dir_for(self.dir, [PHONE.encode(), NAME.encode("utf-8")])
        self.assertEqual(hits, [])
        self.assertEqual(os.listdir(os.path.join(self.dir, "keys")), [])

    def _assert_chain_linear(self, expected_count):
        con = sqlite3.connect(os.path.join(self.dir, "audit.db"))
        n = con.execute("SELECT COUNT(*) FROM entries").fetchone()[0]
        self.assertEqual(n, expected_count)
        dup = con.execute(
            "SELECT prev_hash, COUNT(*) c FROM entries"
            " GROUP BY prev_hash HAVING c > 1"
        ).fetchall()
        self.assertEqual(dup, [])
        seqs = [r[0] for r in con.execute("SELECT seq FROM entries ORDER BY seq")]
        self.assertEqual(seqs, list(range(1, n + 1)))
        con.close()

    def test_concurrent_appends_with_mid_erase(self):
        stop = self.ctx.Event()
        counter = self.ctx.Queue()
        workers = [
            self.ctx.Process(
                target=_appender, args=(self.dir, SUBJECT, stop, counter, i)
            )
            for i in range(3)
        ]
        for w in workers:
            w.start()
        # Record heads while appends are in flight.
        observer = AuditLog(self.dir)
        heads = []
        deadline = time.time() + 0.6
        while time.time() < deadline:
            h = observer.head()
            if h.seq > 0 and (not heads or heads[-1] != h):
                heads.append(h)
            time.sleep(0.02)
        # Erase from a separate process while appends continue.
        eraser = self.ctx.Process(target=_eraser, args=(self.dir, SUBJECT, 20))
        eraser.start()
        eraser.join(60)
        self.assertEqual(eraser.exitcode, 0)
        # Keep appending after erase returned (post-erase appends).
        time.sleep(0.4)
        heads.append(observer.head())
        stop.set()
        for w in workers:
            w.join(60)
            self.assertEqual(w.exitcode, 0)
        total = 0
        for _ in workers:
            _, n = counter.get(timeout=10)
            total += n
        # Every append landed, plus exactly one erase record.
        self._assert_chain_linear(total + 1)
        observer.verify(heads)
        observer.close()
        self._assert_no_pii_left()

    def test_sigkill_mid_erase_then_recover(self):
        log = AuditLog(self.dir)
        heads = []
        total = 20000
        for i in range(total):
            log.append(
                Entry(actor="a", action=f"op{i}", session_id="s",
                      subject_id=SUBJECT, pii=_pii())
            )
            if i % 5000 == 0:
                heads.append(log.head())
        heads.append(log.head())
        log.close()
        # Start erasing in a child process with tiny batches, then SIGKILL
        # it as soon as the batch-marking phase has begun.
        eraser = self.ctx.Process(
            target=_eraser, args=(self.dir, SUBJECT, 10)
        )
        eraser.start()
        ro = sqlite3.connect(
            f"file:{os.path.join(self.dir, 'audit.db')}?mode=ro", uri=True
        )
        ro.execute("PRAGMA busy_timeout=5000")
        while True:
            n = ro.execute(
                "SELECT COUNT(*) FROM entries WHERE erased=1"
            ).fetchone()[0]
            if n > 0:
                break
            time.sleep(0.002)
        ro.close()
        os.kill(eraser.pid, signal.SIGKILL)
        eraser.join(30)
        self.assertEqual(eraser.exitcode, -signal.SIGKILL)
        # The kill really interrupted the marking phase.
        con = sqlite3.connect(os.path.join(self.dir, "audit.db"))
        marked = con.execute(
            "SELECT COUNT(*) FROM entries WHERE erased=1"
        ).fetchone()[0]
        con.close()
        self.assertLess(marked, total)
        # Any intermediate state must verify against all known heads.
        log = AuditLog(self.dir)
        log.verify(heads)
        # Re-running erase converges to full erasure.
        log.erase(SUBJECT, batch_size=100)
        log.verify(heads)
        log.close()
        self._assert_chain_linear(total + 1)
        self._assert_no_pii_left()


if __name__ == "__main__":
    unittest.main()
