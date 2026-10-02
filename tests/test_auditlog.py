import json
import os
import shutil
import tempfile
import unittest

from auditlog import AuditLog

NAME = "ZhangWei_TESTNAME_9f3a"
PHONE = "13900001234"
PII = {"name": NAME, "phone": PHONE}


def scan_dir_for(path, needles):
    """Return list of (filename, needle) where needle bytes appear."""
    hits = []
    for fname in os.listdir(path):
        fpath = os.path.join(path, fname)
        if not os.path.isfile(fpath):
            continue
        with open(fpath, "rb") as fh:
            data = fh.read()
        for needle in needles:
            if needle.encode() in data:
                hits.append((fname, needle))
    return hits


class AuditLogTestBase(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp(prefix="auditlog-test-")
        self.db = os.path.join(self.dir, "audit.db")
        self.addCleanup(shutil.rmtree, self.dir, True)

    def open_log(self):
        log = AuditLog(self.db)
        self.addCleanup(log.close)
        return log


class TestChain(AuditLogTestBase):
    def test_append_head_verify(self):
        log = self.open_log()
        heads = []
        for i in range(50):
            seq = log.append("alice", "op", "sess", subject_id="u1", pii=PII)
            assert seq == i + 1
            heads.append(log.head())
        self.assertEqual(log.verify(heads), [])
        self.assertEqual(log.verify([]), [])
        self.assertEqual(log.read_pii(1), PII)

    def test_tamper_field_points_to_entry(self):
        log = self.open_log()
        for _ in range(10):
            log.append("alice", "op", "sess")
        log.con.execute("UPDATE entries SET actor='mallory' WHERE seq=7")
        issues = log.verify()
        self.assertTrue(any("entry 7" in i for i in issues), issues)

    def test_delete_entry_detected(self):
        log = self.open_log()
        for _ in range(10):
            log.append("alice", "op", "sess")
        log.con.execute("DELETE FROM entries WHERE seq=5")
        issues = log.verify()
        self.assertTrue(issues, "deletion must be detected")

    def test_reorder_detected(self):
        log = self.open_log()
        for _ in range(5):
            log.append("alice", "op", "sess")
        log.con.execute("UPDATE entries SET seq=100 WHERE seq=3")
        log.con.execute("UPDATE entries SET seq=3 WHERE seq=4")
        log.con.execute("UPDATE entries SET seq=4 WHERE seq=100")
        issues = log.verify()
        self.assertTrue(issues, "reorder must be detected")

    def test_truncation_before_known_head(self):
        log = self.open_log()
        heads = []
        for _ in range(10):
            log.append("alice", "op", "sess")
            heads.append(log.head())
        log.con.execute("DELETE FROM entries WHERE seq > 6")
        issues = log.verify(heads)
        self.assertTrue(any("truncated" in i for i in issues), issues)


class TestErase(AuditLogTestBase):
    def test_erase_keeps_chain_valid_and_shreds_pii(self):
        log = self.open_log()
        heads = []
        for _ in range(30):
            log.append("bob", "update", "s", subject_id="victim", pii=PII)
            heads.append(log.head())
        log.append("carol", "login", "s2")
        heads.append(log.head())
        log.erase("victim", batch_size=4)
        # every head recorded before the erase still verifies
        self.assertEqual(log.verify(heads), [])
        # key destroyed: PII unreadable through the API
        self.assertIsNone(log.read_pii(1))
        # other subjects unaffected
        self.assertEqual(log.read_pii(31), {})
        log.close()
        hits = scan_dir_for(self.dir, [NAME, PHONE])
        self.assertEqual(hits, [], f"PII plaintext leaked in {hits}")

    def test_erase_is_idempotent(self):
        log = self.open_log()
        for _ in range(5):
            log.append("bob", "update", "s", subject_id="victim", pii=PII)
        log.erase("victim", batch_size=2)
        log.erase("victim", batch_size=2)
        self.assertEqual(log.verify(), [])

    def test_append_after_erase_has_unrecoverable_pii(self):
        log = self.open_log()
        log.append("bob", "update", "s", subject_id="victim", pii=PII)
        log.erase("victim")
        seq = log.append("bob", "update", "s", subject_id="victim", pii=PII)
        self.assertIsNone(log.read_pii(seq))
        self.assertEqual(log.verify(), [])
        log.close()
        hits = scan_dir_for(self.dir, [NAME, PHONE])
        self.assertEqual(hits, [], f"PII plaintext leaked in {hits}")

    def test_erased_state_without_record_is_tamper(self):
        log = self.open_log()
        log.append("bob", "update", "s", subject_id="u9", pii=PII)
        log.con.execute("UPDATE entries SET erased=1 WHERE seq=1")
        issues = log.verify()
        self.assertTrue(any("no erase record" in i for i in issues), issues)


def _append_worker(db_path, subject, count, result_queue):
    """Child process: append `count` entries, report their seqs."""
    import random
    import time as _time

    from auditlog import AuditLog

    log = AuditLog(db_path)
    seqs = []
    try:
        for _ in range(count):
            seqs.append(log.append("worker", "op", "sess",
                                   subject_id=subject, pii=PII))
            _time.sleep(random.random() * 0.002)
    finally:
        log.close()
    result_queue.put(seqs)


def _erase_worker(db_path, subject, batch_size, batch_delay):
    """Child process: run a slow, batched erase (SIGKILL target)."""
    import time as _time

    from auditlog import AuditLog

    log = AuditLog(db_path)
    try:
        log.erase(subject, batch_size=batch_size,
                  batch_hook=lambda: _time.sleep(batch_delay))
    finally:
        log.close()


class TestConcurrency(AuditLogTestBase):
    def test_concurrent_appends_and_erase(self):
        import multiprocessing as mp
        import threading
        import time

        ctx = mp.get_context("spawn")
        results = ctx.Queue()
        workers = [
            ctx.Process(target=_append_worker,
                        args=(self.db, "victim", 60, results))
            for _ in range(3)
        ]
        for w in workers:
            w.start()

        # sample heads from a dedicated connection while workers run
        sampled_heads = []
        stop = threading.Event()

        def sampler():
            from auditlog import AuditLog
            log = AuditLog(self.db)
            try:
                while not stop.is_set():
                    sampled_heads.append(log.head())
                    time.sleep(0.01)
            finally:
                log.close()

        t = threading.Thread(target=sampler)
        t.start()
        time.sleep(0.3)  # let workers get going, then erase mid-stream
        eraser = self.open_log()
        eraser.erase("victim", batch_size=10)
        for w in workers:
            w.join(60)
        stop.set()
        t.join()
        for w in workers:
            self.assertEqual(w.exitcode, 0)

        seqs = []
        for _ in workers:
            seqs.extend(results.get())
        # no entry lost, chain is a perfect 1..N sequence
        final_seq, _ = eraser.head()
        self.assertEqual(len(seqs), 180)
        self.assertEqual(len(set(seqs)), 180)
        count = eraser.con.execute("SELECT COUNT(*) FROM entries").fetchone()[0]
        self.assertEqual(count, final_seq)
        # every head sampled during the run still verifies
        self.assertEqual(eraser.verify(sampled_heads), [])
        # PII plaintext is gone from every file in the db directory
        eraser.close()
        hits = scan_dir_for(self.dir, [NAME, PHONE])
        self.assertEqual(hits, [], f"PII plaintext leaked in {hits}")


class TestSigkillDuringErase(AuditLogTestBase):
    def test_sigkill_mid_erase_then_resume(self):
        import multiprocessing as mp
        import os as _os
        import signal
        import time

        log = self.open_log()
        heads = []
        for _ in range(800):
            log.append("bob", "update", "s", subject_id="victim", pii=PII)
        heads.append(log.head())
        log.close()

        ctx = mp.get_context("spawn")
        killer_target = ctx.Process(
            target=_erase_worker, args=(self.db, "victim", 10, 0.02)
        )
        killer_target.start()

        # wait until the erase has actually started marking entries
        watcher = AuditLog(self.db)
        self.addCleanup(watcher.close)
        deadline = time.time() + 30
        while time.time() < deadline:
            n = watcher.con.execute(
                "SELECT COUNT(*) FROM entries WHERE erased=1"
            ).fetchone()[0]
            if n > 0:
                break
            time.sleep(0.05)
        else:
            self.fail("erase never started marking entries")
        heads.append(watcher.head())
        _os.kill(killer_target.pid, signal.SIGKILL)
        killer_target.join(10)
        self.assertEqual(killer_target.exitcode, -signal.SIGKILL)

        # any intermediate state must still verify
        self.assertEqual(watcher.verify(heads), [])

        # re-running erase converges to full erasure
        watcher.erase("victim", batch_size=50)
        remaining = watcher.con.execute(
            "SELECT COUNT(*) FROM entries WHERE subject_id='victim'"
            " AND erased=0 AND action<>'__erase__'"
        ).fetchone()[0]
        self.assertEqual(remaining, 0)
        self.assertEqual(watcher.verify(heads), [])
        self.assertIsNone(watcher.read_pii(1))
        watcher.close()
        hits = scan_dir_for(self.dir, [NAME, PHONE])
        self.assertEqual(hits, [], f"PII plaintext leaked in {hits}")


if __name__ == "__main__":
    unittest.main()
