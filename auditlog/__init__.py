"""Tamper-evident audit log with crypto-shredding PII erasure.

Public API:
    AuditLog(path)  -- open (or create) a log stored under directory `path`
    AuditLog.append(entry) -> int
    AuditLog.head() -> Head
    AuditLog.erase(subject_id) -> None
    AuditLog.verify(known_heads=()) -> None  (raises VerifyError)
"""

from .core import AuditLog, Entry, Head, VerifyError

__all__ = ["AuditLog", "Entry", "Head", "VerifyError"]
