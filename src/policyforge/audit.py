from __future__ import annotations

import fcntl
import hashlib
import hmac
import json
import os
import time
from pathlib import Path
from threading import RLock
from typing import Any

from .models import AuthorizationRequest, Decision

_GENESIS = "0" * 64


class AuditIntegrityError(RuntimeError):
    pass


class AuditLedger:
    def __init__(self, path: str | Path, secret: bytes) -> None:
        if len(secret) < 32:
            raise ValueError("audit HMAC key must contain at least 32 bytes")
        self._path = Path(path)
        self._secret = bytes(secret)
        self._lock = RLock()

    def record(self, request: AuthorizationRequest, decision: Decision) -> None:
        with self._lock:
            self._path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
            fd = os.open(
                self._path,
                os.O_RDWR | os.O_APPEND | os.O_CREAT | os.O_CLOEXEC,
                0o600,
            )
            try:
                fcntl.flock(fd, fcntl.LOCK_EX)
                count, previous_hash = self._verify_descriptor(fd)
                body: dict[str, Any] = {
                    "sequence": count + 1,
                    "previous_hash": previous_hash,
                    "recorded_at_ns": time.time_ns(),
                    "request_id": request.request_id,
                    "tenant_id": request.principal.tenant_id,
                    "principal_id": request.principal.principal_id,
                    "action": request.action,
                    "resource": f"{request.resource.resource_type}:{request.resource.resource_id}",
                    "allowed": decision.allowed,
                    "reason": decision.reason,
                    "policy_version": decision.policy_version,
                    "matched_rule_ids": list(decision.matched_rule_ids),
                    "cache_hit": decision.cache_hit,
                }
                body["entry_hash"] = self._sign(body)
                line = _canonical(body) + b"\n"
                os.lseek(fd, 0, os.SEEK_END)
                _write_all(fd, line)
                os.fsync(fd)
            finally:
                try:
                    fcntl.flock(fd, fcntl.LOCK_UN)
                finally:
                    os.close(fd)

    def verify(self) -> int:
        with self._lock:
            try:
                fd = os.open(self._path, os.O_RDONLY | os.O_CLOEXEC)
            except FileNotFoundError:
                return 0
            try:
                fcntl.flock(fd, fcntl.LOCK_SH)
                count, _ = self._verify_descriptor(fd)
                return count
            finally:
                try:
                    fcntl.flock(fd, fcntl.LOCK_UN)
                finally:
                    os.close(fd)

    def _verify_descriptor(self, fd: int) -> tuple[int, str]:
        os.lseek(fd, 0, os.SEEK_SET)
        raw = _read_all(fd)
        previous_hash = _GENESIS
        count = 0
        for line_number, line in enumerate(raw.splitlines(), start=1):
            if not line:
                raise AuditIntegrityError(f"empty audit entry at line {line_number}")
            try:
                entry = json.loads(line)
            except json.JSONDecodeError as error:
                raise AuditIntegrityError(f"invalid JSON at audit line {line_number}") from error
            if not isinstance(entry, dict):
                raise AuditIntegrityError(f"audit line {line_number} is not an object")
            entry_hash = entry.pop("entry_hash", None)
            if entry.get("sequence") != count + 1:
                raise AuditIntegrityError(f"audit sequence mismatch at line {line_number}")
            if entry.get("previous_hash") != previous_hash:
                raise AuditIntegrityError(f"audit chain mismatch at line {line_number}")
            expected = self._sign(entry)
            if not isinstance(entry_hash, str) or not hmac.compare_digest(entry_hash, expected):
                raise AuditIntegrityError(f"audit HMAC mismatch at line {line_number}")
            previous_hash = entry_hash
            count += 1
        return count, previous_hash

    def _sign(self, entry: dict[str, Any]) -> str:
        return hmac.new(self._secret, _canonical(entry), hashlib.sha256).hexdigest()


def _canonical(value: Any) -> bytes:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode()


def _read_all(fd: int) -> bytes:
    chunks: list[bytes] = []
    while True:
        chunk = os.read(fd, 65_536)
        if not chunk:
            return b"".join(chunks)
        chunks.append(chunk)


def _write_all(fd: int, data: bytes) -> None:
    offset = 0
    while offset < len(data):
        written = os.write(fd, data[offset:])
        if written == 0:
            raise OSError("audit write returned zero bytes")
        offset += written
