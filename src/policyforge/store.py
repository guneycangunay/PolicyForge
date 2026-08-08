from __future__ import annotations

import json
import os
import re
import tempfile
from collections.abc import Mapping
from pathlib import Path
from typing import Any

_TENANT_ID = re.compile(r"^[a-zA-Z0-9][a-zA-Z0-9._-]{0,63}$")


class PolicyFileStore:
    def __init__(self, directory: str | Path) -> None:
        self._directory = Path(directory)

    def save(self, tenant_id: str, document: Mapping[str, Any]) -> None:
        _validate_tenant(tenant_id)
        self._directory.mkdir(parents=True, exist_ok=True, mode=0o700)
        target = self._directory / f"{tenant_id}.json"
        descriptor, temporary = tempfile.mkstemp(
            prefix=f".{tenant_id}.", suffix=".tmp", dir=self._directory
        )
        try:
            with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
                json.dump(document, stream, indent=2, sort_keys=True, ensure_ascii=False, allow_nan=False)
                stream.write("\n")
                stream.flush()
                os.fsync(stream.fileno())
            os.chmod(temporary, 0o600)
            os.replace(temporary, target)
        finally:
            try:
                os.unlink(temporary)
            except FileNotFoundError:
                pass

    def load_all(self) -> list[dict[str, Any]]:
        if not self._directory.exists():
            return []
        documents: list[dict[str, Any]] = []
        for filename in sorted(self._directory.glob("*.json")):
            _validate_tenant(filename.stem)
            with filename.open(encoding="utf-8") as stream:
                document = json.load(stream)
            if not isinstance(document, dict):
                raise ValueError(f"policy file {filename} must contain an object")
            documents.append(document)
        return documents


def _validate_tenant(tenant_id: str) -> None:
    if not _TENANT_ID.fullmatch(tenant_id):
        raise ValueError("invalid tenant identifier")
