from __future__ import annotations

import time
from collections import OrderedDict
from collections.abc import Callable
from dataclasses import dataclass
from threading import RLock

from .models import Decision


@dataclass(frozen=True, slots=True)
class _Entry:
    expires_at: float
    decision: Decision


class DecisionCache:
    def __init__(
        self,
        *,
        maximum_entries: int = 10_000,
        ttl_seconds: float = 5.0,
        monotonic: Callable[[], float] = time.monotonic,
    ) -> None:
        if maximum_entries < 1:
            raise ValueError("maximum_entries must be positive")
        if ttl_seconds <= 0:
            raise ValueError("ttl_seconds must be positive")
        self._maximum_entries = maximum_entries
        self._ttl_seconds = ttl_seconds
        self._monotonic = monotonic
        self._entries: OrderedDict[tuple[str, str], _Entry] = OrderedDict()
        self._lock = RLock()

    def get(self, tenant_id: str, key: str) -> Decision | None:
        with self._lock:
            compound = (tenant_id, key)
            entry = self._entries.get(compound)
            if entry is None:
                return None
            if entry.expires_at <= self._monotonic():
                del self._entries[compound]
                return None
            self._entries.move_to_end(compound)
            return entry.decision

    def put(self, tenant_id: str, key: str, decision: Decision) -> None:
        with self._lock:
            compound = (tenant_id, key)
            self._entries[compound] = _Entry(self._monotonic() + self._ttl_seconds, decision)
            self._entries.move_to_end(compound)
            while len(self._entries) > self._maximum_entries:
                self._entries.popitem(last=False)

    def invalidate_tenant(self, tenant_id: str) -> None:
        with self._lock:
            for key in [key for key in self._entries if key[0] == tenant_id]:
                del self._entries[key]
