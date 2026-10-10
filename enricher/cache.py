"""Tiny JSON-file cache so repeated lookups don't burn free-tier API quota."""

from __future__ import annotations

import json
import time
from dataclasses import asdict
from pathlib import Path

from .providers import ProviderResult

DEFAULT_TTL = 3600  # seconds


class Cache:
    def __init__(self, path: Path | None, ttl: int = DEFAULT_TTL, now=time.time):
        self.path = path
        self.ttl = ttl
        self.now = now
        self._data: dict = {}
        if path and path.exists():
            try:
                self._data = json.loads(path.read_text())
            except (OSError, json.JSONDecodeError):
                self._data = {}

    @staticmethod
    def _key(provider: str, value: str) -> str:
        # "v2": entries written before ProviderResult.facts existed are ignored.
        return f"v2|{provider}|{value}"

    def get(self, provider: str, value: str) -> ProviderResult | None:
        entry = self._data.get(self._key(provider, value))
        if not entry or self.now() - entry["ts"] > self.ttl:
            return None
        return ProviderResult(**entry["result"])

    def put(self, provider: str, value: str, result: ProviderResult) -> None:
        # Only cache definitive answers, never transient errors or skips.
        if result.status not in ("ok", "not_found"):
            return
        self._data[self._key(provider, value)] = {"ts": self.now(), "result": asdict(result)}

    def save(self) -> None:
        if not self.path:
            return
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.path.write_text(json.dumps(self._data))
