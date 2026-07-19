from __future__ import annotations

import json
import logging
import re
import tempfile
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from ..ids import stable_hash

LOGGER = logging.getLogger(__name__)
CVE_PATTERN = re.compile(r"^CVE-\d{4}-\d{4,}$", re.I)


def normalize_cve_id(value: str) -> str:
    cve_id = str(value or "").strip().upper()
    if not CVE_PATTERN.fullmatch(cve_id):
        raise ValueError(f"Invalid CVE ID: {value!r}")
    return cve_id


@dataclass(frozen=True)
class CacheReadResult:
    response: dict[str, Any] | None
    status: str
    warning: str | None = None
    cache_hash: str | None = None


class NvdCache:
    def __init__(self, directory: str | Path, ttl_seconds: int = 86400 * 7):
        self.directory = Path(directory)
        self.ttl_seconds = max(0, int(ttl_seconds))

    def path_for(self, cve_id: str) -> Path:
        return self.directory / f"{normalize_cve_id(cve_id)}.json"

    def read(self, cve_id: str, now: datetime | None = None) -> CacheReadResult:
        path = self.path_for(cve_id)
        if not path.exists():
            return CacheReadResult(None, "miss")
        try:
            entry = json.loads(path.read_text(encoding="utf-8"))
            fetched_at = datetime.fromisoformat(str(entry["fetched_at"]).replace("Z", "+00:00"))
            if fetched_at.tzinfo is None:
                fetched_at = fetched_at.replace(tzinfo=timezone.utc)
            age = ((now or datetime.now(timezone.utc)) - fetched_at).total_seconds()
            response = entry["response"]
            if not isinstance(response, dict):
                raise ValueError("response is not an object")
            if age > self.ttl_seconds:
                return CacheReadResult(None, "stale", "NVD cache entry expired")
            return CacheReadResult(response, "hit", cache_hash=stable_hash(entry))
        except (OSError, ValueError, KeyError, TypeError, json.JSONDecodeError) as exc:
            warning = f"Corrupt NVD cache for {normalize_cve_id(cve_id)}: {exc}"
            LOGGER.warning(warning)
            return CacheReadResult(None, "corrupt", warning)

    def write(self, cve_id: str, response: dict[str, Any], fetched_at: datetime | None = None) -> Path:
        normalized = normalize_cve_id(cve_id)
        if not isinstance(response, dict):
            raise ValueError("NVD response must be an object")
        self.directory.mkdir(parents=True, exist_ok=True)
        entry = {
            "cve_id": normalized,
            "fetched_at": (fetched_at or datetime.now(timezone.utc)).isoformat(),
            "response": response,
        }
        with tempfile.NamedTemporaryFile("w", encoding="utf-8", dir=self.directory, prefix=f".{normalized}-", suffix=".tmp", delete=False) as handle:
            json.dump(entry, handle, ensure_ascii=False, sort_keys=True)
            temporary_path = Path(handle.name)
        temporary_path.replace(self.path_for(normalized))
        return self.path_for(normalized)
