from __future__ import annotations

import logging
import os
import time
from typing import Any

import requests

from .cache import normalize_cve_id

LOGGER = logging.getLogger(__name__)
NVD_ENDPOINT = "https://services.nvd.nist.gov/rest/json/cves/2.0"


class NvdClient:
    def __init__(
        self,
        *,
        timeout_seconds: float = 10.0,
        max_retries: int = 2,
        rate_limit_seconds: float = 0.7,
        session: Any | None = None,
    ):
        self.timeout_seconds = timeout_seconds
        self.max_retries = max(0, int(max_retries))
        self.rate_limit_seconds = max(0.0, float(rate_limit_seconds))
        self.session = session or requests.Session()
        self._last_request_at = 0.0

    def fetch(self, cve_id: str) -> dict[str, Any]:
        normalized = normalize_cve_id(cve_id)
        headers = {"User-Agent": "CAPRA-Layer2/0.1"}
        api_key = os.environ.get("NVD_API_KEY")
        if api_key:
            headers["apiKey"] = api_key
        last_error: Exception | None = None
        for attempt in range(self.max_retries + 1):
            elapsed = time.monotonic() - self._last_request_at
            if elapsed < self.rate_limit_seconds:
                time.sleep(self.rate_limit_seconds - elapsed)
            try:
                response = self.session.get(
                    NVD_ENDPOINT,
                    params={"cveId": normalized},
                    headers=headers,
                    timeout=self.timeout_seconds,
                )
                self._last_request_at = time.monotonic()
                response.raise_for_status()
                payload = response.json()
                if not isinstance(payload, dict):
                    raise ValueError("NVD response root is not an object")
                return payload
            except (requests.RequestException, ValueError) as exc:
                last_error = exc
                LOGGER.warning("NVD request failed for %s (attempt %s)", normalized, attempt + 1)
        raise RuntimeError(f"NVD request failed for {normalized}") from last_error
