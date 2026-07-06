from __future__ import annotations

SEVERITY_SCORES: dict[str, float] = {
    "Critical": 1.0,
    "High": 0.8,
    "Medium": 0.5,
    "Low": 0.2,
    "Negligible": 0.1,
    "Unknown": 0.0,
}

_ALIASES = {
    "critical": "Critical",
    "high": "High",
    "medium": "Medium",
    "moderate": "Medium",
    "low": "Low",
    "negligible": "Negligible",
    "info": "Negligible",
    "informational": "Negligible",
    "none": "Unknown",
    "unknown": "Unknown",
    "error": "Unknown",
    "warning": "Medium",
    "note": "Low",
}


def normalize_severity(severity: str | None) -> tuple[str, float]:
    """Normalize scanner severity labels into CAPRA's provisional scale."""
    normalized = _ALIASES.get(str(severity or "").strip().lower(), "Unknown")
    return normalized, SEVERITY_SCORES[normalized]
