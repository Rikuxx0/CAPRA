from __future__ import annotations

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


# スキャナごとの差分を吸収して CAPRA 用の severity ラベルへ変換する。
def normalize_severity(severity: str | None) -> str:
    """Normalize scanner severity labels into CAPRA's labels."""
    return _ALIASES.get(str(severity or "").strip().lower(), "Unknown")
