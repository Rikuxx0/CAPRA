from __future__ import annotations

import re


def slugify(value: str | None) -> str:
    text = str(value or "unknown").strip().lower()
    text = re.sub(r"[^a-z0-9:_./-]+", "-", text)
    text = re.sub(r"-+", "-", text).strip("-")
    return text or "unknown"


def generate_node_id(name: str | None, node_type: str = "unknown", cloud: str = "unknown") -> str:
    return f"{slugify(cloud)}:{slugify(node_type)}:{slugify(name)}"


def generate_vulnerability_id(prefix: str, index: int, hint: str | None = None) -> str:
    suffix = slugify(hint) if hint else str(index)
    return f"{prefix}:{index}:{suffix}"
