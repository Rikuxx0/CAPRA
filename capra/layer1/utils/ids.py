from __future__ import annotations

import re


# ID 用に文字列を小文字・記号制限付きの slug へ変換する。
def slugify(value: str | None) -> str:
    text = str(value or "unknown").strip().lower()
    text = re.sub(r"[^a-z0-9:_./-]+", "-", text)
    text = re.sub(r"-+", "-", text).strip("-")
    return text or "unknown"


# クラウド・種別・名前を組み合わせて安定したノード ID を生成する。
def generate_node_id(name: str | None, node_type: str = "unknown", cloud: str = "unknown") -> str:
    return f"{slugify(cloud)}:{slugify(node_type)}:{slugify(name)}"


# 接頭辞とヒントから脆弱性 ID を一意に組み立てる。
def generate_vulnerability_id(prefix: str, index: int, hint: str | None = None) -> str:
    suffix = slugify(hint) if hint else str(index)
    return f"{prefix}:{index}:{suffix}"
