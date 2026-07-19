from __future__ import annotations

from pathlib import Path

import yaml

from ..ids import stable_hash
from .models import PatternRuleModel

DEFAULT_PATTERN_PATH = Path(__file__).parents[1] / "rules" / "iamhounddog_patterns.yaml"


def load_pattern_rules(path: str | Path = DEFAULT_PATTERN_PATH) -> tuple[list[PatternRuleModel], str, str]:
    raw = Path(path).read_text(encoding="utf-8")
    payload = yaml.safe_load(raw) or {}
    raw_rules = payload.get("rules") if isinstance(payload, dict) else None
    if raw_rules is None and isinstance(payload, dict) and payload.get("id"):
        raw_rules = [payload]
    if not isinstance(raw_rules, list):
        raise ValueError("IAMHoundDog pattern YAML must contain a rules list")
    rules = sorted((PatternRuleModel.model_validate(rule) for rule in raw_rules), key=lambda rule: rule.id)
    return rules, str(payload.get("version") or "unknown"), stable_hash(payload)
