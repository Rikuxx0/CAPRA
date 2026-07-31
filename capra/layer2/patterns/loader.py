from __future__ import annotations

from collections.abc import Sequence
from pathlib import Path

import yaml

from ..ids import stable_hash
from .models import PatternRuleModel

DEFAULT_PATTERN_PATH = Path(__file__).parents[1] / "rules" / "iamhounddog_patterns.yaml"


def load_pattern_rules(
    path: str | Path | Sequence[str | Path] = DEFAULT_PATTERN_PATH,
) -> tuple[list[PatternRuleModel], str, str]:
    paths = [Path(item) for item in path] if isinstance(path, Sequence) and not isinstance(path, (str, bytes)) else [Path(path)]
    payloads: list[dict] = []
    rules: list[PatternRuleModel] = []
    versions: set[str] = set()
    rule_sources: dict[str, Path] = {}

    for rule_path in paths:
        raw = rule_path.read_text(encoding="utf-8")
        payload = yaml.safe_load(raw) or {}
        if not isinstance(payload, dict):
            raise ValueError(f"IAMHoundDog pattern YAML must be an object: {rule_path}")
        raw_rules = payload.get("rules")
        if raw_rules is None and payload.get("id"):
            raw_rules = [payload]
        if not isinstance(raw_rules, list):
            raise ValueError(f"IAMHoundDog pattern YAML must contain a rules list: {rule_path}")
        payloads.append(payload)
        versions.add(str(payload.get("version") or "unknown"))
        for raw_rule in raw_rules:
            rule = PatternRuleModel.model_validate(raw_rule)
            if rule.id in rule_sources:
                raise ValueError(
                    f"Duplicate IAMHoundDog rule id {rule.id!r} in "
                    f"{rule_sources[rule.id]} and {rule_path}"
                )
            rule_sources[rule.id] = rule_path
            rules.append(rule)

    canonical_payloads = sorted(payloads, key=stable_hash)
    return sorted(rules, key=lambda rule: rule.id), ",".join(sorted(versions)), stable_hash(canonical_payloads)
