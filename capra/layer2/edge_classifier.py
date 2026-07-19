from __future__ import annotations

from typing import Any

from .schemas import EdgeClassification

RELATIONSHIP_TYPES = {
    "attachedpolicy", "assumerole", "contains", "containsserviceaccount", "owns",
    "ownsstoragebucket", "hasgoogleownedsa", "belongsto", "memberof", "instancerole",
    "mountsserviceaccount", "azcontains", "networkaccess", "entrypoint",
}
PERMISSION_TYPES = {
    "haspermission", "permission", "ec2runinstances", "passroleoractas", "canlistkeys",
}
ATTACK_TYPES = {
    "azaddsecret", "azaddmembers", "azmggrantrole", "cancreatekeys", "canimpersonate",
    "canreadsecrets", "canreadsecretsinproject", "cansignblob", "cansignjwt",
    "canmodifybucketpoliciesinproject", "canbind", "canescalate", "cancreatetoken",
    "fullaccess", "canassumeserviceaccount", "canexec", "canattach", "canportforward",
    "cancreateworkload", "canpatch", "cancreateephemeral", "secretsread", "secretscreate",
    "podprivileged", "podhostpid", "podhostnetwork", "podhostipc", "nodesproxyrce",
    "unauthapiaccess", "unauthkubeletaccess", "accessimds",
}


def normalize_edge_key(value: Any) -> str:
    return "".join(character for character in str(value or "").strip().lower() if character.isalnum() or character == ":")


def classify_edge(edge: dict[str, Any]) -> EdgeClassification:
    keys = {
        normalize_edge_key(edge.get("original_edge_type")),
        normalize_edge_key(edge.get("type")),
    }
    if keys & ATTACK_TYPES:
        return EdgeClassification.ATTACK_EDGE
    if keys & RELATIONSHIP_TYPES:
        return EdgeClassification.RELATIONSHIP
    if keys & PERMISSION_TYPES:
        return EdgeClassification.PERMISSION
    permission = str(edge.get("permission") or "").strip()
    if ":" in permission and " " not in permission:
        return EdgeClassification.PERMISSION
    return EdgeClassification.UNKNOWN
