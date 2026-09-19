"""Validated policy contract for bounded provider-boundary evidence."""

from __future__ import annotations

import re
from typing import Any

from stac_attack_lab.hashing import stable_hash

POLICY_VERSION = "1.0"
EXACT_DERIVATION_RULE = "stac.experimental.exact_tool_result_to_argument.v1"
UTF8_STRING_PROJECTION = "utf8-string-v1"
DEFAULT_MAX_PROJECTION_BYTES = 16_384
KNOWN_TARGET_TOOLS = frozenset({"add", "exec", "write", "edit"})
_POLICY_ID = re.compile(r"^[a-z0-9][a-z0-9._-]{2,127}$")


def disabled_provider_evidence_policy() -> dict[str, Any]:
    return {
        "policy_id": "stac.provider-evidence.disabled",
        "policy_version": POLICY_VERSION,
        "mode": "disabled",
        "enabled": False,
        "rule_id": None,
        "target_selectors": [],
        "projection_kind": UTF8_STRING_PROJECTION,
        "applicability": "synthetic_only",
        "max_projection_bytes": DEFAULT_MAX_PROJECTION_BYTES,
    }


def _validate_pointer(pointer: object) -> str:
    if not isinstance(pointer, str):
        raise ValueError("provider_evidence_selector_pointer_type")
    if pointer == "" or not pointer.startswith("/"):
        raise ValueError("provider_evidence_selector_pointer_invalid")
    for token in pointer[1:].split("/"):
        index = 0
        while index < len(token):
            if token[index] == "~":
                if index + 1 >= len(token) or token[index + 1] not in {"0", "1"}:
                    raise ValueError("provider_evidence_selector_pointer_escape_invalid")
                index += 2
            else:
                index += 1
    return pointer


def validate_provider_evidence_policy(value: object | None) -> dict[str, Any]:
    """Return one canonical policy or reject ambiguous/unknown configuration."""
    if value is None:
        return disabled_provider_evidence_policy()
    if not isinstance(value, dict):
        raise ValueError("provider_evidence_policy_not_object")
    allowed = {
        "policy_id",
        "policy_version",
        "mode",
        "enabled",
        "rule_id",
        "target_selectors",
        "projection_kind",
        "applicability",
        "max_projection_bytes",
    }
    unknown = sorted(set(value) - allowed)
    if unknown:
        raise ValueError("provider_evidence_policy_unknown_fields:" + ",".join(unknown))
    policy = {**disabled_provider_evidence_policy(), **value}
    if value.get("enabled") is True:
        required = allowed
        missing = sorted(required - set(value))
        if missing:
            raise ValueError("provider_evidence_policy_fields_missing:" + ",".join(missing))
    policy_id = policy.get("policy_id")
    if not isinstance(policy_id, str) or not _POLICY_ID.fullmatch(policy_id):
        raise ValueError("provider_evidence_policy_id_invalid")
    if policy.get("policy_version") != POLICY_VERSION:
        raise ValueError("provider_evidence_policy_version_unknown")
    if type(policy.get("enabled")) is not bool:
        raise ValueError("provider_evidence_policy_enabled_not_boolean")
    if policy.get("mode") not in {"disabled", "experimental"}:
        raise ValueError("provider_evidence_policy_mode_unknown")
    if policy.get("projection_kind") != UTF8_STRING_PROJECTION:
        raise ValueError("provider_evidence_projection_kind_unknown")
    if policy.get("applicability") != "synthetic_only":
        raise ValueError("provider_evidence_policy_applicability_unknown")
    limit = policy.get("max_projection_bytes")
    if type(limit) is not int or limit < 1 or limit > DEFAULT_MAX_PROJECTION_BYTES:
        raise ValueError("provider_evidence_policy_size_limit_invalid")
    selectors = policy.get("target_selectors")
    if not isinstance(selectors, list):
        raise ValueError("provider_evidence_selectors_not_list")
    canonical_selectors: list[dict[str, str]] = []
    seen: set[tuple[str, str]] = set()
    for selector in selectors:
        if not isinstance(selector, dict) or set(selector) != {"tool_name", "json_pointer"}:
            raise ValueError("provider_evidence_selector_invalid")
        tool = selector.get("tool_name")
        if not isinstance(tool, str) or tool not in KNOWN_TARGET_TOOLS:
            raise ValueError("provider_evidence_selector_tool_unknown")
        pointer = _validate_pointer(selector.get("json_pointer"))
        key = (tool, pointer)
        if key in seen:
            raise ValueError("provider_evidence_selector_duplicate")
        seen.add(key)
        canonical_selectors.append({"tool_name": tool, "json_pointer": pointer})
    enabled = policy["enabled"]
    if enabled:
        if policy.get("mode") != "experimental":
            raise ValueError("provider_evidence_enabled_mode_mismatch")
        if policy.get("rule_id") != EXACT_DERIVATION_RULE:
            raise ValueError("provider_evidence_rule_unknown")
        if not canonical_selectors:
            raise ValueError("provider_evidence_selectors_required")
    else:
        if policy.get("mode") != "disabled":
            raise ValueError("provider_evidence_disabled_mode_mismatch")
        if policy.get("rule_id") is not None or canonical_selectors:
            raise ValueError("provider_evidence_disabled_policy_has_rule")
    policy["target_selectors"] = canonical_selectors
    return policy


def provider_evidence_policy_hash(policy: dict[str, Any]) -> str:
    return stable_hash(validate_provider_evidence_policy(policy))


def selector_allowed(policy: dict[str, Any], tool_name: object, pointer: object) -> bool:
    return any(
        item["tool_name"] == tool_name and item["json_pointer"] == pointer
        for item in policy["target_selectors"]
    )
