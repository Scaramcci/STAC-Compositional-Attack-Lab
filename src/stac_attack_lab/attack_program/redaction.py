"""Bounded secret-pattern screen for public planner material."""

from __future__ import annotations

import re
from typing import Any

SECRET_PATTERNS = (
    re.compile(r"(?i)\bBearer\s+[A-Za-z0-9._~+/=-]{16,}"),
    re.compile(r"\bsk-[A-Za-z0-9_-]{16,}\b"),
    re.compile(r"\bAIza[A-Za-z0-9_-]{20,}\b"),
    re.compile(
        r"(?i)\b(?:api[_-]?key|token|authorization|password|passwd|secret|credential)"
        r"\s*[=:]\s*[^\s,;]+"
    ),
)


def scan_for_secrets(value: Any, exact_secrets: list[str] | None = None) -> list[str]:
    serialized = str(value)
    findings: list[str] = []
    for secret in exact_secrets or []:
        if secret and secret in serialized:
            findings.append("exact_secret_present")
    for pattern in SECRET_PATTERNS:
        for match in pattern.finditer(serialized):
            if "CANARY_" not in match.group(0):
                findings.append("secret_pattern_present")
    return sorted(set(findings))
