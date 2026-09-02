from __future__ import annotations

import re
from pathlib import Path
from typing import Any

from pydantic import Field

from stac_attack_lab.contracts import StrictModel

REDACTED = "***REDACTED***"
SENSITIVE_KEY = re.compile(
    r"(^|_)(api_?key|key|token|authorization|password|passwd|secret|credential)($|_)",
    re.IGNORECASE,
)
SECRET_PATTERNS = (
    re.compile(r"(?i)\bBearer\s+[A-Za-z0-9._~+/=-]{16,}"),
    re.compile(r"\bsk-[A-Za-z0-9_-]{16,}\b"),
    re.compile(r"\bAIza[A-Za-z0-9_-]{20,}\b"),
    re.compile(
        r"(?i)\b(?:api[_-]?key|token|authorization|password|passwd|secret|credential)"
        r"\s*[=:]\s*[^\s,;]+"
    ),
)


class RedactionFinding(StrictModel):
    path: str
    reason_code: str


class RedactionResult(StrictModel):
    sanitized: Any
    findings: list[RedactionFinding] = Field(default_factory=list)


def _redact_text(
    text: str, exact_secrets: list[str], path: str
) -> tuple[str, list[RedactionFinding]]:
    result = text
    findings: list[RedactionFinding] = []
    for secret in sorted((item for item in exact_secrets if item), key=len, reverse=True):
        if secret in result:
            result = result.replace(secret, REDACTED)
            findings.append(RedactionFinding(path=path, reason_code="exact_secret_redacted"))
    for pattern in SECRET_PATTERNS:
        matches = list(pattern.finditer(result))
        for match in reversed(matches):
            if "CANARY_" in match.group(0):
                continue
            result = result[: match.start()] + REDACTED + result[match.end() :]
            findings.append(RedactionFinding(path=path, reason_code="secret_pattern_redacted"))
    return result, findings


def redact_value(
    value: Any,
    exact_secrets: list[str] | None = None,
    *,
    path: str = "$",
) -> RedactionResult:
    secrets = exact_secrets or []
    if isinstance(value, dict):
        sanitized: dict[str, Any] = {}
        findings: list[RedactionFinding] = []
        for key, child in value.items():
            child_path = f"{path}.{key}"
            if SENSITIVE_KEY.search(str(key)) and "canary" not in str(key).lower():
                sanitized[str(key)] = child if child in (None, "", [], {}) else REDACTED
                if child not in (None, "", [], {}):
                    findings.append(
                        RedactionFinding(path=child_path, reason_code="sensitive_key_redacted")
                    )
                continue
            result = redact_value(child, secrets, path=child_path)
            sanitized[str(key)] = result.sanitized
            findings.extend(result.findings)
        return RedactionResult(sanitized=sanitized, findings=findings)
    if isinstance(value, list):
        sanitized_items: list[Any] = []
        findings = []
        for index, child in enumerate(value):
            result = redact_value(child, secrets, path=f"{path}[{index}]")
            sanitized_items.append(result.sanitized)
            findings.extend(result.findings)
        return RedactionResult(sanitized=sanitized_items, findings=findings)
    if isinstance(value, str):
        sanitized_text, findings = _redact_text(value, secrets, path)
        return RedactionResult(sanitized=sanitized_text, findings=findings)
    return RedactionResult(sanitized=value)


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


def scan_tree(path: Path, exact_secrets: list[str] | None = None) -> list[str]:
    findings: list[str] = []
    for file_path in sorted(item for item in path.rglob("*") if item.is_file()):
        try:
            text = file_path.read_text(encoding="utf-8")
        except UnicodeDecodeError:
            continue
        for finding in scan_for_secrets(text, exact_secrets):
            findings.append(f"{file_path.relative_to(path)}:{finding}")
    return findings
