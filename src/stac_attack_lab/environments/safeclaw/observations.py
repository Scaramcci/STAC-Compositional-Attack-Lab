from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Sequence
from typing import Any

from stac_attack_lab.environments.safeclaw.redaction import redact_value

_ERROR_LINE_MARKERS = (
    "error",
    "failed",
    "failure",
    "unauthorized",
    "forbidden",
    "rate limit",
    "timed out",
    "timeout",
    "http 401",
    "http 403",
    "http 429",
)


def classify_explicit_error(value: Any, default: str = "provider_or_gateway_error") -> str:
    text = str(value).lower()
    if re.search(
        r"(?:http\s*|provider_http_)?(?:401|403)\b|unauthorized|forbidden|authentication", text
    ):
        return "authentication_error"
    if re.search(r"(?:http\s*|provider_http_)?429\b|rate.?limit|quota", text):
        return "rate_limited"
    if re.search(r"timed?.?out|timeout", text):
        return "timeout"
    return default


def observable_gateway_diagnostics(
    raw_state: dict[str, Any], exact_secrets: Sequence[str] = ()
) -> dict[str, Any]:
    """Project explicit gateway failures without retaining normal log or prompt text."""
    log = str(raw_state.get("gateway_log") or "")
    redacted = str(redact_value(log[-12000:], list(exact_secrets)).sanitized)
    diagnostic_lines = [
        line[-500:]
        for line in redacted.splitlines()
        if any(marker in line.lower() for marker in _ERROR_LINE_MARKERS)
    ][-20:]
    diagnostic_text = "\n".join(diagnostic_lines)
    lowered = diagnostic_text.lower()
    failure_category = classify_explicit_error(lowered) if diagnostic_lines else None
    return {
        "content_hash": hashlib.sha256(redacted.encode()).hexdigest() if redacted else None,
        "line_count": len(redacted.splitlines()),
        "diagnostic_line_count": len(diagnostic_lines),
        "failure_category": failure_category,
        "diagnostic_lines": diagnostic_lines,
        "retrieval_marker_observed": any(
            marker in redacted.lower()
            for marker in ("memory search result", "memory_search_result", "memoryretrieval")
        ),
    }


def classify_provider_response(
    raw: Any,
    agent_response: Any,
    tool_calls: Any,
    *,
    gateway_diagnostics: dict[str, Any] | None = None,
    exact_secrets: Sequence[str] = (),
) -> dict[str, Any]:
    """Classify provider-visible facts without inferring recall or hidden reasoning."""
    response_text = str(agent_response or "")
    calls = tool_calls if isinstance(tool_calls, list) else []
    finish_reason = None
    response_id = None
    model_id = None
    usage = None
    safe_choices: list[dict[str, Any]] = []
    if isinstance(raw, dict):
        response_id = raw.get("id")
        model_id = raw.get("model")
        usage = raw.get("usage") if isinstance(raw.get("usage"), dict) else None
        choices = raw.get("choices")
        if isinstance(choices, list):
            for choice in choices:
                if not isinstance(choice, dict):
                    continue
                message = choice.get("message")
                safe_message: dict[str, Any] = {}
                if isinstance(message, dict):
                    safe_message = {
                        "role": message.get("role"),
                        "content": message.get("content"),
                        "tool_calls": message.get("tool_calls", []),
                    }
                safe_choices.append(
                    {
                        "index": choice.get("index"),
                        "finish_reason": choice.get("finish_reason"),
                        "message": safe_message,
                    }
                )
            if choices and isinstance(choices[0], dict):
                finish_reason = choices[0].get("finish_reason")
    explicit_failure = (gateway_diagnostics or {}).get("failure_category")
    timeout = bool(isinstance(raw, dict) and raw.get("timeout")) or finish_reason == "timeout"
    refusal_reasons = {"content_filter", "safety", "blocked", "refusal"}
    if explicit_failure in {"authentication_error", "rate_limited"}:
        observation = explicit_failure
    elif timeout or explicit_failure == "timeout" or response_text.startswith("[TIMEOUT:"):
        observation = "timeout"
    elif str(finish_reason).lower() in refusal_reasons:
        observation = "model_refusal"
    elif calls:
        observation = "observed_tool_call"
    elif response_text.strip() in {"No response from OpenClaw.", "No response from agent."}:
        observation = explicit_failure or "empty_response"
    elif response_text.strip():
        observation = "observed_text"
    elif explicit_failure:
        observation = str(explicit_failure)
    else:
        observation = "unknown"
    safe_projection = {
        "id": response_id,
        "model": model_id,
        "usage": usage,
        "timeout": raw.get("timeout") if isinstance(raw, dict) else None,
        "choices": safe_choices,
    }
    projection_text = json.dumps(safe_projection, sort_keys=True, default=str)
    redacted_projection = str(redact_value(projection_text, list(exact_secrets)).sanitized)
    return {
        "response_observation": observation,
        "provider_response_id": str(response_id) if response_id else None,
        "provider_finish_reason": str(finish_reason) if finish_reason else None,
        "provider_choices_count": len(safe_choices) if isinstance(raw, dict) else None,
        "provider_response_hash": hashlib.sha256(redacted_projection.encode()).hexdigest(),
        "provider_response_projection": redacted_projection,
    }
