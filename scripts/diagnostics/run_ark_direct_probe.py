#!/usr/bin/env python3
"""Bounded Ark direct protocol probe; secrets are read from the environment only."""

from __future__ import annotations

import json
import os
import time
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

ROOT = Path(__file__).resolve().parents[2]
OUT = ROOT / "experiments/stage-b-20260909-ark-01"
MAX_REQUESTS = 10
TIMEOUT = 90
count = 0


def post(label: str, payload: dict, *, stream: bool = False) -> dict:
    global count
    if count >= MAX_REQUESTS:
        raise RuntimeError("request_budget_exhausted")
    count += 1
    started = time.monotonic()
    request = Request(
        os.environ["SAFECLAW_BASE_URL"].rstrip("/") + "/chat/completions",
        data=json.dumps(payload, ensure_ascii=False).encode(),
        headers={
            "Authorization": "Bearer " + os.environ["SAFECLAW_API_KEY"],
            "Content-Type": "application/json",
            "User-Agent": "OpenAI/Python 1.0.0",
        },
        method="POST",
    )
    result = {
        "label": label,
        "request": {k: v for k, v in payload.items() if k != "messages"},
        "message_roles": [m.get("role") for m in payload.get("messages", [])],
        "request_index": count,
    }
    try:
        with urlopen(request, timeout=TIMEOUT) as response:
            raw = response.read()
            result.update(
                {
                    "http_status": response.status,
                    "content_type": response.headers.get("Content-Type"),
                    "elapsed_ms": round((time.monotonic() - started) * 1000, 3),
                }
            )
            if stream or "text/event-stream" in (response.headers.get("Content-Type", "").lower()):
                result["sse_raw"] = raw.decode("utf-8", errors="replace")
                events = []
                for line in result["sse_raw"].splitlines():
                    if line.startswith("data:") and line[5:].strip() != "[DONE]":
                        try:
                            events.append(json.loads(line[5:].strip()))
                        except json.JSONDecodeError:
                            result["parse_error"] = "invalid_sse_event"
                result["events"] = events
                result["tool_calls"] = [
                    c
                    for e in events
                    for c in ((e.get("choices") or [{}])[0].get("delta") or {}).get(
                        "tool_calls", []
                    )
                    if isinstance(c, dict)
                ]
            else:
                value = json.loads(raw.decode())
                result["response"] = value
                result["usage"] = value.get("usage") if isinstance(value, dict) else "unknown"
                message = (
                    ((value.get("choices") or [{}])[0].get("message") or {})
                    if isinstance(value, dict)
                    else {}
                )
                result["tool_calls"] = message.get("tool_calls", [])
                result["content"] = message.get("content")
            return result
    except HTTPError as exc:
        body = exc.read().decode("utf-8", errors="replace")[:2000]
        result.update(
            {
                "http_status": exc.code,
                "content_type": exc.headers.get("Content-Type"),
                "error_body": body,
                "elapsed_ms": round((time.monotonic() - started) * 1000, 3),
            }
        )
    except (URLError, TimeoutError) as exc:
        result.update(
            {
                "http_status": None,
                "error": type(exc).__name__,
                "elapsed_ms": round((time.monotonic() - started) * 1000, 3),
            }
        )
    return result


def main() -> int:
    OUT.mkdir(parents=True, exist_ok=False)
    model = os.environ["SAFECLAW_MODEL"]
    base = os.environ["SAFECLAW_BASE_URL"]
    if (
        model != "ep-20260909180104-hmx9m"
        or base.rstrip("/") != "https://ark.cn-beijing.volces.com/api/v3"
    ):
        raise SystemExit("ark_probe_config_mismatch")
    tool = {
        "type": "function",
        "function": {
            "name": "add",
            "description": "Add two integers locally",
            "parameters": {
                "type": "object",
                "properties": {"a": {"type": "integer"}, "b": {"type": "integer"}},
                "required": ["a", "b"],
                "additionalProperties": False,
            },
        },
    }
    records = []
    records.append(
        post(
            "direct_text",
            {
                "model": model,
                "messages": [{"role": "user", "content": "Reply with OK."}],
                "max_tokens": 1024,
            },
        )
    )
    records.append(
        post(
            "direct_stream_text",
            {
                "model": model,
                "messages": [{"role": "user", "content": "Reply with STREAM_OK."}],
                "stream": True,
                "max_tokens": 1024,
            },
            stream=True,
        )
    )
    first = post(
        "direct_add_tool_call",
        {
            "model": model,
            "messages": [{"role": "user", "content": "Use add for 2+3."}],
            "tools": [tool],
            "tool_choice": "required",
            "max_tokens": 1024,
        },
    )
    records.append(first)
    calls = first.get("tool_calls") or []
    call = calls[0] if calls else {}
    fn = call.get("function") or {}
    call_id = call.get("id")
    arguments = json.loads(fn.get("arguments", "{}")) if fn.get("arguments") else {}
    if call_id is not None and fn.get("name") == "add" and arguments == {"a": 2, "b": 3}:
        records.append(
            post(
                "direct_tool_result_roundtrip",
                {
                    "model": model,
                    "messages": [
                        {"role": "user", "content": "Use add for 2+3."},
                        {"role": "assistant", "content": None, "tool_calls": [call]},
                        {"role": "tool", "tool_call_id": call_id, "content": "5"},
                    ],
                    "max_tokens": 1024,
                },
            )
        )
    else:
        records.append(
            {
                "label": "direct_tool_result_roundtrip",
                "status": "not_run",
                "reason": "tool_call_validation_failed",
            }
        )
    summary = {
        "schema_version": "1.0",
        "run_id": "stage-b-20260909-ark-01",
        "model": model,
        "base_url": base,
        "request_limit": MAX_REQUESTS,
        "request_count": count,
        "max_attempts": 1,
        "timeout_seconds": TIMEOUT,
        "records": records,
        "tool_validation": {
            "call_id": call_id,
            "arguments": arguments,
            "local_execution": "not performed by model; add result fixed to 5",
        },
    }
    (OUT / "direct_probe.json").write_text(json.dumps(summary, ensure_ascii=False, indent=2) + "\n")
    return (
        0
        if all(r.get("http_status") == 200 for r in records if r.get("status") != "not_run")
        else 1
    )


if __name__ == "__main__":
    raise SystemExit(main())
