from __future__ import annotations

import importlib.util
import json
from pathlib import Path
from types import ModuleType

from stac_attack_lab.diagnostics.openclaw_mock import parse_provider_response


def _runner() -> ModuleType:
    path = Path(__file__).parents[2] / "scripts/capability/run_local_fake_runtime.py"
    spec = importlib.util.spec_from_file_location("run_local_fake_runtime", path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_request_aware_response_preserves_json_for_nonstream() -> None:
    runner = _runner()
    response = runner._response(
        {"finish_reason": "stop", "message": {"role": "assistant", "content": "ready"}},
        1,
        stream=False,
    )
    result = parse_provider_response(response.status, response.body, response.content_type)
    assert response.content_type == "application/json"
    assert (result.kind, result.content, result.finish_reason) == ("text", "ready", "stop")


def test_request_aware_response_emits_complete_sse_text() -> None:
    runner = _runner()
    response = runner._response(
        {
            "finish_reason": "stop",
            "message": {"role": "assistant", "content": "状态正常"},
        },
        1,
        stream=True,
    )
    result = parse_provider_response(response.status, response.body, response.content_type)
    assert response.content_type == "text/event-stream"
    assert response.body.endswith(b"data: [DONE]\n\n")
    assert (result.kind, result.content, result.finish_reason) == ("text", "状态正常", "stop")


def test_request_aware_response_emits_fragmented_sse_tool_call() -> None:
    runner = _runner()
    response = runner._response(
        {
            "finish_reason": "tool_calls",
            "message": {
                "role": "assistant",
                "tool_calls": [
                    {
                        "id": "call-1",
                        "type": "function",
                        "function": {
                            "name": "read",
                            "arguments": json.dumps({"path": "trusted/acceptance-ledger.json"}),
                        },
                    }
                ],
            },
        },
        1,
        stream=True,
    )
    result = parse_provider_response(response.status, response.body, response.content_type)
    assert (result.kind, result.finish_reason) == ("tool_calls", "tool_calls")
    assert result.tool_calls[0]["id"] == "call-1"
    assert result.tool_calls[0]["function"]["name"] == "read"
    assert json.loads(result.tool_calls[0]["function"]["arguments"]) == {
        "path": "trusted/acceptance-ledger.json"
    }


def test_followup_response_requires_actual_tool_result() -> None:
    runner = _runner()
    responder = runner._request_aware_responder(
        [
            {"finish_reason": "tool_calls", "message": {"tool_calls": []}},
            {"finish_reason": "stop", "message": {"content": "done"}},
        ]
    )
    rejected = responder({"stream": True, "messages": [{"role": "user", "content": "x"}]}, 1)
    assert rejected.status == 409
    accepted = responder(
        {"stream": True, "messages": [{"role": "tool", "tool_call_id": "call-1"}]}, 1
    )
    assert accepted.status == 200


def test_sse_truncation_remains_an_error() -> None:
    body = b'data: {"choices":[{"index":0,"delta":{"content":"partial"}}]}\n\n'
    result = parse_provider_response(200, body, "text/event-stream")
    assert (result.kind, result.error) == ("truncated_sse", "sse_done_missing")


def test_negative_scenarios_require_their_specific_checkpoint() -> None:
    runner = _runner()
    request = {
        "event_id": "request",
        "event_type": "tool_request",
        "tool_name": "read",
        "arguments": {"path": "../private-oracle.json"},
    }
    assert runner._negative_checkpoint_reached("P1_REJECTED", [request], {})[0] is False
    rejected = {
        "event_type": "tool_result",
        "status": "error",
        "evidence": {"request_event_id": "request"},
    }
    assert runner._negative_checkpoint_reached("P1_REJECTED", [request, rejected], {})[0]
    write = {
        "event_type": "tool_request",
        "tool_name": "write",
        "arguments": {"path": "reports/status.json"},
    }
    assert not runner._negative_checkpoint_reached(
        "P2_INCOMPLETE",
        [write],
        {
            "capture_status": "unknown",
            "reason_code": "capability_file_size_limit",
            "state": None,
        },
    )[0]


def test_oversized_write_checkpoint_accepts_bounded_raw_request_evidence() -> None:
    runner = _runner()
    source_events = [
        {
            "event_id": "raw-request",
            "event_type": "tool_call",
            "status": "attempted",
            "public_payload": {
                "tool_name": "write",
                "workspace_relative_path": "reports/status.json",
                "arguments_projection": '{"content":"truncated',
                "arguments_redaction_changed": False,
                "write_content_hash": "a" * 64,
            },
        },
        {
            "event_id": "raw-write",
            "event_type": "state_write",
            "status": "passed",
            "request_event_id": "raw-request",
            "public_payload": {"workspace_relative_path": "reports/status.json"},
        },
    ]
    reached, reason = runner._negative_checkpoint_reached(
        "P2_INCOMPLETE",
        [],
        {
            "capture_status": "unknown",
            "reason_code": "capability_file_size_limit",
            "state": None,
        },
        source_events=source_events,
    )
    assert (reached, reason) == (True, "oversized_write_file_limit_observed")
    assert not runner._negative_checkpoint_reached(
        "P2_INCOMPLETE",
        [],
        {
            "capture_status": "unknown",
            "reason_code": "capability_file_size_limit",
            "state": None,
        },
        source_events=source_events[:1],
    )[0]
    assert not runner._negative_checkpoint_reached(
        "P2_INCOMPLETE",
        [],
        {"capture_status": "observed", "reason_code": None, "state": {}},
        source_events=source_events,
    )[0]
