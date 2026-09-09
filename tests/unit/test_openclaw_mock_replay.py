from __future__ import annotations

import json

from stac_attack_lab.diagnostics.openclaw_mock import (
    MockProviderServer,
    MockResponse,
    parse_provider_response,
    request_with_retries,
)


def text_response(text: str = "OK") -> MockResponse:
    return MockResponse.json(
        {"choices": [{"message": {"role": "assistant", "content": text}, "finish_reason": "stop"}]}
    )


def tool_response(*, content: str = "", call_id: str = "call-1") -> MockResponse:
    return MockResponse.json(
        {
            "choices": [
                {
                    "message": {
                        "role": "assistant",
                        "content": content,
                        "tool_calls": [
                            {
                                "id": call_id,
                                "type": "function",
                                "function": {"name": "add", "arguments": '{"a":2,"b":3}'},
                            }
                        ],
                    },
                    "finish_reason": "tool_calls",
                }
            ]
        }
    )


def sse_response(*, truncated: bool = False, tool: bool = False) -> MockResponse:
    if tool:
        event = {
            "choices": [
                {
                    "delta": {
                        "tool_calls": [
                            {
                                "id": "call-1",
                                "type": "function",
                                "function": {"name": "add", "arguments": '{"a":'},
                            }
                        ]
                    },
                    "finish_reason": None,
                }
            ]
        }
        event2 = {
            "choices": [
                {
                    "delta": {"tool_calls": [{"index": 0, "function": {"arguments": "2,"}}]},
                    "finish_reason": None,
                }
            ]
        }
        event3 = {
            "choices": [
                {
                    "delta": {"tool_calls": [{"index": 0, "function": {"arguments": '"b":3}'}}]},
                    "finish_reason": "tool_calls",
                }
            ]
        }
        lines = [event, event2, event3]
    else:
        lines = [
            {"choices": [{"delta": {"role": "assistant", "content": "O"}, "finish_reason": None}]},
            {"choices": [{"delta": {"content": "K"}, "finish_reason": "stop"}]},
        ]
    body = b"".join(b"data: " + json.dumps(item).encode() + b"\n\n" for item in lines)
    if not truncated:
        body += b"data: [DONE]\n\n"
    return MockResponse(body=body, content_type="text/event-stream")


def test_mock_captures_request_without_auth_and_respects_budget() -> None:
    with MockProviderServer([text_response()], max_requests=1) as server:
        result, attempts = request_with_retries(
            server.url + "/chat/completions",
            {"model": "mock", "messages": [{"role": "user", "content": "OK"}]},
        )
        assert (result.kind, result.content, attempts) == ("text", "OK", 1)
        assert len(server.state.requests) == 1
        assert "authorization" not in server.state.requests[0].headers
        assert server.state.requests[0].body["model"] == "mock"


def test_nonstream_tool_calls_and_empty_content_are_observed() -> None:
    result = parse_provider_response(200, tool_response().body, "application/json")
    assert result.kind == "tool_calls"
    assert result.tool_calls[0]["id"] == "call-1"
    result = parse_provider_response(200, tool_response(content="").body, "application/json")
    assert result.kind == "tool_calls"


def test_streaming_text_and_fragmented_tool_arguments_replay() -> None:
    text = sse_response()
    result = parse_provider_response(200, text.body, text.content_type)
    assert (result.kind, result.content, result.finish_reason) == ("text", "OK", "stop")
    tool = sse_response(tool=True)
    result = parse_provider_response(200, tool.body, tool.content_type)
    assert result.kind == "tool_calls"
    assert result.finish_reason == "tool_calls"
    assert len(result.tool_calls) == 1
    assert result.tool_calls[0]["id"] == "call-1"
    assert json.loads(result.tool_calls[0]["function"]["arguments"]) == {"a": 2, "b": 3}


def test_errors_empty_invalid_and_truncated_are_not_empty_success() -> None:
    assert (
        parse_provider_response(
            400, b'{"error":{"message":"bad request"}}', "application/json"
        ).kind
        == "http_error"
    )
    assert parse_provider_response(200, b"", "application/json").kind == "empty_body"
    assert parse_provider_response(200, b"not-json", "application/json").kind == "invalid_json"
    assert (
        parse_provider_response(200, sse_response(truncated=True).body, "text/event-stream").kind
        == "truncated_sse"
    )


def test_transient_errors_retry_but_budget_rejects_extra_attempts() -> None:
    error = MockResponse.json({"error": {"message": "temporary"}}, status=503)
    with MockProviderServer([error, error, text_response()], max_requests=2) as server:
        result, attempts = request_with_retries(
            server.url + "/v1/chat/completions", {"model": "mock"}, max_attempts=3
        )
        assert result.kind == "http_error"
        assert attempts == 3
        assert len(server.state.requests) == 2
        assert len(server.state.rejected_attempts) == 1


def test_transport_failure_is_bounded_without_provider() -> None:
    result, attempts = request_with_retries(
        "http://127.0.0.1:1/v1/chat/completions",
        {"model": "mock"},
        max_attempts=2,
        timeout_seconds=0.1,
    )
    assert result.kind == "transport_error"
    assert attempts == 2
