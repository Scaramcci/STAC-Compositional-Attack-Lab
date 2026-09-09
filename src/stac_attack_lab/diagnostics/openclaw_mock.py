from __future__ import annotations

import json
import threading
import time
from dataclasses import dataclass, field
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen


@dataclass(frozen=True)
class MockResponse:
    status: int = 200
    body: bytes = b""
    content_type: str = "application/json"
    delay_seconds: float = 0.0

    @classmethod
    def json(cls, payload: dict[str, Any], *, status: int = 200) -> MockResponse:
        return cls(status=status, body=json.dumps(payload).encode("utf-8"))


@dataclass
class CapturedRequest:
    sequence: int
    path: str
    headers: dict[str, str]
    body: dict[str, Any] | None
    body_raw_length: int
    received_at: float


@dataclass
class MockProviderState:
    responses: list[MockResponse]
    max_requests: int = 5
    requests: list[CapturedRequest] = field(default_factory=list)
    rejected_attempts: list[dict[str, Any]] = field(default_factory=list)
    _lock: threading.Lock = field(default_factory=threading.Lock, repr=False)

    def next_response(self) -> MockResponse:
        index = len(self.requests) - 1
        if index >= len(self.responses):
            return MockResponse.json(
                {"error": {"message": "response replay exhausted"}}, status=500
            )
        return self.responses[index]


class _MockHandler(BaseHTTPRequestHandler):
    server: _MockHTTPServer

    def log_message(self, _format: str, *_args: object) -> None:
        return

    def do_POST(self) -> None:  # noqa: N802
        state = self.server.state
        length = int(self.headers.get("Content-Length", "0"))
        raw = self.rfile.read(length)
        try:
            body = json.loads(raw.decode("utf-8")) if raw else None
        except json.JSONDecodeError:
            body = None
        safe_headers = {
            key.lower(): value
            for key, value in self.headers.items()
            if key.lower() not in {"authorization", "proxy-authorization"}
        }
        with state._lock:
            sequence = len(state.requests) + 1
            if sequence > state.max_requests:
                state.rejected_attempts.append(
                    {"sequence": sequence, "path": self.path, "body_length": len(raw)}
                )
                response = MockResponse.json(
                    {"error": {"message": "mock request budget exhausted"}}, status=429
                )
            else:
                state.requests.append(
                    CapturedRequest(
                        sequence=sequence,
                        path=self.path,
                        headers=safe_headers,
                        body=body if isinstance(body, dict) else None,
                        body_raw_length=len(raw),
                        received_at=time.time(),
                    )
                )
                response = state.next_response()
        if response.delay_seconds:
            time.sleep(response.delay_seconds)
        self.send_response(response.status)
        self.send_header("Content-Type", response.content_type)
        self.send_header("Content-Length", str(len(response.body)))
        self.end_headers()
        self.wfile.write(response.body)


class _MockHTTPServer(ThreadingHTTPServer):
    def __init__(self, address: tuple[str, int], state: MockProviderState) -> None:
        super().__init__(address, _MockHandler)
        self.state = state


class MockProviderServer:
    """Local-only provider replay server with a hard request budget."""

    def __init__(self, responses: list[MockResponse], *, max_requests: int = 5) -> None:
        self.state = MockProviderState(responses=list(responses), max_requests=max_requests)
        self._server = _MockHTTPServer(("127.0.0.1", 0), self.state)
        self._thread = threading.Thread(target=self._server.serve_forever, daemon=True)

    @property
    def url(self) -> str:
        return f"http://127.0.0.1:{self._server.server_port}/v1"

    def __enter__(self) -> MockProviderServer:
        self._thread.start()
        return self

    def __exit__(self, *_args: object) -> None:
        self._server.shutdown()
        self._server.server_close()
        self._thread.join(timeout=2)


@dataclass(frozen=True)
class ReplayResult:
    kind: str
    status: int | None
    content: str = ""
    tool_calls: tuple[dict[str, Any], ...] = ()
    finish_reason: str | None = None
    error: str | None = None
    usage: dict[str, Any] | None = None


def parse_provider_response(status: int, body: bytes, content_type: str) -> ReplayResult:
    if status >= 400:
        error_message = body.decode("utf-8", errors="replace")[:500]
        return ReplayResult("http_error", status, error=error_message or "empty_error_body")
    if not body:
        return ReplayResult("empty_body", status, error="provider_response_empty")
    if "text/event-stream" in content_type.lower() or body.startswith(b"data:"):
        events: list[dict[str, Any]] = []
        for line in body.decode("utf-8", errors="replace").splitlines():
            line = line.strip()
            if not line or not line.startswith("data:"):
                continue
            payload = line[5:].strip()
            if payload == "[DONE]":
                events.append({"done": True})
                continue
            try:
                value = json.loads(payload)
            except json.JSONDecodeError:
                return ReplayResult("invalid_sse", status, error="sse_event_invalid_json")
            if isinstance(value, dict):
                events.append(value)
        if not events or not events[-1].get("done"):
            return ReplayResult("truncated_sse", status, error="sse_done_missing")
        calls_by_key: dict[tuple[Any, Any], dict[str, Any]] = {}
        active_key: tuple[Any, Any] | None = None
        text_parts: list[str] = []
        finish_reason = None
        for event in events:
            choice = (event.get("choices") or [{}])[0]
            if not isinstance(choice, dict):
                continue
            finish_reason = choice.get("finish_reason") or finish_reason
            delta = choice.get("delta") or {}
            if isinstance(delta, dict):
                if isinstance(delta.get("content"), str):
                    text_parts.append(delta["content"])
                if isinstance(delta.get("tool_calls"), list):
                    for call in delta["tool_calls"]:
                        if not isinstance(call, dict):
                            continue
                        function = call.get("function") or {}
                        if "index" in call:
                            index = call["index"]
                        elif call.get("id") is None and active_key is not None:
                            index = active_key[0]
                        else:
                            index = len(calls_by_key)
                        key = (index, call.get("id") or (active_key[1] if active_key else None))
                        active_key = key
                        merged = calls_by_key.setdefault(
                            key,
                            {
                                "index": index,
                                "id": call.get("id"),
                                "type": call.get("type", "function"),
                                "function": {"name": "", "arguments": ""},
                            },
                        )
                        if isinstance(function, dict):
                            if isinstance(function.get("name"), str):
                                merged["function"]["name"] = function["name"]
                            if isinstance(function.get("arguments"), str):
                                merged["function"]["arguments"] += function["arguments"]
        calls = list(calls_by_key.values())
        kind = "tool_calls" if calls else "text"
        return ReplayResult(kind, status, "".join(text_parts), tuple(calls), finish_reason)
    try:
        value = json.loads(body.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        return ReplayResult("invalid_json", status, error="provider_response_invalid_json")
    if not isinstance(value, dict):
        return ReplayResult("invalid_json", status, error="provider_response_not_object")
    choices = value.get("choices")
    if not isinstance(choices, list) or not choices or not isinstance(choices[0], dict):
        return ReplayResult("invalid_json", status, error="provider_choices_missing")
    choice = choices[0]
    message_value = choice.get("message")
    json_message: dict[str, Any] = message_value if isinstance(message_value, dict) else {}
    calls_value = json_message.get("tool_calls")
    json_calls: list[dict[str, Any]] = calls_value if isinstance(calls_value, list) else []
    content_value = json_message.get("content")
    json_content = content_value if isinstance(content_value, str) else ""
    kind = "tool_calls" if json_calls else "text" if json_content.strip() else "empty_content"
    return ReplayResult(
        kind,
        status,
        json_content,
        tuple(json_calls),
        choice.get("finish_reason"),
        usage=value.get("usage"),
    )


def request_with_retries(
    url: str,
    payload: dict[str, Any],
    *,
    max_attempts: int = 3,
    timeout_seconds: float = 2.0,
    retry_statuses: frozenset[int] = frozenset({429, 500, 502, 503, 504}),
) -> tuple[ReplayResult, int]:
    """Call a mock provider with explicit, bounded retry behavior."""
    attempts = 0
    while attempts < max_attempts:
        attempts += 1
        request = Request(
            url,
            data=json.dumps(payload).encode("utf-8"),
            headers={"Content-Type": "application/json", "Authorization": "Bearer fake"},
            method="POST",
        )
        try:
            with urlopen(request, timeout=timeout_seconds) as response:
                return parse_provider_response(
                    response.status, response.read(), response.headers.get("Content-Type", "")
                ), attempts
        except HTTPError as exc:
            body = exc.read()
            result = parse_provider_response(exc.code, body, exc.headers.get("Content-Type", ""))
            if exc.code not in retry_statuses or attempts >= max_attempts:
                return result, attempts
        except (TimeoutError, URLError) as exc:
            if attempts >= max_attempts:
                return ReplayResult("transport_error", None, error=type(exc).__name__), attempts
    return ReplayResult("transport_error", None, error="retry_budget_exhausted"), attempts
