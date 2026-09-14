from __future__ import annotations

import json
import subprocess
import urllib.error
import urllib.request
from pathlib import Path

import pytest

from stac_attack_lab.diagnostics.openclaw_mock import MockProviderServer, MockResponse
from stac_attack_lab.environments.safeclaw.provider_relay import (
    ContainerProviderRelay,
    ProviderRelayConfig,
    ProviderRelayServer,
    RunningProviderRelay,
    _extract_provider_usage,
    chat_completions_url,
    relay_runtime_from_model_config,
)


def _post(url: str, payload: dict[str, object], token: str = "relay-token") -> tuple[int, bytes]:
    request = urllib.request.Request(
        url,
        data=json.dumps(payload).encode(),
        headers={
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json",
        },
        method="POST",
    )
    try:
        with urllib.request.urlopen(request, timeout=3) as response:
            return response.status, response.read()
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read()


def _text_response() -> MockResponse:
    return MockResponse.json({"choices": [{"message": {"role": "assistant", "content": "OK"}}]})


def _config(upstream: str, ledger: Path, *, limit: int = 2) -> ProviderRelayConfig:
    return ProviderRelayConfig(
        upstream_base_url=upstream,
        upstream_api_key="upstream-secret",
        ingress_token="relay-token",
        max_requests=limit,
        timeout_seconds=3,
        allowed_tools=("add",),
        ledger_path=str(ledger),
    )


def test_ark_api_root_is_preserved_without_v1_insertion() -> None:
    assert (
        chat_completions_url("https://ark.cn-beijing.volces.com/api/v3")
        == "https://ark.cn-beijing.volces.com/api/v3/chat/completions"
    )
    assert (
        chat_completions_url("https://provider.invalid/v1/")
        == "https://provider.invalid/v1/chat/completions"
    )


def test_relay_filters_openclaw_builtins_to_exact_add_schema(tmp_path: Path) -> None:
    with MockProviderServer([_text_response()], max_requests=1) as upstream:
        config = _config(upstream.url.removesuffix("/v1") + "/api/v3", tmp_path / "ledger.jsonl")
        relay = ProviderRelayServer(("127.0.0.1", 0), config)
        with RunningProviderRelay(relay):
            status, _ = _post(
                relay.url + "/v1/chat/completions",
                {
                    "model": "ep-test",
                    "messages": [{"role": "user", "content": "2+3"}],
                    "tools": [
                        {"type": "function", "function": {"name": "exec"}},
                        {
                            "type": "function",
                            "function": {
                                "name": "add",
                                "parameters": {
                                    "type": "object",
                                    "required": ["a", "b"],
                                },
                            },
                        },
                    ],
                },
            )
        assert status == 200
        captured = upstream.state.requests[0]
        assert captured.path == "/api/v3/chat/completions"
        assert [item["function"]["name"] for item in captured.body["tools"]] == ["add"]
        assert "authorization" not in captured.headers
        record = json.loads((tmp_path / "ledger.jsonl").read_text().strip())
        assert record["final_tools"] == ["add"]
        assert record["upstream_path"] == "/api/v3/chat/completions"


def test_relay_hard_limit_counts_actual_attempts_and_rejects_excess(tmp_path: Path) -> None:
    with MockProviderServer([_text_response()], max_requests=1) as upstream:
        relay = ProviderRelayServer(
            ("127.0.0.1", 0),
            _config(
                upstream.url.removesuffix("/v1") + "/api/v3",
                tmp_path / "ledger.jsonl",
                limit=1,
            ),
        )
        with RunningProviderRelay(relay):
            first, _ = _post(relay.url + "/chat/completions", {"model": "ep-test"})
            second, body = _post(relay.url + "/chat/completions", {"model": "ep-test"})
        assert first == 200
        assert second == 429
        assert b"provider_request_budget_exhausted" in body
        assert len(upstream.state.requests) == 1
        assert relay.state.accepted_requests == 1
        assert relay.state.total_attempts == 2
        assert [record["accepted"] for record in relay.state.records] == [True, False]


def test_relay_rejects_bad_ingress_auth_without_spending_budget(tmp_path: Path) -> None:
    with MockProviderServer([_text_response()], max_requests=1) as upstream:
        relay = ProviderRelayServer(
            ("127.0.0.1", 0),
            _config(
                upstream.url.removesuffix("/v1") + "/api/v3",
                tmp_path / "ledger.jsonl",
                limit=1,
            ),
        )
        with RunningProviderRelay(relay):
            status, _ = _post(relay.url + "/chat/completions", {"model": "ep-test"}, token="wrong")
        assert status == 401
        assert relay.state.total_attempts == 0
        assert not upstream.state.requests


def test_relay_runtime_keeps_openclaw_and_transport_allowlists_aligned() -> None:
    value = {
        "provider_relay_source": "source",
        "provider_upstream_base_url": "https://provider.invalid/v1",
        "provider_upstream_api_key": "secret",
        "provider_request_budget": 2,
        "provider_timeout_seconds": 10,
        "provider_allowed_tools": ["add"],
    }
    runtime = relay_runtime_from_model_config(value)
    assert runtime is not None
    assert runtime["allowed_tools"] == ["add"]
    assert value["openclaw_allowed_tools"] == ["add"]
    assert "provider_upstream_api_key" not in value


def test_container_cleanup_targets_only_owned_names(monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[tuple[str, ...]] = []

    def fake_docker(
        *args: str, check: bool = True, input_data: bytes | None = None
    ) -> subprocess.CompletedProcess[bytes]:
        del check, input_data
        calls.append(args)
        return subprocess.CompletedProcess(args, 0, b"", b"")

    monkeypatch.setattr(ContainerProviderRelay, "_docker", staticmethod(fake_docker))
    relay = ContainerProviderRelay(
        image="image",
        victim_container="victim-owned",
        runtime={},
    )
    relay.container = "relay-owned"
    relay.network = "network-owned"
    relay.stop()

    assert calls == [
        ("rm", "-f", "relay-owned"),
        ("network", "disconnect", "network-owned", "victim-owned"),
        ("network", "rm", "network-owned"),
    ]


def test_container_relay_removes_victim_egress_and_keeps_relay_egress(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[tuple[str, ...]] = []

    def fake_docker(
        *args: str, check: bool = True, input_data: bytes | None = None
    ) -> subprocess.CompletedProcess[bytes]:
        del check, input_data
        calls.append(args)
        return subprocess.CompletedProcess(args, 0, b"ok", b"")

    monkeypatch.setattr(ContainerProviderRelay, "_docker", staticmethod(fake_docker))
    relay = ContainerProviderRelay(
        image="image",
        victim_container="victim-owned",
        runtime={
            "source": "source",
            "upstream_api_key": "secret",
            "upstream_base_url": "https://provider.invalid/v1",
            "max_requests": 1,
            "timeout_seconds": 1,
            "allowed_tools": [],
        },
    )
    monkeypatch.setattr("time.sleep", lambda _seconds: None)

    relay.start()

    assert ("network", "create", "--internal", relay.network) in calls
    assert ("network", "disconnect", "bridge", "victim-owned") in calls
    assert ("network", "connect", "bridge", relay.container) in calls


def test_embedding_probe_parses_openai_compatible_data_list_and_outer_timeout(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[tuple[tuple[str, ...], int]] = []

    def fake_docker(
        *args: str,
        check: bool = True,
        input_data: bytes | None = None,
        timeout: int = 30,
    ) -> subprocess.CompletedProcess[bytes]:
        del check, input_data
        calls.append((args, timeout))
        return subprocess.CompletedProcess(
            args,
            0,
            b'{"status":200,"dimension":3,"finite_nonempty":true,"usage":{"prompt_tokens":2}}',
            b"",
        )

    monkeypatch.setattr(ContainerProviderRelay, "_docker", staticmethod(fake_docker))
    relay = ContainerProviderRelay(
        image="image",
        victim_container="victim-owned",
        runtime={"timeout_seconds": 90},
    )
    relay.embedding_started = True
    result = relay.embedding_probe(from_victim=False, model="embed-model", text="safe probe")
    assert result == {
        "status": 200,
        "dimension": 3,
        "finite_nonempty": True,
        "usage": {"prompt_tokens": 2},
    }
    args, timeout = calls[-1]
    assert "timeout" in args and "100s" in args
    assert timeout == 105


def test_relay_ledger_read_fails_closed_on_corrupt_line(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    relay = ContainerProviderRelay(image="image", victim_container="victim", runtime={})
    relay.embedding_started = True
    relay.started = True

    def corrupt_docker(*args: str, **kwargs: object) -> subprocess.CompletedProcess[bytes]:
        del args, kwargs
        return subprocess.CompletedProcess([], 0, b'{"ok":true}\nnot-json\n', b"")

    monkeypatch.setattr(ContainerProviderRelay, "_docker", staticmethod(corrupt_docker))
    with pytest.raises(RuntimeError, match="ledger_corrupt"):
        relay.embedding_records()
    with pytest.raises(RuntimeError, match="ledger_corrupt"):
        relay.records()


def test_provider_usage_extracts_nonstream_json_and_rejects_invalid() -> None:
    usage, observation, reasons = _extract_provider_usage(
        b'{"usage":{"prompt_tokens":11,"completion_tokens":7,"total_tokens":18}}',
        "application/json",
    )
    assert usage == {"input_tokens": 11, "output_tokens": 7, "total_tokens": 18}
    assert observation == "complete" and reasons == []
    usage, observation, reasons = _extract_provider_usage(
        b'{"usage":{"prompt_tokens":11,"completion_tokens":7,"total_tokens":99}}',
        "application/json",
    )
    assert usage is None and observation == "partial" and "total_tokens_inconsistent" in reasons


def test_provider_usage_extracts_sse_final_usage_only_chunk() -> None:
    body = (
        b'data: {"choices":[{"delta":{"content":"ok"}}]}\n'
        b'data: {"choices":[],"usage":{"prompt_tokens":13,'
        b'"completion_tokens":5,"total_tokens":18}}\n'
        b"data: [DONE]\n"
    )
    usage, observation, reasons = _extract_provider_usage(body, "text/event-stream")
    assert usage == {"input_tokens": 13, "output_tokens": 5, "total_tokens": 18}
    assert observation == "complete" and reasons == []


def test_provider_usage_marks_truncated_and_missing_sse() -> None:
    usage, observation, reasons = _extract_provider_usage(
        b'data: {"choices":[],"usage":{"prompt_tokens":1}}\n', "text/event-stream"
    )
    assert usage is None and observation == "truncated" and "sse_done_missing" in reasons
    usage, observation, reasons = _extract_provider_usage(
        b'data: {"choices":[]}\ndata: [DONE]\n', "text/event-stream"
    )
    assert usage is None and observation == "missing" and "usage_missing" in reasons


def test_relay_records_provider_usage_and_requests_ark_stream_usage(tmp_path: Path) -> None:
    response = MockResponse(
        body=(
            b'data: {"choices":[{"delta":{"content":"ok"}}]}\n'
            b'data: {"choices":[],"usage":{"prompt_tokens":4,'
            b'"completion_tokens":6,"total_tokens":10}}\n'
            b"data: [DONE]\n"
        ),
        content_type="text/event-stream",
    )
    with MockProviderServer([response], max_requests=1) as upstream:
        config = ProviderRelayConfig(
            upstream_base_url=upstream.url,
            upstream_api_key="secret",
            ingress_token="relay-token",
            max_requests=1,
            timeout_seconds=3,
            provider_compat="ark",
            ledger_path=str(tmp_path / "ledger.jsonl"),
        )
        relay = ProviderRelayServer(("127.0.0.1", 0), config)
        with RunningProviderRelay(relay):
            status, _ = _post(relay.url + "/v1/chat/completions", {"model": "ep", "stream": True})
        assert status == 200
        assert upstream.state.requests[0].body["stream_options"] == {"include_usage": True}
        record = json.loads((tmp_path / "ledger.jsonl").read_text().splitlines()[-1])
        assert record["provider_usage"] == {
            "input_tokens": 4,
            "output_tokens": 6,
            "total_tokens": 10,
        }
        assert record["provider_usage_observation"] == "complete"
