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
