from __future__ import annotations

import urllib.request
from pathlib import Path
from typing import Any

from pydantic import BaseModel

from stac_attack_lab.config import RoleModelConfig, load_simple_yaml
from stac_attack_lab.models.factory import build_model_client
from stac_attack_lab.models.openai_compatible import (
    OpenAICompatibleClient,
    ProviderRequestLedger,
    _post_json,
)


def test_model_factory_builds_openai_compatible_client() -> None:
    config = RoleModelConfig.model_validate(
        load_simple_yaml(Path("configs/models/formal_attacker.yaml"))
    )
    assert isinstance(build_model_client(config), OpenAICompatibleClient)


def test_openai_compatible_uses_gateway_safe_user_agent(monkeypatch: Any) -> None:
    observed: dict[str, str] = {}

    class Response:
        def __enter__(self) -> Response:
            return self

        def __exit__(self, *args: object) -> None:
            return None

        def read(self) -> bytes:
            return b"{}"

    def fake_urlopen(request: urllib.request.Request, timeout: int) -> Response:
        observed.update(dict(request.header_items()))
        assert timeout == 30
        return Response()

    monkeypatch.setattr(urllib.request, "urlopen", fake_urlopen)
    assert _post_json("https://example.test/v1/chat/completions", {}, "secret", 30) == {}
    assert observed["User-agent"] == "OpenAI/Python 1.0.0"


class EchoResponse(BaseModel):
    value: str


def test_openai_compatible_omits_response_format_by_default(monkeypatch: Any) -> None:
    observed: dict[str, Any] = {}

    def fake_post_json(
        url: str, payload: dict[str, object], api_key: str, timeout: int
    ) -> dict[str, object]:
        observed["payload"] = payload
        return {"choices": [{"message": {"content": '{"value": "ok"}'}}]}

    monkeypatch.setenv("OPENAI_BASE_URL", "https://example.test/v1")
    monkeypatch.setenv("OPENAI_API_KEY", "secret")
    monkeypatch.setattr("stac_attack_lab.models.openai_compatible._post_json", fake_post_json)

    result = OpenAICompatibleClient("gpt-test").generate([], EchoResponse, seed=1, timeout=30)

    assert result == EchoResponse(value="ok")
    assert "response_format" not in observed["payload"]


def test_provider_request_ledger_counts_boundary_and_hard_limits(monkeypatch: Any) -> None:
    calls = 0

    class Response:
        status = 200
        headers = {"Content-Type": "application/json"}

        def __enter__(self) -> Response:
            return self

        def __exit__(self, *args: object) -> None:
            return None

        def read(self) -> bytes:
            return b'{"choices":[{"message":{"content":"{}"}}],"usage":{"total_tokens":2}}'

    def fake_urlopen(request: urllib.request.Request, timeout: int) -> Response:
        nonlocal calls
        calls += 1
        return Response()

    monkeypatch.setattr(urllib.request, "urlopen", fake_urlopen)
    ledger = ProviderRequestLedger(max_requests=1)
    assert _post_json(
        "https://example.test/v1/chat/completions", {"model": "m"}, "secret", 30, ledger=ledger
    )
    assert calls == 1
    assert len(ledger.records) == 1
    assert ledger.records[0].status == 200
    try:
        _post_json(
            "https://example.test/v1/chat/completions", {"model": "m"}, "secret", 30, ledger=ledger
        )
    except Exception as exc:
        assert str(exc) == "provider_request_budget_exhausted"
    else:
        raise AssertionError("request budget did not reject the second attempt")
    assert calls == 1
