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


def test_construction_schema_and_failed_attempt_share_http_cap(monkeypatch: Any) -> None:
    import json

    import pytest

    from stac_attack_lab.interactions.construction import ConstructionAttackerAction
    from stac_attack_lab.models.base import ModelCallError

    monkeypatch.setenv("OPENAI_BASE_URL", "https://example.test/v1")
    monkeypatch.setenv("OPENAI_API_KEY", "secret")
    ledger = ProviderRequestLedger(max_requests=2)
    client = OpenAICompatibleClient("gpt-5.6-sol", request_ledger=ledger)
    calls = 0

    class Response:
        status = 200
        headers = {"Content-Type": "application/json"}

        def __enter__(self) -> Any:
            return self

        def __exit__(self, *args: object) -> None:
            pass

        def read(self) -> bytes:
            return json.dumps(
                {
                    "model": "returned-sol",
                    "choices": [
                        {
                            "message": {
                                "content": json.dumps(
                                    {
                                        "action_id": "stop",
                                        "action_type": "stop",
                                        "rationale_summary": "done",
                                    }
                                )
                            }
                        }
                    ],
                    "usage": {"total_tokens": 7},
                }
            ).encode()

    def fake_urlopen(request: urllib.request.Request, timeout: int) -> Response:
        nonlocal calls
        calls += 1
        assert timeout <= 90
        if calls == 2:
            raise TimeoutError("unknown send result")
        return Response()

    monkeypatch.setattr(urllib.request, "urlopen", fake_urlopen)
    assert client.generate([], ConstructionAttackerAction, 1, 60).action_type == "stop"
    assert client.last_returned_model == "returned-sol"
    with pytest.raises(ModelCallError, match="timeouterror"):
        client.generate([], ConstructionAttackerAction, 1, 60)
    assert client.last_usage is None
    with pytest.raises(ModelCallError, match="provider_request_budget_exhausted"):
        client.generate([], ConstructionAttackerAction, 1, 60)
    assert calls == len(ledger.records) == 2


def test_502_two_retries_record_each_attempt_and_stop_on_success(
    monkeypatch: Any, tmp_path: Path
) -> None:
    import io
    import json
    import urllib.error

    import pytest

    from stac_attack_lab.models.base import ModelCallError

    monkeypatch.setenv("OPENAI_BASE_URL", "https://example.test/v1")
    monkeypatch.setenv("OPENAI_API_KEY", "private-test-secret")
    ledger = ProviderRequestLedger(
        max_requests=3, path=tmp_path / "attempts.jsonl", batch_id="batch"
    )
    client = OpenAICompatibleClient("sol", request_ledger=ledger, http_502_retries=2)
    sent = []

    class Response:
        status = 200
        headers = {}

        def __enter__(self) -> Any:
            return self

        def __exit__(self, *args: object) -> None:
            pass

        def read(self) -> bytes:
            return (
                b'{"choices":[{"message":{"content":"{\\"value\\":\\"ok\\"}"}}],'
                b'"usage":{"total_tokens":7}}'
            )

    def send(request: Any, timeout: int) -> Any:
        sent.append(request.data)
        if len(sent) < 3:
            raise urllib.error.HTTPError(
                request.full_url, 502, "bad gateway", {}, io.BytesIO(b"upstream error")
            )
        return Response()

    monkeypatch.setattr(urllib.request, "urlopen", send)
    assert client.generate([], EchoResponse, 1, 60).value == "ok"
    assert len(sent) == 3 and len(set(sent)) == 1
    assert client.last_retry_count == 2
    assert [x["status"] for x in client.last_upstream_attempts] == [502, 502, 200]
    assert [x["usage"] for x in client.last_upstream_attempts] == [None, None, {"total_tokens": 7}]
    journal = (tmp_path / "attempts.jsonl").read_text()
    assert "private-test-secret" not in journal
    assert sum(json.loads(x)["stage"] == "attempt_started" for x in journal.splitlines()) == 3
    ledger.close()
    reopened = ProviderRequestLedger(
        max_requests=3, path=tmp_path / "attempts.jsonl", batch_id="batch"
    )
    client.request_ledger = reopened
    with pytest.raises(ModelCallError, match="budget_exhausted"):
        client.generate([], EchoResponse, 1, 60)
    assert len(sent) == 3
    reopened.close()


def test_non_502_errors_do_not_retry(monkeypatch: Any) -> None:
    import io
    import urllib.error

    import pytest

    monkeypatch.setenv("OPENAI_BASE_URL", "https://example.test/v1")
    monkeypatch.setenv("OPENAI_API_KEY", "secret")
    for code in (400, 401, 429, 500, 503):
        ledger = ProviderRequestLedger(max_requests=3)
        client = OpenAICompatibleClient("sol", request_ledger=ledger, http_502_retries=2)

        def send(request: Any, timeout: int, status: int = code) -> Any:
            raise urllib.error.HTTPError(
                request.full_url, status, "error", {}, io.BytesIO(b"error")
            )

        monkeypatch.setattr(urllib.request, "urlopen", send)
        from stac_attack_lab.models.base import ModelCallError

        with pytest.raises(ModelCallError):
            client.generate([], EchoResponse, 1, 60)
        assert len(ledger.records) == 1
        assert client.last_retry_count == 0


def test_502_retries_respect_smaller_hard_cap(monkeypatch: Any) -> None:
    import io
    import urllib.error

    import pytest

    from stac_attack_lab.models.base import ModelCallError

    monkeypatch.setenv("OPENAI_BASE_URL", "https://example.test/v1")
    monkeypatch.setenv("OPENAI_API_KEY", "secret")
    ledger = ProviderRequestLedger(max_requests=2)
    client = OpenAICompatibleClient("sol", request_ledger=ledger, http_502_retries=2)

    def send(request: Any, timeout: int) -> Any:
        raise urllib.error.HTTPError(request.full_url, 502, "error", {}, io.BytesIO(b"error"))

    monkeypatch.setattr(urllib.request, "urlopen", send)
    with pytest.raises(ModelCallError, match="budget_exhausted"):
        client.generate([], EchoResponse, 1, 60)
    assert len(ledger.records) == 2
    assert client.last_retry_count == 1


def test_three_502_attempts_stop_and_corrupt_ledger_fails_closed(
    monkeypatch: Any, tmp_path: Path
) -> None:
    import io
    import urllib.error

    import pytest

    from stac_attack_lab.models.base import ModelCallError

    monkeypatch.setenv("OPENAI_BASE_URL", "https://example.test/v1")
    monkeypatch.setenv("OPENAI_API_KEY", "secret")
    ledger = ProviderRequestLedger(max_requests=48)
    client = OpenAICompatibleClient("sol", request_ledger=ledger, http_502_retries=2)

    def send(request: Any, timeout: int) -> Any:
        raise urllib.error.HTTPError(request.full_url, 502, "error", {}, io.BytesIO(b"error"))

    monkeypatch.setattr(urllib.request, "urlopen", send)
    with pytest.raises(ModelCallError, match="provider_http_502"):
        client.generate([], EchoResponse, 1, 60)
    assert len(ledger.records) == 3
    assert client.last_retry_count == 2
    path = tmp_path / "corrupt.jsonl"
    path.write_text("{not json")
    with pytest.raises(ModelCallError, match="corrupt"):
        ProviderRequestLedger(max_requests=48, path=path, batch_id="batch")


def test_schema_failure_does_not_trigger_502_retry(monkeypatch: Any) -> None:
    import pytest
    from pydantic import ValidationError

    monkeypatch.setenv("OPENAI_BASE_URL", "https://example.test/v1")
    monkeypatch.setenv("OPENAI_API_KEY", "secret")
    ledger = ProviderRequestLedger(max_requests=3)
    client = OpenAICompatibleClient("sol", request_ledger=ledger, http_502_retries=2)

    class Response:
        status = 200
        headers = {}

        def __enter__(self) -> Any:
            return self

        def __exit__(self, *args: object) -> None:
            pass

        def read(self) -> bytes:
            return b'{"choices":[{"message":{"content":"{}"}}]}'

    monkeypatch.setattr(urllib.request, "urlopen", lambda *args, **kwargs: Response())
    with pytest.raises(ValidationError):
        client.generate([], EchoResponse, 1, 60)
    assert len(ledger.records) == 1
    assert client.last_retry_count == 0
