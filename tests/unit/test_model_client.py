from __future__ import annotations

import urllib.request
from pathlib import Path
from typing import Any

from pydantic import BaseModel

from stac_attack_lab.config import RoleModelConfig, load_simple_yaml
from stac_attack_lab.models.factory import build_model_client
from stac_attack_lab.models.openai_compatible import OpenAICompatibleClient, _post_json


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
