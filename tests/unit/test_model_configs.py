from __future__ import annotations

import urllib.request
from pathlib import Path
from typing import Any

import pytest
from pydantic import BaseModel

from stac_attack_lab.config import load_experiment_config
from stac_attack_lab.contracts import ActorRole
from stac_attack_lab.models.factory import build_model_client
from stac_attack_lab.models.fake import FakeModelClient
from stac_attack_lab.models.gemini import GeminiClient
from stac_attack_lab.models.huihui import HuihuiLocalClient
from stac_attack_lab.models.openai_compatible import OpenAICompatibleClient, _post_json
from stac_attack_lab.recording.conversations import ConversationRecorder
from stac_attack_lab.recording.events import read_jsonl

ROOT = Path(__file__).resolve().parents[2]


def test_role_configs_load_for_current_and_future_runs() -> None:
    configs = [
        "configs/experiments/stac_sample_build_gemini.yaml",
        "configs/experiments/stac_sample_build_gpt_gemini.yaml",
        "configs/experiments/evaluation_gpt_huihui_4090.yaml",
    ]
    for config_path in configs:
        config = load_experiment_config(ROOT / config_path)
        assert {"planner", "attacker", "victim", "prompt_writer", "verifier", "judge"} <= set(
            config.models
        )


def test_model_factory_resolves_supported_providers() -> None:
    fake = load_experiment_config(ROOT / "configs/experiments/mvp_online.yaml")
    gemini = load_experiment_config(ROOT / "configs/experiments/stac_sample_build_gemini.yaml")
    future = load_experiment_config(ROOT / "configs/experiments/evaluation_gpt_huihui_4090.yaml")

    assert isinstance(build_model_client(fake.models["planner"]), FakeModelClient)
    assert isinstance(build_model_client(gemini.models["victim"]), GeminiClient)
    assert isinstance(build_model_client(future.models["planner"]), OpenAICompatibleClient)
    assert isinstance(build_model_client(future.models["victim"]), HuihuiLocalClient)


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


def test_huihui_local_defaults_to_local_vllm_endpoint(monkeypatch: Any) -> None:
    monkeypatch.delenv("HUIHUI_BASE_URL", raising=False)
    client = HuihuiLocalClient("huihui-qwen3-14b-abliterated-v2")
    assert client.base_url == "http://127.0.0.1:8000/v1"


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


def test_huihui_local_requests_vllm_json_schema_response_format(monkeypatch: Any) -> None:
    observed: dict[str, Any] = {}

    def fake_post_json(
        url: str, payload: dict[str, object], api_key: str, timeout: int
    ) -> dict[str, object]:
        observed["payload"] = payload
        return {"choices": [{"message": {"content": '{"value": "ok"}'}}]}

    monkeypatch.delenv("HUIHUI_MODEL", raising=False)
    monkeypatch.setenv("HUIHUI_BASE_URL", "http://127.0.0.1:8000/v1")
    monkeypatch.setattr("stac_attack_lab.models.openai_compatible._post_json", fake_post_json)

    result = HuihuiLocalClient("huihui-test").generate([], EchoResponse, seed=1, timeout=30)

    assert result == EchoResponse(value="ok")
    response_format = observed["payload"]["response_format"]
    assert response_format["type"] == "json_schema"
    assert response_format["json_schema"]["name"] == "EchoResponse"
    assert response_format["json_schema"]["schema"]["title"] == "EchoResponse"
    assert response_format["json_schema"]["strict"] is True


def test_recorder_preserves_raw_model_response_on_error(tmp_path: Path) -> None:
    recorder = ConversationRecorder(tmp_path / "conversations.jsonl")

    def invoke() -> EchoResponse:
        raise ValueError("schema validation failed")

    invoke.last_raw_response = '{"unexpected": true}'  # type: ignore[attr-defined]

    with pytest.raises(ValueError):
        recorder.record_model_call(
            run_id="run-1",
            attack_id="attack-1",
            idempotency_key="attack-1-stage-1",
            phase="evaluation",
            condition="llm_planner_full",
            seed=1,
            attempt_no=1,
            sender_role=ActorRole.attacker,
            recipient_role=ActorRole.victim,
            provider="huihui_local",
            model_id="huihui-test",
            model_config={"provider": "huihui_local"},
            prompt_id="victim_action",
            prompt_version="1.0",
            prompt_hash="hash",
            input_schema_id="VictimRequest",
            output_schema_id="VictimAction",
            messages=[{"role": "user", "content": "act"}],
            invoke=invoke,
        )

    error_event = next(
        event for event in read_jsonl(recorder.path) if event["event_type"] == "model_error"
    )
    assert error_event["raw_model_response"] == '{"unexpected": true}'
    assert error_event["schema_validation"]["error_category"] == "schema_validation"
