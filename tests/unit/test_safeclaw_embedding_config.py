from __future__ import annotations

import json
import runpy
import shutil
import subprocess
from pathlib import Path
from typing import Any

import pytest

from stac_attack_lab.environments.safeclaw.model_config import (
    SafeClawEmbeddingRuntime,
    build_safeclaw_model_config,
)

ROOT = Path(__file__).resolve().parents[2]
UPSTREAM = ROOT / "integrations/safeclaw/upstream/SafeClawArena"
PATCH = ROOT / "integrations/safeclaw/patches/a11f5cce-safety.patch"


def test_model_config_resolves_chat_and_embedding_endpoints_without_logging() -> None:
    payload, secrets = build_safeclaw_model_config(
        target_model_id="synthetic-chat",
        target_base_url="https://provider.invalid/v1",
        target_api_key_env="CHAT_KEY",
        environment={
            "CHAT_KEY": "chat-secret",
            "EMBEDDING_KEY": "embedding-secret",
        },
        embedding=SafeClawEmbeddingRuntime(
            provider="openai",
            model_id="synthetic-embedding",
            base_url="https://embedding.invalid",
            api_key_env="EMBEDDING_KEY",
        ),
    )

    assert payload == {
        "model": "synthetic-chat",
        "api_base_url": "https://provider.invalid",
        "api_key": "chat-secret",
        "embedding_provider": "openai",
        "embedding_model": "synthetic-embedding",
        "embedding_api_base_url": "https://embedding.invalid/v1",
        "embedding_api_key": "embedding-secret",
    }
    assert secrets == [
        "chat-secret",
        "https://provider.invalid/v1",
        "embedding-secret",
        "https://embedding.invalid",
    ]


def test_model_config_fails_closed_when_embedding_key_is_missing() -> None:
    with pytest.raises(ValueError, match="missing_environment_variable:EMBEDDING_KEY"):
        build_safeclaw_model_config(
            target_model_id="synthetic-chat",
            target_base_url="https://provider.invalid/v1",
            target_api_key_env="CHAT_KEY",
            environment={"CHAT_KEY": "chat-secret"},
            embedding=SafeClawEmbeddingRuntime(
                provider="openai",
                model_id="synthetic-embedding",
                base_url="https://embedding.invalid/v1",
                api_key_env="EMBEDDING_KEY",
            ),
        )


@pytest.mark.skipif(not UPSTREAM.is_dir(), reason="SafeClawArena checkout not installed")
def test_patched_judge_applies_memory_search_config_without_secret_output(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    patched = tmp_path / "SafeClawArena"
    shutil.copytree(UPSTREAM, patched)
    subprocess.run(
        ["git", "apply", "--unidiff-zero", str(PATCH)],
        cwd=patched,
        check=True,
        text=True,
        capture_output=True,
    )
    module = runpy.run_path(str(patched / "scripts/judge.py"))
    captured_inputs: list[dict[str, Any]] = []
    docker_commands: list[str] = []

    def fake_run(command: list[str], **kwargs: Any) -> subprocess.CompletedProcess[bytes]:
        input_value = kwargs.get("input")
        if isinstance(input_value, bytes):
            captured_inputs.append(json.loads(input_value))
        docker_commands.append(" ".join(command))
        return subprocess.CompletedProcess(command, 0, b"", b"")

    module["_get_platform"] = lambda: {
        "cli_transport": False,
        "config_writable": True,
    }
    module["dexec"] = lambda command: docker_commands.append(command)
    module["dexec_output"] = lambda command: "valid"
    monkeypatch.setattr(module["subprocess"], "run", fake_run)
    monkeypatch.setattr(module["time"], "sleep", lambda seconds: None)
    model_config = tmp_path / "model-config.json"
    model_config.write_text(
        json.dumps(
            {
                "model": "synthetic-chat",
                "api_base_url": "https://provider.invalid",
                "api_key": "chat-secret",
                "embedding_provider": "openai",
                "embedding_model": "synthetic-embedding",
                "embedding_api_base_url": "https://embedding.invalid/v1",
                "embedding_api_key": "embedding-secret",
            }
        ),
        encoding="utf-8",
    )

    applied = module["_apply_model_config"](str(model_config))
    output = capsys.readouterr().out

    memory_configs = [
        item
        for item in captured_inputs
        if isinstance(item, dict) and item.get("provider") == "openai"
    ]
    assert memory_configs == [
        {
            "enabled": True,
            "provider": "openai",
            "model": "synthetic-embedding",
            "fallback": "none",
            "remote": {
                "baseUrl": "https://embedding.invalid/v1",
                "apiKey": "embedding-secret",
            },
        }
    ]
    assert any("memorySearch" in command for command in docker_commands)
    assert applied["embedding_configured"] is True
    assert applied["embedding_model"] == "synthetic-embedding"
    assert "chat-secret" not in output
    assert "embedding-secret" not in output

def test_gemini_embedding_endpoint_root_is_not_double_versioned() -> None:
    payload, _ = build_safeclaw_model_config(
        target_model_id="gemini-2.5-flash",
        target_base_url="https://generativelanguage.googleapis.com/v1beta/openai/",
        target_api_key_env="CHAT_KEY",
        environment={"CHAT_KEY": "chat-secret", "EMBED_KEY": "embedding-secret"},
        embedding=SafeClawEmbeddingRuntime(
            provider="openai",
            model_id="gemini-embedding-001",
            base_url="https://generativelanguage.googleapis.com/v1beta/openai/",
            api_key_env="EMBED_KEY",
        ),
    )
    assert payload["api_base_url"] == "https://generativelanguage.googleapis.com/v1beta/openai"
    assert payload["embedding_api_base_url"] == "https://generativelanguage.googleapis.com/v1beta/openai"
