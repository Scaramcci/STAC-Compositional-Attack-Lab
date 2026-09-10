from __future__ import annotations

from pathlib import Path

from stac_attack_lab.environments.safeclaw.model_config import (
    SafeClawEmbeddingRuntime,
    build_safeclaw_model_config,
)
from stac_attack_lab.environments.safeclaw.preflight import load_safeclaw_preflight_config

ROOT = Path(__file__).resolve().parents[2]
PATCH = ROOT / "integrations/safeclaw/patches/a11f5cce-safety.patch"


def test_current_ark_config_is_strictly_allowlisted_and_has_one_port_source() -> None:
    config = load_safeclaw_preflight_config(ROOT / "configs/environments/safeclaw.yaml")
    assert config.target_model_env == "SAFECLAW_MODEL"
    assert config.target_base_url_env == "SAFECLAW_BASE_URL"
    assert config.target_api_key_env == "SAFECLAW_API_KEY"
    assert config.allowed_target_models == ["ep-20260909180104-hmx9m"]
    assert config.provider == "ark"
    assert config.api == "openai-compatible-chat-completions"
    assert config.endpoint_path == "/api/v3/chat/completions"
    assert config.context_window == 200000
    assert config.max_output_tokens == 1024
    assert config.request_budget == 8
    assert config.max_attempts == 1
    assert config.request_timeout_seconds == 90
    assert config.gateway_container_port == 18789
    assert config.embedding_proxy_container_port == 18790
    assert config.provider_relay_container_port == 18791
    assert config.gateway_host_port == 0
    assert config.upstream_legacy_gateway_host_port == 19090


def test_ark_model_config_maps_base_url_and_keeps_embedding_independent() -> None:
    payload, secrets = build_safeclaw_model_config(
        target_model_id="ep-20260909180104-hmx9m",
        target_base_url="https://ark.cn-beijing.volces.com/api/v3",
        target_api_key_env="SAFECLAW_API_KEY",
        environment={
            "SAFECLAW_API_KEY": "synthetic-ark-key",
            "SAFECLAW_EMBEDDING_API_KEY": "synthetic-embedding-key",
        },
        embedding=SafeClawEmbeddingRuntime(
            provider="ark_multimodal",
            model_id="ep-embedding",
            base_url="https://ark.cn-beijing.volces.com/api/v3/embeddings/multimodal",
            api_key_env="SAFECLAW_EMBEDDING_API_KEY",
        ),
    )
    assert payload["model"] == "ep-20260909180104-hmx9m"
    assert payload["api_base_url"] == "https://ark.cn-beijing.volces.com/api/v3"
    assert payload["provider_compat"] == "ark"
    assert payload["provider_upstream_base_url"] == payload["api_base_url"]
    assert payload["provider_request_budget"] == 128
    assert "class ProviderRelayServer" in payload["provider_relay_source"]
    assert payload["embedding_api_base_url"].endswith("/embeddings/multimodal")
    assert payload["api_key"] == "synthetic-ark-key"
    assert payload["embedding_api_key"] == "synthetic-embedding-key"
    assert secrets == [
        "synthetic-ark-key",
        "https://ark.cn-beijing.volces.com/api/v3",
        "synthetic-embedding-key",
        "https://ark.cn-beijing.volces.com/api/v3/embeddings/multimodal",
    ]


def test_ark_model_allowlist_rejects_gemini_or_unknown_ids() -> None:
    config = load_safeclaw_preflight_config(ROOT / "configs/environments/safeclaw.yaml")
    assert "gemini-2.5-flash" not in config.allowed_target_models
    assert "ep-20260909180104-hmx9m" in config.allowed_target_models


def test_gateway_patch_uses_atomic_loopback_publish_and_unique_container() -> None:
    patch = PATCH.read_text(encoding="utf-8")
    assert '+             else "127.0.0.1::18789"' in patch
    assert '+    CONTAINER = os.environ.get("SAFECLAW_CONTAINER_NAME") or' in patch
    assert '+    subprocess.run(["docker", "rm", "-f", CONTAINER]' not in patch
