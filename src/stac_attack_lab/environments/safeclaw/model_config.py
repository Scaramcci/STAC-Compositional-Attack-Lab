from __future__ import annotations

from collections.abc import Mapping
from pathlib import Path
from typing import Any, Literal

from stac_attack_lab.contracts import StrictModel


class SafeClawEmbeddingRuntime(StrictModel):
    provider: Literal["openai", "ark_multimodal"]
    model_id: str
    base_url: str
    api_key_env: str


def _chat_provider_root(base_url: str) -> str:
    """Preserve the operator-provided API root without guessing a version suffix."""
    return base_url.rstrip("/")


def _provider_compat(base_url: str) -> str:
    normalized = base_url.rstrip("/")
    if normalized.endswith("/api/v3"):
        return "ark"
    if normalized.endswith("/openai"):
        return "gemini"
    return "openai"


def _embedding_endpoint_root(base_url: str) -> str:
    normalized = base_url.rstrip("/")
    # Gemini's OpenAI-compatible endpoint already includes its API root
    # (/v1beta/openai); other OpenAI gateways conventionally need /v1.
    if (
        normalized.endswith("/openai")
        or normalized.endswith("/v1")
        or normalized.endswith("/api/v3")
    ):
        return normalized
    return normalized + "/v1"


def build_safeclaw_model_config(
    *,
    target_model_id: str,
    target_base_url: str,
    target_api_key_env: str,
    environment: Mapping[str, str],
    embedding: SafeClawEmbeddingRuntime | None = None,
    provider_request_budget: int = 128,
    provider_timeout_seconds: int = 90,
    provider_allowed_tools: list[str] | None = None,
    embedding_request_budget: int = 128,
    provider_context_window: int = 200000,
    provider_max_output_tokens: int = 1024,
) -> tuple[dict[str, Any], list[str]]:
    target_api_key = environment.get(target_api_key_env)
    if not target_api_key:
        raise ValueError(f"missing_environment_variable:{target_api_key_env}")
    if (
        min(
            provider_request_budget,
            provider_timeout_seconds,
            provider_context_window,
            provider_max_output_tokens,
            embedding_request_budget,
        )
        < 1
    ):
        raise ValueError("safeclaw_provider_transport_limits_must_be_positive")
    if provider_allowed_tools is not None and len(provider_allowed_tools) != len(
        set(provider_allowed_tools)
    ):
        raise ValueError("safeclaw_provider_allowed_tools_duplicate")
    payload: dict[str, Any] = {
        "model": target_model_id,
        "api_base_url": _chat_provider_root(target_base_url),
        "api_key": target_api_key,
        "provider_compat": _provider_compat(target_base_url),
        "provider_relay_source": Path(__file__)
        .with_name("provider_relay.py")
        .read_text(encoding="utf-8"),
        "provider_upstream_base_url": _chat_provider_root(target_base_url),
        "provider_upstream_api_key": target_api_key,
        "provider_request_budget": provider_request_budget,
        "provider_timeout_seconds": provider_timeout_seconds,
        "provider_allowed_tools": provider_allowed_tools,
        "embedding_request_budget": embedding_request_budget,
        "provider_context_window": provider_context_window,
        "provider_max_output_tokens": provider_max_output_tokens,
    }
    exact_secrets = [target_api_key, target_base_url]
    if embedding is None:
        return payload, exact_secrets
    embedding_api_key = environment.get(embedding.api_key_env)
    if not embedding_api_key:
        raise ValueError(f"missing_environment_variable:{embedding.api_key_env}")
    payload.update(
        {
            "embedding_provider": embedding.provider,
            "embedding_model": embedding.model_id,
            "embedding_api_base_url": _embedding_endpoint_root(embedding.base_url),
            "embedding_api_key": embedding_api_key,
        }
    )
    if embedding.provider == "ark_multimodal":
        payload["embedding_api_base_url"] = embedding.base_url.rstrip("/")
        payload["embedding_adapter_source"] = (
            Path(__file__).with_name("ark_embedding_proxy.py").read_text(encoding="utf-8")
        )
    exact_secrets.extend([embedding_api_key, embedding.base_url])
    return payload, list(dict.fromkeys(exact_secrets))
