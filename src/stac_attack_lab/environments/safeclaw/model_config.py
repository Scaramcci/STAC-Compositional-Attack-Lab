from __future__ import annotations

from collections.abc import Mapping
from pathlib import Path
from typing import Literal

from stac_attack_lab.contracts import StrictModel


class SafeClawEmbeddingRuntime(StrictModel):
    provider: Literal["openai", "ark_multimodal"]
    model_id: str
    base_url: str
    api_key_env: str


def _chat_provider_root(base_url: str) -> str:
    normalized = base_url.rstrip("/")
    return normalized[:-3] if normalized.endswith("/v1") else normalized


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
) -> tuple[dict[str, str], list[str]]:
    target_api_key = environment.get(target_api_key_env)
    if not target_api_key:
        raise ValueError(f"missing_environment_variable:{target_api_key_env}")
    payload = {
        "model": target_model_id,
        "api_base_url": _chat_provider_root(target_base_url),
        "api_key": target_api_key,
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
