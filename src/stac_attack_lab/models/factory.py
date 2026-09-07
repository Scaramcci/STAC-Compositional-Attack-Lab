from __future__ import annotations

from stac_attack_lab.config import RoleModelConfig
from stac_attack_lab.models.base import ModelClient
from stac_attack_lab.models.openai_compatible import OpenAICompatibleClient


def build_model_client(config: RoleModelConfig) -> ModelClient:
    if config.provider == "openai_compatible":
        return OpenAICompatibleClient(
            config.model,
            max_output_tokens=config.max_output_tokens,
            base_url_env=config.base_url_env,
            api_key_env=config.api_key_env,
        )
    raise ValueError(f"unsupported model provider: {config.provider}")
