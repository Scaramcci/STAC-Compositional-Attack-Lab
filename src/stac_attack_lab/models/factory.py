from __future__ import annotations

from stac_attack_lab.config import RoleModelConfig
from stac_attack_lab.models.base import ModelClient
from stac_attack_lab.models.fake import FakeModelClient
from stac_attack_lab.models.gemini import GeminiClient
from stac_attack_lab.models.huihui import HuihuiLocalClient
from stac_attack_lab.models.openai_compatible import OpenAICompatibleClient


def build_model_client(config: RoleModelConfig) -> ModelClient:
    if config.provider == "fake":
        return FakeModelClient()
    if config.provider == "gemini":
        return GeminiClient(config.model, max_output_tokens=config.max_output_tokens)
    if config.provider == "openai_compatible":
        return OpenAICompatibleClient(config.model, max_output_tokens=config.max_output_tokens)
    if config.provider == "huihui_local":
        return HuihuiLocalClient(config.model, max_output_tokens=config.max_output_tokens)
    raise ValueError(f"unsupported model provider: {config.provider}")
