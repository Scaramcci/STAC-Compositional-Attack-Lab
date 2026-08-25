from __future__ import annotations

import os

from stac_attack_lab.config import HUIHUI_DEFAULT_BASE_URL
from stac_attack_lab.models.openai_compatible import OpenAICompatibleClient


class HuihuiLocalClient(OpenAICompatibleClient):
    provider_id = "huihui_local"

    def __init__(self, model_id: str, max_output_tokens: int = 1200) -> None:
        resolved_model = os.environ.get("HUIHUI_MODEL") or model_id
        super().__init__(
            resolved_model,
            max_output_tokens=max_output_tokens,
            use_response_format=True,
        )
        self.base_url = os.environ.get("HUIHUI_BASE_URL") or HUIHUI_DEFAULT_BASE_URL
        self._api_key = os.environ.get("HUIHUI_API_KEY") or "local-no-key"
