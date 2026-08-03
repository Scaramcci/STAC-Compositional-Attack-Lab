from __future__ import annotations

import os

from stac_attack_lab.models.openai_compatible import OpenAICompatibleClient


class HuihuiLocalClient(OpenAICompatibleClient):
    def __init__(self, model_id: str, max_output_tokens: int = 1200) -> None:
        super().__init__(model_id, max_output_tokens=max_output_tokens)
        self.base_url = os.environ.get("HUIHUI_BASE_URL") or self.base_url
        self._api_key = os.environ.get("HUIHUI_API_KEY") or self._api_key or "local-no-key"
