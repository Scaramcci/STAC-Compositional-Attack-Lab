from __future__ import annotations

import http.client
import json
import os
import urllib.error
import urllib.parse
import urllib.request
from typing import Any, cast

from pydantic import BaseModel

from stac_attack_lab.models.base import ModelCallError
from stac_attack_lab.models.openai_compatible import _extract_json


class GeminiClient:
    provider_id = "gemini"

    def __init__(self, model_id: str | None = None, max_output_tokens: int = 1200) -> None:
        self._api_key = os.environ.get("GEMINI_API_KEY")
        self.model_id = model_id or os.environ.get("GEMINI_MODEL") or "gemini-2.5-flash"
        self.max_output_tokens = max_output_tokens
        self.last_raw_response: str | None = None
        self.last_usage: dict[str, Any] | None = None
        self.last_request_id: str | None = None
        self.last_retry_count = 0

    def generate(
        self,
        messages: list[dict[str, str]],
        response_schema: type[BaseModel],
        seed: int,
        timeout: int,
    ) -> BaseModel:
        self.last_raw_response = None
        self.last_usage = None
        self.last_request_id = None
        self.last_retry_count = 0
        if not self._api_key:
            raise ModelCallError("missing_gemini_env")
        prompt = (
            "Return JSON only. The JSON must validate this schema:\n"
            + json.dumps(response_schema.model_json_schema(), sort_keys=True)
            + "\n\nInput:\n"
            + json.dumps(messages, ensure_ascii=False)
        )
        endpoint = (
            "https://generativelanguage.googleapis.com/v1beta/models/"
            + urllib.parse.quote(self.model_id, safe="")
            + ":generateContent?key="
            + urllib.parse.quote(self._api_key, safe="")
        )
        payload: dict[str, object] = {
            "contents": [{"role": "user", "parts": [{"text": prompt}]}],
            "generationConfig": {
                "temperature": 0,
                "maxOutputTokens": self.max_output_tokens,
                "responseMimeType": "application/json",
                "seed": seed,
            },
        }
        last_error: Exception | None = None
        for _attempt in range(2):
            try:
                data = _post(endpoint, payload, timeout)
                candidates = cast(list[dict[str, Any]], data["candidates"])
                content = cast(str, candidates[0]["content"]["parts"][0]["text"])
                self.last_raw_response = content
                usage = data.get("usageMetadata")
                self.last_usage = dict(usage) if isinstance(usage, dict) else None
                request_id = data.get("responseId")
                self.last_request_id = str(request_id) if request_id is not None else None
                self.last_retry_count = _attempt
                return response_schema.model_validate(json.loads(_extract_json(content)))
            except urllib.error.HTTPError as exc:
                self.last_retry_count = _attempt
                category = "quota" if exc.code == 429 else f"provider_http_{exc.code}"
                raise ModelCallError(category) from exc
            except (
                KeyError,
                json.JSONDecodeError,
                urllib.error.URLError,
                TimeoutError,
                http.client.RemoteDisconnected,
            ) as exc:
                last_error = exc
                self.last_retry_count = _attempt
        assert last_error is not None
        raise ModelCallError(type(last_error).__name__.lower()) from last_error


def _post(url: str, payload: dict[str, object], timeout: int) -> dict[str, object]:
    request = urllib.request.Request(
        url,
        data=json.dumps(payload).encode("utf-8"),
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    with urllib.request.urlopen(request, timeout=timeout) as response:
        return cast(dict[str, object], json.loads(response.read().decode("utf-8")))
