from __future__ import annotations

import http.client
import json
import os
import urllib.error
import urllib.request
from typing import Any, cast
from urllib.parse import urlparse

from pydantic import BaseModel

from stac_attack_lab.models.base import ModelCallError


class OpenAICompatibleClient:
    provider_id = "openai_compatible"

    def __init__(
        self,
        model_id: str,
        max_output_tokens: int = 1200,
        *,
        use_response_format: bool = False,
    ) -> None:
        self.model_id = model_id
        self.max_output_tokens = max_output_tokens
        self.use_response_format = use_response_format
        self.base_url = os.environ.get("OPENAI_BASE_URL")
        self._api_key = os.environ.get("OPENAI_API_KEY")
        self.last_raw_response: str | None = None
        self.last_usage: dict[str, Any] | None = None
        self.last_request_id: str | None = None
        self.last_retry_count = 0

    @property
    def endpoint_host(self) -> str:
        return urlparse(self.base_url or "").netloc

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
        if not self.base_url or not self._api_key:
            raise ModelCallError("missing_openai_env")
        url = self.base_url.rstrip("/") + "/chat/completions"
        schema = response_schema.model_json_schema()
        prompt = "Return JSON only. The JSON must validate this schema:\n" + json.dumps(
            schema, sort_keys=True
        )
        payload = {
            "model": self.model_id,
            "messages": [{"role": "system", "content": prompt}, *messages],
            "temperature": 0,
            "max_tokens": self.max_output_tokens,
            "seed": seed,
        }
        if self.use_response_format:
            payload["response_format"] = {
                "type": "json_schema",
                "json_schema": {
                    "name": response_schema.__name__,
                    "schema": schema,
                    "strict": True,
                },
            }
        try:
            data = _post_json(url, payload, self._api_key, timeout)
            choices = cast(list[dict[str, Any]], data["choices"])
            content = cast(str, choices[0]["message"]["content"])
            usage = data.get("usage")
            self.last_usage = dict(usage) if isinstance(usage, dict) else None
            request_id = data.get("id")
            self.last_request_id = str(request_id) if request_id is not None else None
            self.last_raw_response = content
            return response_schema.model_validate(json.loads(_extract_json(content)))
        except urllib.error.HTTPError as exc:
            category = "quota" if exc.code == 429 else f"provider_http_{exc.code}"
            raise ModelCallError(category) from exc
        except (
            KeyError,
            json.JSONDecodeError,
            urllib.error.URLError,
            TimeoutError,
            http.client.RemoteDisconnected,
        ) as exc:
            raise ModelCallError(type(exc).__name__.lower()) from exc


def _post_json(
    url: str, payload: dict[str, object], api_key: str, timeout: int
) -> dict[str, object]:
    request = urllib.request.Request(
        url,
        data=json.dumps(payload).encode("utf-8"),
        headers={
            "Authorization": f"Bearer {api_key}",
            "Content-Type": "application/json",
            # Some OpenAI-compatible gateways reject urllib's default
            # Python-urllib user agent before the request reaches the model.
            "User-Agent": "OpenAI/Python 1.0.0",
        },
        method="POST",
    )
    with urllib.request.urlopen(request, timeout=timeout) as response:
        return cast(dict[str, object], json.loads(response.read().decode("utf-8")))


def _extract_json(content: str) -> str:
    stripped = content.strip()
    if stripped.startswith("```"):
        stripped = stripped.strip("`")
        if stripped.startswith("json"):
            stripped = stripped[4:]
    start = stripped.find("{")
    end = stripped.rfind("}")
    if start == -1 or end == -1 or end < start:
        raise json.JSONDecodeError("no json object", content, 0)
    return stripped[start : end + 1]
