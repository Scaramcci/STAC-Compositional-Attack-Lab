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
    def __init__(self, model_id: str, max_output_tokens: int = 1200) -> None:
        self.model_id = model_id
        self.max_output_tokens = max_output_tokens
        self.base_url = os.environ.get("OPENAI_BASE_URL") or os.environ.get(
            "OPENAI_COMPATIBLE_BASE_URL"
        )
        self._api_key = os.environ.get("OPENAI_API_KEY") or os.environ.get(
            "OPENAI_COMPATIBLE_API_KEY"
        )

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
        if not self.base_url or not self._api_key:
            raise ModelCallError("missing_openai_compatible_env")
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
        }
        try:
            data = _post_json(url, payload, self._api_key, timeout)
            choices = cast(list[dict[str, Any]], data["choices"])
            content = cast(str, choices[0]["message"]["content"])
            return response_schema.model_validate(json.loads(_extract_json(content)))
        except urllib.error.HTTPError as exc:
            raise ModelCallError(
                f"openai_compatible_smoke_failed:HTTPError:{exc.code}:{exc.reason}"
            ) from exc
        except (
            KeyError,
            json.JSONDecodeError,
            urllib.error.URLError,
            TimeoutError,
            http.client.RemoteDisconnected,
        ) as exc:
            raise ModelCallError(f"openai_compatible_smoke_failed:{type(exc).__name__}") from exc


def _post_json(
    url: str, payload: dict[str, object], api_key: str, timeout: int
) -> dict[str, object]:
    request = urllib.request.Request(
        url,
        data=json.dumps(payload).encode("utf-8"),
        headers={
            "Authorization": f"Bearer {api_key}",
            "Content-Type": "application/json",
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
