from __future__ import annotations

import http.client
import json
import os
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from time import monotonic
from typing import Any, cast
from urllib.parse import urlparse

from pydantic import BaseModel

from stac_attack_lab.models.base import ModelCallError


@dataclass
class ProviderRequestRecord:
    sequence: int
    url: str
    payload: dict[str, object]
    status: int | None = None
    content_type: str | None = None
    error_body: str | None = None
    duration_ms: float | None = None
    usage: dict[str, Any] | None = None


@dataclass
class ProviderRequestLedger:
    """Counts requests at the urlopen boundary and enforces a hard budget."""

    max_requests: int = 10
    records: list[ProviderRequestRecord] = field(default_factory=list)

    def begin(self, url: str, payload: dict[str, object]) -> ProviderRequestRecord:
        if len(self.records) >= self.max_requests:
            raise ModelCallError("provider_request_budget_exhausted")
        record = ProviderRequestRecord(len(self.records) + 1, url, dict(payload))
        self.records.append(record)
        return record


class OpenAICompatibleClient:
    provider_id = "openai_compatible"

    def __init__(
        self,
        model_id: str,
        max_output_tokens: int = 1200,
        *,
        use_response_format: bool = False,
        base_url_env: str = "OPENAI_BASE_URL",
        api_key_env: str = "OPENAI_API_KEY",
        request_ledger: ProviderRequestLedger | None = None,
    ) -> None:
        self.model_id = model_id
        self.max_output_tokens = max_output_tokens
        self.use_response_format = use_response_format
        self.base_url_env = base_url_env
        self.api_key_env = api_key_env
        self.base_url = os.environ.get(base_url_env)
        self._api_key = os.environ.get(api_key_env)
        self.last_raw_response: str | None = None
        self.last_usage: dict[str, Any] | None = None
        self.last_request_id: str | None = None
        self.last_retry_count = 0
        self.request_ledger = request_ledger

    @property
    def endpoint_host(self) -> str:
        return urlparse(self.base_url or "").netloc

    @property
    def _is_gemini_endpoint(self) -> bool:
        return self.endpoint_host == "generativelanguage.googleapis.com"

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
            raise ModelCallError(f"missing_model_env:{self.base_url_env}:{self.api_key_env}")
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
        # Gemini rejects the OpenAI-only seed field.
        if not self._is_gemini_endpoint:
            payload["seed"] = seed
        if self._is_gemini_endpoint:
            payload["response_format"] = {"type": "json_object"}
        elif self.use_response_format:
            payload["response_format"] = {
                "type": "json_schema",
                "json_schema": {
                    "name": response_schema.__name__,
                    "schema": schema,
                    "strict": True,
                },
            }
        try:
            if self.request_ledger is None:
                data = _post_json(url, payload, self._api_key, timeout)
            else:
                data = _post_json(url, payload, self._api_key, timeout, ledger=self.request_ledger)
            choices = cast(list[dict[str, Any]], data["choices"])
            content = cast(str, choices[0]["message"]["content"])
            usage = data.get("usage")
            self.last_usage = dict(usage) if isinstance(usage, dict) else None
            if self.request_ledger is not None and self.request_ledger.records:
                self.request_ledger.records[-1].usage = self.last_usage
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
    url: str,
    payload: dict[str, object],
    api_key: str,
    timeout: int,
    *,
    ledger: ProviderRequestLedger | None = None,
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
    record = ledger.begin(url, payload) if ledger is not None else None
    started = monotonic()
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            raw = response.read()
            if record is not None:
                record.status = response.status
                record.content_type = response.headers.get("Content-Type")
                record.duration_ms = round((monotonic() - started) * 1000, 3)
            return cast(dict[str, object], json.loads(raw.decode("utf-8")))
    except urllib.error.HTTPError as exc:
        if record is not None:
            record.status = exc.code
            record.content_type = exc.headers.get("Content-Type")
            record.error_body = exc.read().decode("utf-8", errors="replace")[:500]
            record.duration_ms = round((monotonic() - started) * 1000, 3)
        raise
    except Exception as exc:
        if record is not None:
            record.error_body = type(exc).__name__
            record.duration_ms = round((monotonic() - started) * 1000, 3)
        raise


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
