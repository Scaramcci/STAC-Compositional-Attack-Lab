from __future__ import annotations

import fcntl
import http.client
import json
import os
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from pathlib import Path
from time import monotonic, time
from typing import IO, Any, cast
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
    error_category: str | None = None


@dataclass
class ProviderRequestLedger:
    """Counts requests at the urlopen boundary and enforces a hard budget."""

    max_requests: int = 10
    records: list[ProviderRequestRecord] = field(default_factory=list)

    path: Path | None = None
    batch_id: str | None = None
    _previous_count: int = field(default=0, init=False)
    _lock: IO[str] | None = field(default=None, init=False, repr=False)

    def __post_init__(self) -> None:
        if self.path is None:
            return
        if not self.batch_id:
            raise ModelCallError("attacker_ledger_batch_id_required")
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = self.path.with_suffix(".lock").open("a")
        try:
            fcntl.flock(self._lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            if self.path.exists():
                rows = [json.loads(line) for line in self.path.read_text().splitlines()]
                if any(row.get("batch_id") != self.batch_id for row in rows):
                    raise ValueError("batch mismatch")
                if any(
                    not isinstance(row, dict)
                    or row.get("stage") not in {"attempt_started", "attempt_finished"}
                    for row in rows
                ):
                    raise ValueError("invalid ledger stage")
                started_sequences: set[int] = set()
                finished_sequences: set[int] = set()
                for row in rows:
                    seq = row.get("sequence")
                    if not isinstance(seq, int) or seq <= 0:
                        raise ValueError("invalid sequence")
                    if row["stage"] == "attempt_started":
                        started_sequences.add(seq)
                    elif seq not in started_sequences or seq in finished_sequences:
                        raise ValueError("orphan or repeated completion")
                    else:
                        finished_sequences.add(seq)
                starts = [row["sequence"] for row in rows if row["stage"] == "attempt_started"]
                if starts != list(range(1, len(starts) + 1)):
                    raise ValueError("invalid reservation sequence")
                self._previous_count = len(starts)
        except Exception as exc:
            self.close()
            raise ModelCallError("attacker_ledger_unavailable_or_corrupt") from exc

    def close(self) -> None:
        if self._lock is not None:
            self._lock.close()
            self._lock = None

    def _append(self, value: dict[str, Any]) -> None:
        if self.path is not None:
            if self._lock is None:
                raise ModelCallError("attacker_ledger_closed")
            with self.path.open("a") as stream:
                stream.write(
                    json.dumps({**value, "batch_id": self.batch_id, "timestamp": time()}) + "\n"
                )
                stream.flush()
                os.fsync(stream.fileno())

    @staticmethod
    def summary(record: ProviderRequestRecord) -> dict[str, Any]:
        return {
            "sequence": record.sequence,
            "status": record.status,
            "duration_ms": record.duration_ms,
            "error_category": record.error_category,
            "usage": record.usage,
            "usage_observation": "returned" if record.usage is not None else "unknown",
        }

    def finish(self, record: ProviderRequestRecord) -> None:
        self._append({"stage": "attempt_finished", **self.summary(record)})

    def begin(self, url: str, payload: dict[str, object]) -> ProviderRequestRecord:
        if self._previous_count + len(self.records) >= self.max_requests:
            raise ModelCallError("provider_request_budget_exhausted")
        record = ProviderRequestRecord(
            self._previous_count + len(self.records) + 1, url, dict(payload)
        )
        self._append(
            {
                "stage": "attempt_started",
                "sequence": record.sequence,
                "requested_model": payload.get("model"),
                "usage_observation": "unknown",
            }
        )
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
        http_502_retries: int = 0,
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
        self.last_returned_model: str | None = None
        self.last_retry_count = 0
        self.request_ledger = request_ledger
        if not 0 <= http_502_retries <= 2:
            raise ValueError("http_502_retries_out_of_range")
        self.http_502_retries = http_502_retries
        self.last_upstream_attempts: list[dict[str, Any]] = []

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
        self.last_returned_model = None
        self.last_retry_count = 0
        self.last_upstream_attempts = []
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
            if self.http_502_retries and self.request_ledger is None:
                raise ModelCallError("retry_requires_http_attempt_ledger")
            attempt_start = len(self.request_ledger.records) if self.request_ledger else 0
            try:
                for retry_index in range(self.http_502_retries + 1):
                    try:
                        if self.request_ledger is None:
                            data = _post_json(url, payload, self._api_key, timeout)
                        else:
                            data = _post_json(
                                url, payload, self._api_key, timeout, ledger=self.request_ledger
                            )
                        break
                    except urllib.error.HTTPError as exc:
                        if exc.code != 502 or retry_index == self.http_502_retries:
                            raise
            finally:
                if self.request_ledger is not None:
                    current_records = self.request_ledger.records[attempt_start:]
                    self.last_upstream_attempts = [
                        self.request_ledger.summary(item) for item in current_records
                    ]
                    self.last_retry_count = max(0, len(current_records) - 1)
            self.last_returned_model = str(data["model"]) if data.get("model") else None
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
            data = cast(dict[str, object], json.loads(raw.decode("utf-8")))
            if record is not None and isinstance(data.get("usage"), dict):
                record.usage = cast(dict[str, Any], data["usage"])
            return data
    except urllib.error.HTTPError as exc:
        if record is not None:
            record.status = exc.code
            record.error_category = f"provider_http_{exc.code}"
            record.content_type = exc.headers.get("Content-Type")
            record.error_body = exc.read().decode("utf-8", errors="replace")[:500]
            record.duration_ms = round((monotonic() - started) * 1000, 3)
        raise
    except Exception as exc:
        if record is not None:
            record.error_category = type(exc).__name__
            record.error_body = type(exc).__name__
            record.duration_ms = round((monotonic() - started) * 1000, 3)
        raise
    finally:
        if ledger is not None and record is not None:
            ledger.finish(record)


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
