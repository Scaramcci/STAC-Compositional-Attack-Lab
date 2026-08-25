from __future__ import annotations

import time
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Literal

from pydantic import BaseModel, Field, NonNegativeInt

from stac_attack_lab.contracts import StrictModel
from stac_attack_lab.environments.safeclaw.redaction import redact_value, scan_for_secrets
from stac_attack_lab.hashing import stable_hash
from stac_attack_lab.models.base import ModelClient
from stac_attack_lab.prompts.loader import PromptAsset
from stac_attack_lab.recording.events import append_jsonl, read_jsonl


def _now() -> str:
    return datetime.now(UTC).isoformat()


class ModelCallRequestEvent(StrictModel):
    schema_version: Literal["1.0"] = "1.0"
    kind: Literal["model_call_request"] = "model_call_request"
    call_id: str
    case_id: str
    role: Literal["planner", "attacker"]
    provider_id: str
    model_id: str
    prompt_id: str
    prompt_version: str
    prompt_hash: str
    response_schema: str
    seed: int
    timeout_seconds: NonNegativeInt
    request_messages: list[dict[str, str]]
    lineage_refs: list[str] = Field(default_factory=list)
    timestamp: str


class ModelCallResponseEvent(StrictModel):
    schema_version: Literal["1.0"] = "1.0"
    kind: Literal["model_call_response"] = "model_call_response"
    call_id: str
    case_id: str
    role: Literal["planner", "attacker"]
    latency_ms: NonNegativeInt
    retry_count: NonNegativeInt | None
    provider_request_id: str | None
    filtered_raw_response: str | None
    parsed_output: dict[str, Any]
    schema_validation: Literal["passed"]
    semantic_validation: Literal["pending"]
    usage: dict[str, Any] | None
    instrumentation_gap_reasons: list[str] = Field(default_factory=list)
    timestamp: str


class ModelCallErrorEvent(StrictModel):
    schema_version: Literal["1.0"] = "1.0"
    kind: Literal["model_call_error"] = "model_call_error"
    call_id: str
    case_id: str
    role: Literal["planner", "attacker"]
    latency_ms: NonNegativeInt
    retry_count: NonNegativeInt | None
    error_category: str
    instrumentation_gap_reasons: list[str] = Field(default_factory=list)
    timestamp: str


class ModelCallValidationEvent(StrictModel):
    schema_version: Literal["1.0"] = "1.0"
    kind: Literal["model_call_semantic_validation"] = "model_call_semantic_validation"
    call_id: str
    case_id: str
    role: Literal["planner", "attacker"]
    status: Literal["passed", "failed"]
    reason_codes: list[str] = Field(default_factory=list)
    timestamp: str


ModelCallEvent = (
    ModelCallRequestEvent | ModelCallResponseEvent | ModelCallErrorEvent | ModelCallValidationEvent
)


def validate_model_call_event(value: dict[str, Any]) -> ModelCallEvent:
    kind = value.get("kind")
    if kind == "model_call_request":
        return ModelCallRequestEvent.model_validate(value)
    if kind == "model_call_response":
        return ModelCallResponseEvent.model_validate(value)
    if kind == "model_call_error":
        return ModelCallErrorEvent.model_validate(value)
    if kind == "model_call_semantic_validation":
        return ModelCallValidationEvent.model_validate(value)
    raise ValueError(f"unknown_model_call_event_kind:{kind}")


class ObservableModelCallRecorder:
    def __init__(
        self,
        *,
        path: Path,
        case_id: str,
        role: Literal["planner", "attacker"],
        prompt: PromptAsset,
        exact_secrets: list[str],
    ) -> None:
        self.path = path
        self.case_id = case_id
        self.role = role
        self.prompt = prompt
        self.exact_secrets = [item for item in exact_secrets if item]
        self._call_index = sum(
            item.get("kind") == "model_call_request"
            and item.get("case_id") == case_id
            and item.get("role") == role
            for item in read_jsonl(path)
        )
        self.last_call_id: str | None = None
        self._close_interrupted_calls()

    def _sanitized(self, value: Any) -> Any:
        sanitized = redact_value(value, self.exact_secrets).sanitized
        if scan_for_secrets(sanitized, self.exact_secrets):
            raise ValueError("model_call_record_secret_gate_failed")
        return sanitized

    def _close_interrupted_calls(self) -> None:
        events = read_jsonl(self.path)
        requests = {
            str(item.get("call_id")): item
            for item in events
            if item.get("kind") == "model_call_request"
            and item.get("case_id") == self.case_id
            and item.get("role") == self.role
        }
        terminal_ids = {
            str(item.get("call_id"))
            for item in events
            if item.get("kind") in {"model_call_response", "model_call_error"}
        }
        response_ids = {
            str(item.get("call_id")) for item in events if item.get("kind") == "model_call_response"
        }
        validation_ids = {
            str(item.get("call_id"))
            for item in events
            if item.get("kind") == "model_call_semantic_validation"
        }
        for call_id in requests:
            if call_id not in terminal_ids:
                append_jsonl(
                    self.path,
                    ModelCallErrorEvent(
                        call_id=call_id,
                        case_id=self.case_id,
                        role=self.role,
                        latency_ms=0,
                        retry_count=None,
                        error_category="interrupted_before_terminal_event",
                        instrumentation_gap_reasons=[
                            "model_call_outcome_not_observable_after_interruption"
                        ],
                        timestamp=_now(),
                    ).model_dump(mode="json"),
                )
            elif call_id in response_ids and call_id not in validation_ids:
                append_jsonl(
                    self.path,
                    ModelCallValidationEvent(
                        call_id=call_id,
                        case_id=self.case_id,
                        role=self.role,
                        status="failed",
                        reason_codes=["interrupted_before_semantic_validation"],
                        timestamp=_now(),
                    ).model_dump(mode="json"),
                )

    def generate(
        self,
        client: ModelClient,
        messages: list[dict[str, str]],
        response_schema: type[BaseModel],
        *,
        seed: int,
        timeout: int,
        lineage_refs: list[str],
    ) -> BaseModel:
        self._call_index += 1
        provider_id = str(getattr(client, "provider_id", "unknown"))
        model_id = str(getattr(client, "model_id", getattr(client, "model", "unknown")))
        call_id = (
            f"{self.role}-call-"
            + stable_hash(
                {
                    "case_id": self.case_id,
                    "role": self.role,
                    "index": self._call_index,
                    "prompt_hash": self.prompt.hash,
                    "messages_hash": stable_hash(messages),
                    "response_schema": response_schema.__name__,
                    "seed": seed,
                }
            )[:20]
        )
        self.last_call_id = call_id
        request = ModelCallRequestEvent(
            call_id=call_id,
            case_id=self.case_id,
            role=self.role,
            provider_id=provider_id,
            model_id=model_id,
            prompt_id=self.prompt.prompt_id,
            prompt_version=self.prompt.version,
            prompt_hash=self.prompt.hash,
            response_schema=response_schema.__name__,
            seed=seed,
            timeout_seconds=timeout,
            request_messages=self._sanitized(messages),
            lineage_refs=list(dict.fromkeys(lineage_refs)),
            timestamp=_now(),
        )
        append_jsonl(self.path, request.model_dump(mode="json"))
        started = time.monotonic()
        try:
            parsed = client.generate(
                messages,
                response_schema,
                seed=seed,
                timeout=timeout,
            )
            if not isinstance(parsed, response_schema):
                raise TypeError("model_response_schema_type_mismatch")
        except Exception as exc:
            error = ModelCallErrorEvent(
                call_id=call_id,
                case_id=self.case_id,
                role=self.role,
                latency_ms=int((time.monotonic() - started) * 1000),
                retry_count=(
                    int(value)
                    if isinstance((value := getattr(client, "last_retry_count", None)), int)
                    else None
                ),
                error_category=str(
                    self._sanitized(
                        type(exc).__name__ if not str(exc) else f"{type(exc).__name__}:{str(exc)}"
                    )
                ),
                instrumentation_gap_reasons=(
                    []
                    if isinstance(getattr(client, "last_retry_count", None), int)
                    else ["model_retry_count_not_exposed"]
                ),
                timestamp=_now(),
            )
            append_jsonl(self.path, error.model_dump(mode="json"))
            raise
        raw_response = getattr(client, "last_raw_response", None)
        raw_usage = getattr(client, "last_usage", None)
        provider_request_id = getattr(client, "last_request_id", None)
        retry_count = getattr(client, "last_retry_count", None)
        gaps: list[str] = []
        if not isinstance(raw_usage, dict):
            gaps.append("model_usage_not_returned")
        if not isinstance(retry_count, int):
            gaps.append("model_retry_count_not_exposed")
        if provider_request_id is None:
            gaps.append("provider_request_id_not_returned")
        response = ModelCallResponseEvent(
            call_id=call_id,
            case_id=self.case_id,
            role=self.role,
            latency_ms=int((time.monotonic() - started) * 1000),
            retry_count=int(retry_count) if isinstance(retry_count, int) else None,
            provider_request_id=(
                str(provider_request_id) if provider_request_id is not None else None
            ),
            filtered_raw_response=(
                str(self._sanitized(raw_response)) if raw_response is not None else None
            ),
            parsed_output=self._sanitized(parsed.model_dump(mode="json")),
            schema_validation="passed",
            semantic_validation="pending",
            usage=self._sanitized(raw_usage) if isinstance(raw_usage, dict) else None,
            instrumentation_gap_reasons=gaps,
            timestamp=_now(),
        )
        append_jsonl(self.path, response.model_dump(mode="json"))
        return parsed

    def mark_semantic_validation(
        self,
        *,
        passed: bool,
        reason_codes: list[str],
    ) -> None:
        if self.last_call_id is None:
            raise ValueError("model_call_validation_without_call")
        event = ModelCallValidationEvent(
            call_id=self.last_call_id,
            case_id=self.case_id,
            role=self.role,
            status="passed" if passed else "failed",
            reason_codes=list(dict.fromkeys(reason_codes)),
            timestamp=_now(),
        )
        append_jsonl(self.path, event.model_dump(mode="json"))

    def events(self) -> list[ModelCallEvent]:
        return [validate_model_call_event(item) for item in read_jsonl(self.path)]
