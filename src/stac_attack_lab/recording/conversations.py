from __future__ import annotations

import os
import time
from datetime import UTC, datetime
from enum import StrEnum
from pathlib import Path
from typing import Any, Literal

from pydantic import Field, NonNegativeInt, PositiveInt

from stac_attack_lab.contracts import ActorRole, StrictModel
from stac_attack_lab.hashing import stable_hash
from stac_attack_lab.recording.events import append_jsonl, read_jsonl

SECRET_ENV_NAMES = (
    "OPENAI_API_KEY",
    "GEMINI_API_KEY",
    "HUIHUI_API_KEY",
)
VICTIM_FORBIDDEN_FIELDS = (
    "private_oracle",
    "attack_graph",
    "condition_name",
    "verifier_target",
    "expected_predicate",
)


class ConversationEventType(StrEnum):
    model_request = "model_request"
    model_response = "model_response"
    model_error = "model_error"
    tool_request = "tool_request"
    tool_result = "tool_result"
    verifier_result = "verifier_result"
    retry = "retry"
    fallback = "fallback"
    refusal = "refusal"


class ConversationMessage(StrictModel):
    role: Literal["system", "developer", "user", "assistant", "tool"]
    content: str
    name: str | None = None
    tool_call_id: str | None = None


class SchemaValidationRecord(StrictModel):
    schema_id: str | None
    valid: bool | None
    error_category: str | None = None


class ConversationEvent(StrictModel):
    schema_version: Literal["1.0"] = "1.0"
    event_id: str
    call_id: str
    run_id: str
    attack_id: str
    idempotency_key: str
    phase: Literal["offline", "evaluation"]
    condition: str
    seed: int
    sequence_no: NonNegativeInt
    timestamp: datetime
    attempt_no: PositiveInt
    event_type: ConversationEventType
    sender_role: ActorRole
    recipient_role: ActorRole
    model_provider: str | None
    model_id: str | None
    model_config_hash: str | None
    prompt_id: str | None
    prompt_version: str | None
    prompt_hash: str | None
    input_schema_id: str | None
    output_schema_id: str | None
    request_messages: list[ConversationMessage]
    raw_model_response: str | None
    parsed_structured_response: dict[str, Any] | None
    schema_validation: SchemaValidationRecord
    token_metadata: dict[str, NonNegativeInt] = Field(default_factory=dict)
    latency_ms: NonNegativeInt | None = None
    error_category: str | None = None
    related_event_ids: list[str] = Field(default_factory=list)
    artifact_refs: list[str] = Field(default_factory=list)
    snapshot_refs: list[str] = Field(default_factory=list)
    hard_verdict_refs: list[str] = Field(default_factory=list)
    redactions: list[str]


class TranscriptAuditFinding(StrictModel):
    code: str
    message: str
    event_ids: list[str]


class TranscriptAuditReport(StrictModel):
    schema_version: Literal["1.0"] = "1.0"
    run_id: str
    passed: bool
    event_count: NonNegativeInt
    findings: list[TranscriptAuditFinding]


def _secret_values() -> tuple[str, ...]:
    return tuple(value for name in SECRET_ENV_NAMES if (value := os.environ.get(name)))


def redact_value(value: Any) -> tuple[Any, list[str]]:
    """Redact configured secrets before a value is recorded or hashed."""
    secrets = _secret_values()
    redactions = ["environment_secret_filter_applied"]

    def visit(item: Any) -> Any:
        if isinstance(item, str):
            clean = item
            for secret in secrets:
                if secret in clean:
                    clean = clean.replace(secret, "[REDACTED_SECRET]")
                    if "secret_value_removed" not in redactions:
                        redactions.append("secret_value_removed")
            return clean
        if isinstance(item, dict):
            return {str(key): visit(child) for key, child in item.items()}
        if isinstance(item, list):
            return [visit(child) for child in item]
        if isinstance(item, tuple):
            return [visit(child) for child in item]
        return item

    return visit(value), redactions


class ConversationRecorder:
    def __init__(self, path: Path) -> None:
        self.path = path
        existing = read_jsonl(path)
        self._seen = {str(item["event_id"]) for item in existing}
        self._next_sequence = len(existing)

    @staticmethod
    def stable_call_id(idempotency_key: str, role: ActorRole, stage: str, attempt: int) -> str:
        return (
            "call-"
            + stable_hash(
                {
                    "idempotency_key": idempotency_key,
                    "role": role.value,
                    "stage": stage,
                    "attempt": attempt,
                }
            )[:24]
        )

    def append(self, **values: Any) -> ConversationEvent:
        event_id = str(values["event_id"])
        if event_id in self._seen:
            match = next(item for item in read_jsonl(self.path) if item["event_id"] == event_id)
            return ConversationEvent.model_validate(match)
        safe_values, redactions = redact_value(values)
        safe_values["sequence_no"] = self._next_sequence
        safe_values["timestamp"] = datetime.now(UTC)
        safe_values["redactions"] = redactions
        event = ConversationEvent.model_validate(safe_values)
        append_jsonl(self.path, event.model_dump(mode="json"))
        self._seen.add(event_id)
        self._next_sequence += 1
        return event

    def record_model_call(
        self,
        *,
        run_id: str,
        attack_id: str,
        idempotency_key: str,
        phase: Literal["offline", "evaluation"],
        condition: str,
        seed: int,
        attempt_no: int,
        sender_role: ActorRole,
        recipient_role: ActorRole,
        provider: str,
        model_id: str,
        model_config: dict[str, Any],
        prompt_id: str,
        prompt_version: str,
        prompt_hash: str,
        input_schema_id: str,
        output_schema_id: str,
        messages: list[dict[str, str]],
        invoke: Any,
    ) -> Any:
        call_id = self.stable_call_id(idempotency_key, recipient_role, prompt_id, attempt_no)
        common = {
            "call_id": call_id,
            "run_id": run_id,
            "attack_id": attack_id,
            "idempotency_key": idempotency_key,
            "phase": phase,
            "condition": condition,
            "seed": seed,
            "attempt_no": attempt_no,
            "sender_role": sender_role,
            "recipient_role": recipient_role,
            "model_provider": provider,
            "model_id": model_id,
            "model_config_hash": stable_hash(model_config),
            "prompt_id": prompt_id,
            "prompt_version": prompt_version,
            "prompt_hash": prompt_hash,
            "input_schema_id": input_schema_id,
            "output_schema_id": output_schema_id,
            "request_messages": messages,
            "token_metadata": {},
        }
        request = self.append(
            **common,
            event_id=f"{call_id}-request",
            event_type=ConversationEventType.model_request,
            raw_model_response=None,
            parsed_structured_response=None,
            schema_validation=SchemaValidationRecord(schema_id=output_schema_id, valid=None),
        )
        started = time.monotonic()
        try:
            output = invoke()
        except Exception as exc:
            category = categorize_model_error(exc)
            self.append(
                **common,
                event_id=f"{call_id}-error",
                event_type=ConversationEventType.model_error,
                raw_model_response=None,
                parsed_structured_response=None,
                schema_validation=SchemaValidationRecord(
                    schema_id=output_schema_id, valid=False, error_category=category
                ),
                latency_ms=int((time.monotonic() - started) * 1000),
                error_category=category,
                related_event_ids=[request.event_id],
            )
            raise
        parsed = output.model_dump(mode="json")
        raw = _observable_raw_response(invoke)
        self.append(
            **common,
            event_id=f"{call_id}-response",
            event_type=ConversationEventType.model_response,
            raw_model_response=raw if isinstance(raw, str) else None,
            parsed_structured_response=parsed,
            schema_validation=SchemaValidationRecord(schema_id=output_schema_id, valid=True),
            latency_ms=int((time.monotonic() - started) * 1000),
            related_event_ids=[request.event_id],
        )
        return output


def _observable_raw_response(invoke: Any) -> str | None:
    sources = [invoke]
    closure = getattr(invoke, "__closure__", None)
    if closure:
        sources.extend(cell.cell_contents for cell in closure)
    for source in sources:
        raw = getattr(source, "last_raw_response", None)
        if isinstance(raw, str):
            return raw
        nested_client = getattr(source, "client", None)
        nested_raw = getattr(nested_client, "last_raw_response", None)
        if isinstance(nested_raw, str):
            return nested_raw
    return None


def categorize_model_error(exc: BaseException) -> str:
    text = str(exc).lower()
    if "429" in text or "quota" in text or "rate_limit" in text or "resource_exhausted" in text:
        return "quota"
    if isinstance(exc, TimeoutError) or "timeout" in text:
        return "timeout"
    if "schema" in text or "validation" in text or "json" in text:
        return "schema_validation"
    if "missing" in text and "env" in text:
        return "configuration"
    if "refusal" in text:
        return "refusal"
    return "provider_error"


def audit_transcript(
    path: Path,
    *,
    expected_run_id: str,
    expected_role_models: dict[str, tuple[str, str]] | None = None,
    required_roles: set[ActorRole] | None = None,
) -> TranscriptAuditReport:
    findings: list[TranscriptAuditFinding] = []
    raw_events = read_jsonl(path)
    events: list[ConversationEvent] = []
    for index, raw in enumerate(raw_events):
        try:
            events.append(ConversationEvent.model_validate(raw))
        except ValueError:
            findings.append(
                TranscriptAuditFinding(
                    code="schema_invalid",
                    message=f"Conversation event at row {index} is invalid.",
                    event_ids=[str(raw.get("event_id", "unknown"))],
                )
            )
    for index, event in enumerate(events):
        if event.sequence_no != index:
            findings.append(
                TranscriptAuditFinding(
                    code="sequence_gap",
                    message=f"Expected sequence {index}, found {event.sequence_no}.",
                    event_ids=[event.event_id],
                )
            )
        if event.run_id != expected_run_id:
            findings.append(
                TranscriptAuditFinding(
                    code="run_mismatch",
                    message="Event belongs to a different run.",
                    event_ids=[event.event_id],
                )
            )
        if not event.redactions or "environment_secret_filter_applied" not in event.redactions:
            findings.append(
                TranscriptAuditFinding(
                    code="redaction_unproven",
                    message="Secret filtering is not recorded.",
                    event_ids=[event.event_id],
                )
            )
        if event.recipient_role == ActorRole.victim:
            visible = " ".join(message.content.lower() for message in event.request_messages)
            leaked = [field for field in VICTIM_FORBIDDEN_FIELDS if field in visible]
            if leaked:
                findings.append(
                    TranscriptAuditFinding(
                        code="victim_role_leak",
                        message="Victim-visible messages include forbidden experiment metadata.",
                        event_ids=[event.event_id],
                    )
                )
        if expected_role_models and event.model_provider is not None:
            expected = expected_role_models.get(event.recipient_role.value)
            if expected and (event.model_provider, event.model_id) != expected:
                findings.append(
                    TranscriptAuditFinding(
                        code="model_assignment_mismatch",
                        message="Recorded provider/model does not match the role profile.",
                        event_ids=[event.event_id],
                    )
                )
        if (
            event.model_provider is not None
            and event.event_type != ConversationEventType.model_request
        ):
            request_id = f"{event.call_id}-request"
            if request_id not in {candidate.event_id for candidate in events}:
                findings.append(
                    TranscriptAuditFinding(
                        code="orphan_call_result",
                        message="Call result has no corresponding request event.",
                        event_ids=[event.event_id],
                    )
                )
    if required_roles:
        observed = {event.recipient_role for event in events}
        for role in sorted(required_roles - observed, key=lambda item: item.value):
            findings.append(
                TranscriptAuditFinding(
                    code="required_role_missing",
                    message=f"No conversation event was recorded for role {role.value}.",
                    event_ids=[],
                )
            )
    return TranscriptAuditReport(
        run_id=expected_run_id,
        passed=not findings,
        event_count=len(events),
        findings=findings,
    )
