"""Independent verification of bounded provider request-boundary evidence."""

from __future__ import annotations

import base64
import hashlib
import json
import re
from pathlib import Path
from typing import Any

from stac_attack_lab.environments.safeclaw.provider_relay import (
    EXACT_DERIVATION_RULE,
    UTF8_STRING_PROJECTION,
)
from stac_attack_lab.hashing import file_hash
from stac_attack_lab.interactions.models import RawInteractionTrajectory

EVIDENCE_REF = re.compile(r"^provider-evidence:([^:]+):([0-9a-f]{64})$")


def _canonical_bytes(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode(
        "utf-8"
    )


def _record_hash(record: dict[str, Any]) -> str:
    return hashlib.sha256(
        _canonical_bytes({key: value for key, value in record.items() if key != "record_sha256"})
    ).hexdigest()


def load_provider_evidence(
    trajectory: RawInteractionTrajectory, collection: Path
) -> tuple[dict[str, dict[str, Any]], dict[str, Any]]:
    refs = [ref for ref in trajectory.evidence_refs if ref.kind == "provider_boundary_evidence"]
    if not refs:
        return {}, {"state": "unknown", "reason_code": "provider_evidence_file_missing"}
    if len(refs) != 1 or refs[0].relative_path is None:
        return {}, {"state": "failed", "reason_code": "provider_evidence_ref_ambiguous"}
    path = collection / refs[0].relative_path
    try:
        observed_hash = file_hash(path)
        if observed_hash != refs[0].content_hash:
            return {}, {"state": "failed", "reason_code": "provider_evidence_file_hash_mismatch"}
        records: dict[str, dict[str, Any]] = {}
        for line_number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
            if not line.strip():
                continue
            raw = json.loads(line)
            if not isinstance(raw, dict):
                raise ValueError(f"row_not_object:{line_number}")
            record_id = raw.get("record_id")
            record_sha = raw.get("record_sha256")
            if not isinstance(record_id, str) or not isinstance(record_sha, str):
                raise ValueError(f"record_identity_missing:{line_number}")
            if record_sha != _record_hash(raw):
                raise ValueError(f"record_hash_mismatch:{line_number}")
            if record_id in records:
                raise ValueError(f"duplicate_record_id:{record_id}")
            records[record_id] = raw
    except (OSError, UnicodeError, json.JSONDecodeError, ValueError) as exc:
        return {}, {
            "state": "failed",
            "reason_code": "provider_evidence_file_corrupt",
            "detail": str(exc)[:300],
        }
    return records, {
        "state": "observed",
        "reason_code": "provider_evidence_file_verified",
        "content_hash": observed_hash,
        "path": str(path),
    }


def _decode_projection(value: dict[str, Any]) -> bytes | None:
    if (
        value.get("projection_kind") != UTF8_STRING_PROJECTION
        or value.get("projection_complete") is not True
        or not isinstance(value.get("projection_base64"), str)
    ):
        return None
    try:
        decoded = base64.b64decode(value["projection_base64"], validate=True)
    except ValueError:
        return None
    if hashlib.sha256(decoded).hexdigest() != value.get("projection_sha256") or len(
        decoded
    ) != value.get("projection_byte_length"):
        return None
    try:
        decoded.decode("utf-8", errors="strict")
    except UnicodeError:
        return None
    return decoded


def _resolve_ref(ref: str, records: dict[str, dict[str, Any]]) -> dict[str, Any] | None:
    match = EVIDENCE_REF.fullmatch(ref)
    if not match:
        return None
    record = records.get(match.group(1))
    if record is None or record.get("record_sha256") != match.group(2):
        return None
    return record


def verify_context_candidate(
    *,
    trajectory: RawInteractionTrajectory,
    source_artifact: Any,
    source_event: Any,
    consumer_event: Any,
    candidate: dict[str, Any],
    records: dict[str, dict[str, Any]],
    bundle_status: dict[str, Any],
) -> dict[str, Any]:
    """Recompute layer B without treating request reachability as semantic use."""
    if bundle_status.get("state") != "observed":
        return {
            "state": str(bundle_status.get("state", "unknown")),
            "reason_code": str(bundle_status.get("reason_code")),
        }
    refs = [str(value) for value in candidate.get("evidence_ref_ids", [])]
    resolved = [_resolve_ref(ref, records) for ref in refs]
    response = next(
        (r for r in resolved if r and r.get("record_type") == "provider_response"), None
    )
    context = next(
        (
            r
            for r in resolved
            if r
            and r.get("record_type") == "control_context"
            and r.get("context_state") == "closed"
        ),
        None,
    )
    if response is None or context is None:
        return {"state": "failed", "reason_code": "context_required_records_missing"}
    attempted = next(
        (
            r
            for r in records.values()
            if r.get("record_type") == "provider_request"
            and r.get("send_state") == "attempted"
            and r.get("request_id") == response.get("request_id")
        ),
        None,
    )
    if attempted is None:
        return {"state": "failed", "reason_code": "provider_request_attempt_missing"}
    if any(
        record.get("record_sha256") != _record_hash(record)
        for record in (attempted, response, context)
    ):
        return {"state": "failed", "reason_code": "provider_evidence_record_hash_mismatch"}
    batch = response.get("batch_id")
    expected_batch = trajectory.provenance.get("provider_evidence_batch_id")
    if (
        not batch
        or any(record.get("batch_id") != batch for record in (attempted, context))
        or (expected_batch and expected_batch != batch)
    ):
        return {"state": "failed", "reason_code": "provider_evidence_batch_mismatch"}
    if (
        response.get("send_state") != "response_received"
        or response.get("control_context_id") != context.get("control_context_id")
        or attempted.get("control_context_id") != context.get("control_context_id")
        or context.get("close_state") != "completed"
        or response.get("workspace_identity_sha256")
        != source_event.public_payload.get("workspace_identity_sha256")
        != consumer_event.public_payload.get("workspace_identity_sha256")
        or context.get("actual_session_identity_sha256")
        != source_event.public_payload.get("actual_session_identity_sha256")
        != consumer_event.public_payload.get("actual_session_identity_sha256")
    ):
        return {"state": "failed", "reason_code": "provider_context_scope_mismatch"}
    source_call_id = source_event.public_payload.get("provider_tool_call_id")
    sources = [
        item
        for item in attempted.get("source_tool_results", [])
        if isinstance(item, dict) and item.get("tool_result_call_id") == source_call_id
    ]
    if len(sources) != 1:
        return {"state": "failed", "reason_code": "provider_source_not_unique"}
    source_hash = sources[0].get("projection_sha256")
    if (
        source_event.public_payload.get("result_redaction_changed") is not False
        or source_event.public_payload.get("raw_result_projection_sha256") != source_hash
        or source_artifact.content_hash != source_hash
    ):
        return {"state": "failed", "reason_code": "source_artifact_projection_mismatch"}
    return {
        "state": "observed",
        "reason_code": "provider_request_context_recomputed",
        "request_id": response.get("request_id"),
        "batch_id": batch,
        "evidence_ref_ids": refs,
    }


def verify_derivation_candidate(
    *,
    trajectory: RawInteractionTrajectory,
    source_artifact: Any,
    source_event: Any,
    consumer_event: Any,
    candidate: dict[str, Any],
    records: dict[str, dict[str, Any]],
    bundle_status: dict[str, Any],
) -> dict[str, Any]:
    """Recompute exact equality; candidate fields are selectors, never assertions."""

    def result(state: str, reason: str, refs: list[str] | None = None) -> dict[str, Any]:
        return {"state": state, "reason_code": reason, "evidence_ref_ids": refs or []}

    if bundle_status.get("state") != "observed":
        return result(
            str(bundle_status.get("state", "unknown")), str(bundle_status.get("reason_code"))
        )
    if (
        trajectory.source_split != "synthetic"
        or trajectory.provenance.get("provider_evidence_policy_mode") != "experimental"
    ):
        return result("unknown", "experimental_derivation_policy_not_enabled")
    if candidate.get("rule_id") != EXACT_DERIVATION_RULE:
        return result("failed", "derivation_rule_unknown")
    refs = [str(value) for value in candidate.get("evidence_ref_ids", [])]
    if len(refs) < 2 or not set(refs) <= set(consumer_event.evidence_ref_ids):
        return result("failed", "derivation_evidence_ref_unbound")
    resolved = [_resolve_ref(ref, records) for ref in refs]
    if any(record is None for record in resolved):
        return result("failed", "derivation_evidence_ref_unresolvable")
    response = next(
        (r for r in resolved if r and r.get("record_type") == "provider_response"), None
    )
    context = next(
        (
            r
            for r in resolved
            if r
            and r.get("record_type") == "control_context"
            and r.get("context_state") == "closed"
        ),
        None,
    )
    if response is None or context is None:
        return result("failed", "derivation_required_records_missing")
    attempted = next(
        (
            r
            for r in records.values()
            if r.get("record_type") == "provider_request"
            and r.get("send_state") == "attempted"
            and r.get("request_id") == response.get("request_id")
        ),
        None,
    )
    if attempted is None:
        return result("failed", "provider_request_attempt_missing")
    if any(
        not isinstance(record.get("record_sha256"), str)
        or record["record_sha256"] != _record_hash(record)
        for record in (attempted, response, context)
    ):
        return result("failed", "provider_evidence_record_hash_mismatch")
    batch = response.get("batch_id")
    if not batch or any(r.get("batch_id") != batch for r in (attempted, context)):
        return result("failed", "provider_evidence_batch_mismatch")
    expected_batch = trajectory.provenance.get("provider_evidence_batch_id")
    if expected_batch and expected_batch != batch:
        return result("failed", "provider_evidence_trajectory_batch_mismatch")
    if response.get("send_state") != "response_received" or response.get("http_status") != 200:
        return result("failed", "provider_response_not_successful")
    binding = (
        response.get("control_context_id") == context.get("control_context_id")
        and attempted.get("control_context_id") == context.get("control_context_id")
        and context.get("close_state") == "completed"
        and response.get("workspace_identity_sha256")
        == source_event.public_payload.get("workspace_identity_sha256")
        == consumer_event.public_payload.get("workspace_identity_sha256")
        and context.get("actual_session_identity_sha256")
        == source_event.public_payload.get("actual_session_identity_sha256")
        == consumer_event.public_payload.get("actual_session_identity_sha256")
    )
    if not binding:
        return result("failed", "provider_context_scope_mismatch")
    source_call_id = source_event.public_payload.get("provider_tool_call_id")
    sources = [
        item
        for item in attempted.get("source_tool_results", [])
        if isinstance(item, dict) and item.get("tool_result_call_id") == source_call_id
    ]
    targets = [
        item
        for item in response.get("target_tool_arguments", [])
        if isinstance(item, dict)
        and item.get("target_tool_call_id")
        == consumer_event.public_payload.get("provider_tool_call_id")
        and item.get("target_tool_name") == consumer_event.public_payload.get("tool_name")
        and item.get("target_json_pointer") == candidate.get("target_json_pointer")
    ]
    if len(sources) != 1 or len(targets) != 1:
        return result("failed", "provider_source_or_target_not_unique")
    source_bytes, target_bytes = _decode_projection(sources[0]), _decode_projection(targets[0])
    if source_bytes is None or target_bytes is None:
        return result("unknown", "provider_projection_incomplete")
    if source_event.public_payload.get("result_redaction_changed") is not False:
        return result("unknown", "source_projection_redacted_or_unknown")
    if (
        source_event.public_payload.get("raw_result_projection_sha256")
        != hashlib.sha256(source_bytes).hexdigest()
    ):
        return result("failed", "source_artifact_projection_mismatch")
    if source_artifact.content_hash != hashlib.sha256(source_bytes).hexdigest():
        return result("failed", "source_artifact_content_mismatch")
    if consumer_event.public_payload.get("arguments_redaction_changed") is not False:
        return result("unknown", "target_arguments_redacted_or_unknown")
    target = targets[0]
    if consumer_event.public_payload.get("raw_arguments_value_sha256") != target.get(
        "arguments_value_sha256"
    ):
        return result("failed", "consumer_arguments_binding_mismatch")
    if source_bytes != target_bytes:
        return result("failed", "deterministic_projection_not_equal")
    return {
        "state": "observed",
        "reason_code": "deterministic_derivation_recomputed",
        "rule_id": EXACT_DERIVATION_RULE,
        "request_id": response.get("request_id"),
        "batch_id": batch,
        "source_projection_sha256": hashlib.sha256(source_bytes).hexdigest(),
        "target_projection_sha256": hashlib.sha256(target_bytes).hexdigest(),
        "evidence_ref_ids": refs,
    }
