"""Independent verification of bounded provider request-boundary evidence."""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
import re
from pathlib import Path
from typing import Any

from stac_attack_lab.environments.safeclaw.evidence_policy import (
    EXACT_DERIVATION_RULE,
    UTF8_STRING_PROJECTION,
    provider_evidence_policy_hash,
    selector_allowed,
    validate_provider_evidence_policy,
)
from stac_attack_lab.hashing import file_hash, stable_hash
from stac_attack_lab.interactions.models import RawInteractionTrajectory

EVIDENCE_REF = re.compile(r"^provider-evidence:([^:]+):([0-9a-f]{64})$")
IDENTITY = re.compile(r"^[0-9a-f]{64}$")
MAX_JSON_DEPTH = 64


def _canonical_bytes(value: object) -> bytes:
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False
    ).encode("utf-8")


def _record_hash(record: dict[str, Any]) -> str:
    return hashlib.sha256(
        _canonical_bytes({key: value for key, value in record.items() if key != "record_sha256"})
    ).hexdigest()


def _ordered_records(records: dict[str, dict[str, Any]]) -> list[dict[str, Any]]:
    return sorted(records.values(), key=lambda item: int(item.get("evidence_sequence", -1)))


def verify_provider_record_sequence(records: list[dict[str, Any]]) -> bool:
    """Verify local record integrity/order; bundle completeness is checked separately."""
    return all(
        isinstance(item.get("record_id"), str)
        and item.get("record_sha256") == _record_hash(item)
        and item.get("evidence_sequence") == index
        for index, item in enumerate(records, 1)
    ) and len({item.get("record_id") for item in records}) == len(records)


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
        sequences: list[int] = []
        for line_number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
            if not line.strip():
                continue
            raw = json.loads(line)
            if not isinstance(raw, dict):
                raise ValueError(f"row_not_object:{line_number}")
            record_id, record_sha = raw.get("record_id"), raw.get("record_sha256")
            sequence = raw.get("evidence_sequence")
            if not isinstance(record_id, str) or not isinstance(record_sha, str):
                raise ValueError(f"record_identity_missing:{line_number}")
            if type(sequence) is not int or sequence < 1:
                raise ValueError(f"record_sequence_invalid:{line_number}")
            if record_sha != _record_hash(raw):
                raise ValueError(f"record_hash_mismatch:{line_number}")
            if record_id in records:
                raise ValueError(f"duplicate_record_id:{record_id}")
            records[record_id] = raw
            sequences.append(sequence)
        if sequences != list(range(1, len(sequences) + 1)):
            raise ValueError("record_sequence_not_contiguous")
        expected_count = trajectory.provenance.get("provider_evidence_record_count")
        expected_digest = trajectory.provenance.get("provider_evidence_ordered_digest")
        digest = stable_hash([item["record_sha256"] for item in _ordered_records(records)])
        if expected_count is None or expected_digest is None:
            return records, {
                "state": "unknown",
                "reason_code": "provider_evidence_bundle_seal_missing",
                "content_hash": observed_hash,
                "path": str(path),
            }
        if str(len(records)) != expected_count or digest != expected_digest:
            return {}, {"state": "failed", "reason_code": "provider_evidence_bundle_seal_mismatch"}
    except (OSError, UnicodeError, json.JSONDecodeError, ValueError) as exc:
        return {}, {
            "state": "failed",
            "reason_code": "provider_evidence_file_corrupt",
            "detail": str(exc)[:300],
        }
    return records, {
        "state": "observed",
        "reason_code": "provider_evidence_bundle_verified",
        "content_hash": observed_hash,
        "ordered_digest": digest,
        "record_count": len(records),
        "path": str(path),
    }


def _decode_projection(value: dict[str, Any]) -> tuple[bytes | None, str | None]:
    if value.get("projection_kind") != UTF8_STRING_PROJECTION:
        return None, "provider_projection_kind_mismatch"
    if value.get("projection_complete") is not True:
        return None, "provider_projection_incomplete"
    encoded = value.get("projection_base64")
    if not isinstance(encoded, str):
        return None, "provider_projection_bytes_missing"
    try:
        decoded = base64.b64decode(encoded, validate=True)
        decoded.decode("utf-8", errors="strict")
    except (ValueError, UnicodeError, binascii.Error):
        return None, "provider_projection_encoding_invalid"
    if hashlib.sha256(decoded).hexdigest() != value.get("projection_sha256"):
        return None, "provider_projection_hash_mismatch"
    if type(value.get("projection_byte_length")) is not int or len(decoded) != value.get(
        "projection_byte_length"
    ):
        return None, "provider_projection_length_mismatch"
    return decoded, None


def _resolve_ref(ref: str, records: dict[str, dict[str, Any]]) -> dict[str, Any] | None:
    match = EVIDENCE_REF.fullmatch(ref)
    if not match:
        return None
    record = records.get(match.group(1))
    if record is None or record.get("record_sha256") != match.group(2):
        return None
    return record


def _one(
    values: list[dict[str, Any]], missing: str, ambiguous: str
) -> tuple[dict[str, Any] | None, str | None]:
    if not values:
        return None, missing
    if len(values) != 1:
        return None, ambiguous
    return values[0], None


def _nonempty(value: object) -> bool:
    return isinstance(value, str) and bool(value.strip())


def _identity(value: object) -> bool:
    return isinstance(value, str) and IDENTITY.fullmatch(value) is not None


def _binding_failure(state: str, reason: str) -> dict[str, Any]:
    return {"state": state, "reason_code": reason, "evidence_ref_ids": []}


def _bind_candidate(
    *,
    trajectory: RawInteractionTrajectory,
    source_event: Any,
    consumer_event: Any,
    candidate: dict[str, Any],
    records: dict[str, dict[str, Any]],
    require_target_tool_call: bool = True,
) -> tuple[dict[str, Any] | None, dict[str, Any] | None]:
    """Resolve one unambiguous open/prepared/attempted/response/close lifecycle."""
    raw_refs = candidate.get("evidence_ref_ids")
    if not isinstance(raw_refs, list) or len(raw_refs) != 2 or len(set(raw_refs)) != 2:
        return None, _binding_failure("failed", "provider_evidence_ref_set_invalid")
    refs = [value for value in raw_refs if isinstance(value, str)]
    if len(refs) != 2 or not set(refs) <= set(consumer_event.evidence_ref_ids):
        return None, _binding_failure("failed", "provider_evidence_ref_unbound")
    resolved = [_resolve_ref(ref, records) for ref in refs]
    if any(item is None for item in resolved):
        return None, _binding_failure("failed", "provider_evidence_ref_unresolvable")
    resolved_records = [item for item in resolved if item is not None]
    response, error = _one(
        [item for item in resolved_records if item.get("record_type") == "provider_response"],
        "provider_response_ref_missing",
        "provider_response_ref_ambiguous",
    )
    if error:
        return None, _binding_failure("failed", error)
    closed, error = _one(
        [
            item
            for item in resolved_records
            if item.get("record_type") == "control_context"
            and item.get("context_state") == "closed"
        ],
        "provider_context_close_ref_missing",
        "provider_context_close_ref_ambiguous",
    )
    if error:
        return None, _binding_failure("failed", error)
    assert response is not None and closed is not None
    request_id, context_id = response.get("request_id"), response.get("control_context_id")
    if not _nonempty(request_id) or not _nonempty(context_id):
        return None, _binding_failure("unknown", "provider_binding_identity_missing")

    def select(record_type: str, state_key: str, state_value: str) -> list[dict[str, Any]]:
        return [
            item
            for item in records.values()
            if item.get("record_type") == record_type
            and item.get(state_key) == state_value
            and item.get("request_id") == request_id
        ]

    prepared, error = _one(
        select("provider_request", "send_state", "prepared"),
        "provider_request_prepared_missing",
        "provider_request_prepared_ambiguous",
    )
    if error:
        return None, _binding_failure("failed", error)
    attempted, error = _one(
        select("provider_request", "send_state", "attempted"),
        "provider_request_attempt_missing",
        "provider_request_attempt_ambiguous",
    )
    if error:
        return None, _binding_failure("failed", error)
    opened, error = _one(
        [
            item
            for item in records.values()
            if item.get("record_type") == "control_context"
            and item.get("context_state") == "open"
            and item.get("control_context_id") == context_id
        ],
        "provider_context_open_missing",
        "provider_context_open_ambiguous",
    )
    if error:
        return None, _binding_failure("failed", error)
    closes = [
        item
        for item in records.values()
        if item.get("record_type") == "control_context"
        and item.get("context_state") == "closed"
        and item.get("control_context_id") == context_id
    ]
    if len(closes) != 1 or closes[0].get("record_id") != closed.get("record_id"):
        return None, _binding_failure("failed", "provider_context_close_ambiguous")
    responses = [
        item
        for item in records.values()
        if item.get("record_type") == "provider_response" and item.get("request_id") == request_id
    ]
    if len(responses) != 1 or responses[0].get("record_id") != response.get("record_id"):
        return None, _binding_failure("failed", "provider_response_ambiguous")
    if select("provider_request", "send_state", "transport_error"):
        return None, _binding_failure("failed", "provider_request_transport_error_conflict")
    assert prepared is not None and attempted is not None and opened is not None
    bound = [opened, prepared, attempted, response, closed]
    if any(item.get("record_sha256") != _record_hash(item) for item in bound):
        return None, _binding_failure("failed", "provider_evidence_record_hash_mismatch")
    sequence = [item.get("evidence_sequence") for item in bound]
    if any(type(item) is not int for item in sequence):
        return None, _binding_failure("failed", "provider_evidence_lifecycle_order_invalid")
    sequence_ints = [item for item in sequence if isinstance(item, int)]
    if sequence_ints != sorted(sequence_ints):
        return None, _binding_failure("failed", "provider_evidence_lifecycle_order_invalid")
    if len(set(sequence_ints)) != len(sequence_ints):
        return None, _binding_failure("failed", "provider_evidence_lifecycle_order_ambiguous")
    fields = (
        "batch_id",
        "control_context_id",
        "action_id",
        "workspace_identity_sha256",
        "logical_session_id",
    )
    for field in fields:
        values = [item.get(field) for item in bound]
        if not all(_nonempty(value) for value in values):
            return None, _binding_failure("unknown", f"provider_{field}_missing")
        if len(set(values)) != 1:
            return None, _binding_failure("failed", f"provider_{field}_mismatch")
    attempts = [
        prepared.get("attempt_sequence"),
        attempted.get("attempt_sequence"),
        response.get("attempt_sequence"),
    ]
    if any(type(value) is not int or value < 1 for value in attempts):
        return None, _binding_failure("unknown", "provider_attempt_identity_missing")
    if len(set(attempts)) != 1:
        return None, _binding_failure("failed", "provider_attempt_identity_mismatch")
    request_hashes = [
        prepared.get("request_sha256"),
        attempted.get("request_sha256"),
        response.get("request_sha256"),
    ]
    if not all(_identity(value) for value in request_hashes):
        return None, _binding_failure("unknown", "provider_request_hash_missing")
    if len(set(request_hashes)) != 1:
        return None, _binding_failure("failed", "provider_request_hash_mismatch")
    source_sets = [
        prepared.get("source_tool_results"),
        attempted.get("source_tool_results"),
        response.get("source_tool_results"),
    ]
    if any(not isinstance(value, list) for value in source_sets):
        return None, _binding_failure("unknown", "provider_source_projection_set_missing")
    if len({stable_hash(value) for value in source_sets}) != 1:
        return None, _binding_failure("failed", "provider_source_projection_set_mismatch")
    if closed.get("close_state") != "completed":
        return None, _binding_failure("failed", "provider_context_not_completed")
    if response.get("send_state") != "response_received":
        return None, _binding_failure("failed", "provider_response_state_invalid")
    expected_batch = trajectory.provenance.get("provider_evidence_batch_id")
    if not _nonempty(expected_batch):
        return None, _binding_failure("unknown", "provider_trajectory_batch_missing")
    if response.get("batch_id") != expected_batch:
        return None, _binding_failure("failed", "provider_evidence_trajectory_batch_mismatch")
    candidate_bindings: dict[str, object] = {
        "request_id": request_id,
        "batch_id": response.get("batch_id"),
        "control_context_id": context_id,
        "action_id": response.get("action_id"),
        "source_tool_result_call_id": source_event.public_payload.get("provider_tool_call_id"),
    }
    if require_target_tool_call:
        candidate_bindings["target_tool_call_id"] = consumer_event.public_payload.get(
            "provider_tool_call_id"
        )
    elif consumer_event.public_payload.get("provider_request_id") != request_id:
        return None, _binding_failure("failed", "provider_request_event_identity_mismatch")
    for field, expected in candidate_bindings.items():
        if not _nonempty(expected):
            return None, _binding_failure("unknown", f"provider_{field}_missing")
        if candidate.get(field) != expected:
            return None, _binding_failure("failed", f"provider_candidate_{field}_mismatch")
    workspace_values = [
        response.get("workspace_identity_sha256"),
        source_event.public_payload.get("workspace_identity_sha256"),
        consumer_event.public_payload.get("workspace_identity_sha256"),
    ]
    session_values = [
        closed.get("actual_session_identity_sha256"),
        source_event.public_payload.get("actual_session_identity_sha256"),
        consumer_event.public_payload.get("actual_session_identity_sha256"),
    ]
    if not all(_identity(value) for value in workspace_values + session_values):
        return None, _binding_failure("unknown", "provider_context_scope_identity_missing")
    if len(set(workspace_values)) != 1:
        return None, _binding_failure("failed", "provider_workspace_identity_mismatch")
    if len(set(session_values)) != 1:
        return None, _binding_failure("failed", "provider_actual_session_identity_mismatch")
    if source_event.session_id != consumer_event.session_id:
        return None, _binding_failure("failed", "provider_logical_session_event_mismatch")
    if opened.get("logical_session_id") != source_event.session_id:
        return None, _binding_failure("failed", "provider_logical_session_identity_mismatch")
    return {
        "opened": opened,
        "prepared": prepared,
        "attempted": attempted,
        "response": response,
        "closed": closed,
        "refs": refs,
    }, None


def _source_projection(
    binding: dict[str, Any], source_event: Any
) -> tuple[dict[str, Any] | None, str | None]:
    call_id = source_event.public_payload.get("provider_tool_call_id")
    sources = [
        item
        for item in binding["attempted"].get("source_tool_results", [])
        if isinstance(item, dict) and item.get("tool_result_call_id") == call_id
    ]
    return _one(sources, "provider_source_missing", "provider_source_ambiguous")


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
    if bundle_status.get("state") != "observed":
        return _binding_failure(
            str(bundle_status.get("state", "unknown")), str(bundle_status.get("reason_code"))
        )
    request_boundary_consumer = candidate.get("consumer_binding_kind") == "provider_request"
    binding, failure = _bind_candidate(
        trajectory=trajectory,
        source_event=source_event,
        consumer_event=consumer_event,
        candidate=candidate,
        records=records,
        require_target_tool_call=not request_boundary_consumer,
    )
    if failure:
        return failure
    assert binding is not None
    source, error = _source_projection(binding, source_event)
    if error:
        return _binding_failure("failed", error)
    assert source is not None
    source_hash = source.get("projection_sha256")
    if source_event.public_payload.get("result_redaction_changed") is not False:
        return _binding_failure("unknown", "source_projection_redacted_or_unknown")
    if (
        source_event.public_payload.get("raw_result_projection_sha256") != source_hash
        or source_artifact.content_hash != source_hash
    ):
        return _binding_failure("failed", "source_artifact_projection_mismatch")
    return {
        "state": "observed",
        "reason_code": "provider_request_context_recomputed",
        "request_id": binding["response"]["request_id"],
        "batch_id": binding["response"]["batch_id"],
        "evidence_ref_ids": binding["refs"],
    }


def _reject_constant(value: str) -> object:
    raise ValueError(f"non_standard_json_constant:{value}")


def _reject_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate_json_key")
        result[key] = value
    return result


def _json_depth(value: object) -> int:
    if isinstance(value, dict):
        return 1 + max((_json_depth(item) for item in value.values()), default=0)
    if isinstance(value, list):
        return 1 + max((_json_depth(item) for item in value), default=0)
    return 1


def _json_pointer(value: object, pointer: str) -> object:
    if pointer == "" or not pointer.startswith("/"):
        raise ValueError("target_json_pointer_invalid")
    current = value
    for raw in pointer[1:].split("/"):
        index = 0
        while index < len(raw):
            if raw[index] == "~":
                if index + 1 >= len(raw) or raw[index + 1] not in {"0", "1"}:
                    raise ValueError("target_json_pointer_escape_invalid")
                index += 2
            else:
                index += 1
        token = raw.replace("~1", "/").replace("~0", "~")
        if isinstance(current, dict):
            if token not in current:
                raise KeyError("target_json_pointer_missing")
            current = current[token]
        elif isinstance(current, list):
            if token == "-" or not token.isdigit() or (len(token) > 1 and token.startswith("0")):
                raise ValueError("target_json_pointer_array_index_invalid")
            position = int(token)
            if position >= len(current):
                raise KeyError("target_json_pointer_missing")
            current = current[position]
        else:
            raise KeyError("target_json_pointer_missing")
    return current


def _policy_from_trajectory(
    trajectory: RawInteractionTrajectory,
) -> tuple[dict[str, Any] | None, str | None]:
    raw = trajectory.provenance.get("provider_evidence_policy_json")
    if not raw:
        return None, "provider_evidence_policy_missing"
    try:
        policy = validate_provider_evidence_policy(json.loads(raw))
    except (ValueError, json.JSONDecodeError):
        return None, "provider_evidence_policy_invalid"
    expected = trajectory.provenance.get("provider_evidence_policy_hash")
    if not expected:
        return None, "provider_evidence_policy_hash_missing"
    if provider_evidence_policy_hash(policy) != expected:
        return None, "provider_evidence_policy_hash_mismatch"
    return policy, None


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
    def result(state: str, reason: str, refs: list[str] | None = None) -> dict[str, Any]:
        return {"state": state, "reason_code": reason, "evidence_ref_ids": refs or []}

    if bundle_status.get("state") != "observed":
        return result(
            str(bundle_status.get("state", "unknown")), str(bundle_status.get("reason_code"))
        )
    policy, policy_error = _policy_from_trajectory(trajectory)
    if policy_error:
        return result("unknown", policy_error)
    assert policy is not None
    if not policy["enabled"]:
        return result("unknown", "experimental_derivation_policy_disabled")
    if trajectory.source_split != "synthetic" or policy["applicability"] != "synthetic_only":
        return result("failed", "experimental_derivation_scope_mismatch")
    if policy["mode"] != "experimental" or policy["rule_id"] != EXACT_DERIVATION_RULE:
        return result("failed", "derivation_policy_rule_mismatch")
    if candidate.get("rule_id") != policy["rule_id"]:
        return result("failed", "derivation_candidate_rule_mismatch")
    tool_name, pointer = candidate.get("target_tool_name"), candidate.get("target_json_pointer")
    if not selector_allowed(policy, tool_name, pointer):
        return result("failed", "derivation_candidate_selector_not_allowed")
    binding, failure = _bind_candidate(
        trajectory=trajectory,
        source_event=source_event,
        consumer_event=consumer_event,
        candidate=candidate,
        records=records,
    )
    if failure:
        return failure
    assert binding is not None
    response = binding["response"]
    if response.get("http_status") != 200:
        return result("failed", "provider_response_not_successful", binding["refs"])
    expected_policy_hash = provider_evidence_policy_hash(policy)
    for record in (binding["prepared"], binding["attempted"], response):
        if record.get("policy_hash") != expected_policy_hash:
            return result("failed", "provider_evidence_policy_binding_mismatch", binding["refs"])
        if record.get("policy_enabled") is not True or record.get("rule_id") != policy["rule_id"]:
            return result("failed", "provider_evidence_policy_claim_mismatch", binding["refs"])
    source, error = _source_projection(binding, source_event)
    if error:
        return result("failed", error, binding["refs"])
    targets = [
        item
        for item in response.get("target_tool_arguments", [])
        if isinstance(item, dict)
        and item.get("target_tool_call_id")
        == consumer_event.public_payload.get("provider_tool_call_id")
        and item.get("target_tool_name") == tool_name
        and item.get("target_json_pointer") == pointer
    ]
    target, error = _one(targets, "provider_target_missing", "provider_target_ambiguous")
    if error:
        return result("failed", error, binding["refs"])
    assert source is not None and target is not None
    source_bytes, projection_error = _decode_projection(source)
    if projection_error:
        state = "unknown" if projection_error.endswith(("missing", "incomplete")) else "failed"
        return result(state, projection_error, binding["refs"])
    if source_event.public_payload.get("result_redaction_changed") is not False:
        return result("unknown", "source_projection_redacted_or_unknown", binding["refs"])
    assert source_bytes is not None
    if len(source_bytes) > policy["max_projection_bytes"]:
        return result("unknown", "source_projection_size_limit_exceeded", binding["refs"])
    source_hash = hashlib.sha256(source_bytes).hexdigest()
    if (
        source_event.public_payload.get("raw_result_projection_sha256") != source_hash
        or source_artifact.content_hash != source_hash
    ):
        return result("failed", "source_artifact_projection_mismatch", binding["refs"])
    encoded_arguments = target.get("arguments_json_base64")
    if not isinstance(encoded_arguments, str):
        return result("unknown", "target_arguments_bytes_missing", binding["refs"])
    try:
        arguments_bytes = base64.b64decode(encoded_arguments, validate=True)
        arguments_text = arguments_bytes.decode("utf-8", errors="strict")
    except (ValueError, UnicodeError, binascii.Error):
        return result("failed", "target_arguments_encoding_invalid", binding["refs"])
    if len(arguments_bytes) > policy["max_projection_bytes"]:
        return result("unknown", "target_arguments_size_limit_exceeded", binding["refs"])
    if len(arguments_bytes) != target.get("arguments_json_byte_length"):
        return result("failed", "target_arguments_length_mismatch", binding["refs"])
    if hashlib.sha256(arguments_bytes).hexdigest() != target.get("arguments_json_sha256"):
        return result("failed", "target_arguments_hash_mismatch", binding["refs"])
    try:
        arguments = json.loads(
            arguments_text, object_pairs_hook=_reject_duplicates, parse_constant=_reject_constant
        )
        if _json_depth(arguments) > MAX_JSON_DEPTH:
            raise ValueError("target_arguments_depth_exceeded")
        canonical_hash = hashlib.sha256(_canonical_bytes(arguments)).hexdigest()
        selected = _json_pointer(arguments, str(pointer))
    except (json.JSONDecodeError, KeyError, TypeError, ValueError) as exc:
        return result("failed", str(exc) or "target_arguments_json_invalid", binding["refs"])
    if canonical_hash != target.get("arguments_value_sha256"):
        return result("failed", "target_arguments_value_hash_mismatch", binding["refs"])
    if not isinstance(selected, str):
        return result("failed", "target_argument_not_string", binding["refs"])
    selected_bytes = selected.encode("utf-8")
    target_bytes, projection_error = _decode_projection(target)
    if projection_error:
        state = "unknown" if projection_error.endswith(("missing", "incomplete")) else "failed"
        return result(state, projection_error, binding["refs"])
    if selected_bytes != target_bytes:
        return result("failed", "target_projection_not_selected_argument", binding["refs"])
    if target_bytes is not None and len(target_bytes) > policy["max_projection_bytes"]:
        return result("unknown", "target_projection_size_limit_exceeded", binding["refs"])
    if consumer_event.public_payload.get("arguments_redaction_changed") is not False:
        return result("unknown", "target_arguments_redacted_or_unknown", binding["refs"])
    if consumer_event.public_payload.get("raw_arguments_value_sha256") != canonical_hash:
        return result("failed", "consumer_arguments_binding_mismatch", binding["refs"])
    if source_bytes != target_bytes:
        return result("failed", "deterministic_projection_not_equal", binding["refs"])
    assert target_bytes is not None
    return {
        "state": "observed",
        "reason_code": "deterministic_derivation_recomputed",
        "rule_id": EXACT_DERIVATION_RULE,
        "request_id": response["request_id"],
        "batch_id": response["batch_id"],
        "source_projection_sha256": source_hash,
        "target_projection_sha256": hashlib.sha256(target_bytes).hexdigest(),
        "evidence_ref_ids": binding["refs"],
    }
