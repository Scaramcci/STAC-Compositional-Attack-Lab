from __future__ import annotations

import base64
import hashlib
import json
from copy import deepcopy
from pathlib import Path
from types import SimpleNamespace

import pytest

from stac_attack_lab.environments.safeclaw.evidence_policy import (
    EXACT_DERIVATION_RULE,
    disabled_provider_evidence_policy,
    provider_evidence_policy_hash,
    validate_provider_evidence_policy,
)
from stac_attack_lab.execution.provider_evidence import (
    _record_hash,
    load_provider_evidence,
    verify_context_candidate,
    verify_derivation_candidate,
)
from stac_attack_lab.hashing import file_hash, stable_hash
from stac_attack_lab.interactions.models import RawInteractionTrajectory, SourceReference
from stac_attack_lab.interactions.provider_flow_adapter import verify_and_adapt_provider_claims


def _policy() -> dict[str, object]:
    return {
        "policy_id": "stac.synthetic-exact-test",
        "policy_version": "1.0",
        "mode": "experimental",
        "enabled": True,
        "rule_id": EXACT_DERIVATION_RULE,
        "target_selectors": [{"tool_name": "exec", "json_pointer": "/command"}],
        "projection_kind": "utf8-string-v1",
        "applicability": "synthetic_only",
        "max_projection_bytes": 16384,
    }


def _trajectory(policy: dict[str, object] | None = None) -> RawInteractionTrajectory:
    configured = policy or _policy()
    return RawInteractionTrajectory(
        trajectory_id="trajectory",
        source_adapter_id="fixture",
        source_adapter_version="1",
        source_environment_family="safeclaw",
        source_environment_version="1",
        source_task_id="task",
        source_split="synthetic",
        episode_id="episode",
        session_ids=["s3"],
        event_refs=[],
        checkpoint_refs=[],
        model_hashes={},
        config_hash="config",
        collection_seed=1,
        collection_status="complete",
        provenance={
            "provider_evidence_batch_id": "batch",
            "provider_evidence_policy_hash": provider_evidence_policy_hash(configured),
            "provider_evidence_policy_json": json.dumps(
                configured, sort_keys=True, separators=(",", ":")
            ),
        },
    )


def _projection(text: str) -> dict[str, object]:
    raw = text.encode()
    return {
        "projection_kind": "utf8-string-v1",
        "projection_complete": True,
        "projection_base64": base64.b64encode(raw).decode(),
        "projection_sha256": hashlib.sha256(raw).hexdigest(),
        "projection_byte_length": len(raw),
    }


def _record(sequence: int, record_id: str, **values: object) -> dict[str, object]:
    record = {
        "schema_version": "provider-request-boundary-v1",
        "evidence_sequence": sequence,
        "record_id": record_id,
        "recorded_at_unix": float(sequence),
        **values,
    }
    record["record_sha256"] = _record_hash(record)
    return record


def _fixture() -> tuple[
    RawInteractionTrajectory,
    SimpleNamespace,
    SimpleNamespace,
    SimpleNamespace,
    dict[str, object],
    dict[str, dict[str, object]],
]:
    policy = _policy()
    workspace, session = stable_hash("workspace"), stable_hash("s3")
    common = {
        "batch_id": "batch",
        "control_context_id": "context-1",
        "action_id": "action-1",
        "workspace_identity_sha256": workspace,
        "logical_session_id": "s3",
        "request_sha256": "f" * 64,
    }
    arguments = '{"command":"CONTROLLED_CANARY"}'
    arguments_raw = arguments.encode()
    arguments_value_hash = hashlib.sha256(b'{"command":"CONTROLLED_CANARY"}').hexdigest()
    source_projection = _projection("CONTROLLED_CANARY")
    target_projection = {
        "target_tool_call_id": "consumer-1",
        "target_tool_name": "exec",
        "target_json_pointer": "/command",
        "arguments_json_base64": base64.b64encode(arguments_raw).decode(),
        "arguments_json_sha256": hashlib.sha256(arguments_raw).hexdigest(),
        "arguments_json_byte_length": len(arguments_raw),
        "arguments_value_sha256": arguments_value_hash,
        **target_projection_values("CONTROLLED_CANARY"),
    }
    policy_claim = {
        "policy_id": policy["policy_id"],
        "policy_version": policy["policy_version"],
        "policy_hash": provider_evidence_policy_hash(policy),
        "policy_enabled": True,
        "rule_id": EXACT_DERIVATION_RULE,
    }
    records = [
        _record(1, "open", record_type="control_context", context_state="open", **common),
        _record(
            2,
            "prepared",
            record_type="provider_request",
            send_state="prepared",
            request_id="request-1",
            attempt_sequence=1,
            source_tool_results=[{"tool_result_call_id": "source-1", **source_projection}],
            **common,
            **policy_claim,
        ),
        _record(
            3,
            "attempted",
            record_type="provider_request",
            send_state="attempted",
            request_id="request-1",
            attempt_sequence=1,
            source_tool_results=[{"tool_result_call_id": "source-1", **source_projection}],
            **common,
            **policy_claim,
        ),
        _record(
            4,
            "response",
            record_type="provider_response",
            send_state="response_received",
            request_id="request-1",
            attempt_sequence=1,
            http_status=200,
            source_tool_results=[{"tool_result_call_id": "source-1", **source_projection}],
            target_tool_arguments=[target_projection],
            **common,
            **policy_claim,
        ),
        _record(
            5,
            "closed",
            record_type="control_context",
            context_state="closed",
            close_state="completed",
            actual_session_identity_sha256=session,
            **common,
        ),
    ]
    mapped = {str(item["record_id"]): item for item in records}
    source_event = SimpleNamespace(
        session_id="s3",
        public_payload={
            "provider_tool_call_id": "source-1",
            "workspace_identity_sha256": workspace,
            "actual_session_identity_sha256": session,
            "raw_result_projection_sha256": source_projection["projection_sha256"],
            "result_redaction_changed": False,
        },
    )
    consumer_event = SimpleNamespace(
        session_id="s3",
        public_payload={
            "provider_tool_call_id": "consumer-1",
            "tool_name": "exec",
            "workspace_identity_sha256": workspace,
            "actual_session_identity_sha256": session,
            "raw_arguments_value_sha256": arguments_value_hash,
            "arguments_redaction_changed": False,
        },
        evidence_ref_ids=[],
    )
    artifact = SimpleNamespace(content_hash=source_projection["projection_sha256"])
    candidate: dict[str, object] = {
        "source_artifact_id": "artifact",
        "source_tool_result_call_id": "source-1",
        "target_tool_call_id": "consumer-1",
        "target_tool_name": "exec",
        "target_json_pointer": "/command",
        "request_id": "request-1",
        "batch_id": "batch",
        "control_context_id": "context-1",
        "action_id": "action-1",
        "rule_id": EXACT_DERIVATION_RULE,
    }
    _refresh_refs(candidate, consumer_event, mapped)
    return _trajectory(policy), artifact, source_event, consumer_event, candidate, mapped


def target_projection_values(text: str) -> dict[str, object]:
    return _projection(text)


def _rehash(record: dict[str, object]) -> None:
    record["record_sha256"] = _record_hash(record)


def _refresh_refs(
    candidate: dict[str, object],
    consumer_event: SimpleNamespace,
    records: dict[str, dict[str, object]],
) -> None:
    refs = [
        f"provider-evidence:{name}:{records[name]['record_sha256']}"
        for name in ("response", "closed")
    ]
    candidate["evidence_ref_ids"] = refs
    consumer_event.evidence_ref_ids = ["bridge:request", *refs]


def _verify(
    fixture: tuple[
        RawInteractionTrajectory,
        SimpleNamespace,
        SimpleNamespace,
        SimpleNamespace,
        dict[str, object],
        dict[str, dict[str, object]],
    ],
    *,
    derivation: bool = False,
) -> dict[str, object]:
    trajectory, artifact, source, consumer, candidate, records = fixture
    verifier = verify_derivation_candidate if derivation else verify_context_candidate
    return verifier(
        trajectory=trajectory,
        source_artifact=artifact,
        source_event=source,
        consumer_event=consumer,
        candidate=candidate,
        records=records,
        bundle_status={"state": "observed", "reason_code": "test_bundle"},
    )


def test_context_and_derivation_recompute_valid_fixture() -> None:
    fixture = _fixture()
    assert _verify(fixture)["state"] == "observed"
    assert _verify(fixture, derivation=True)["state"] == "observed"


def test_context_recomputes_request_boundary_without_derivation_target() -> None:
    trajectory, artifact, source, consumer, candidate, records = _fixture()
    consumer.public_payload.pop("provider_tool_call_id")
    consumer.public_payload["provider_request_id"] = "request-1"
    candidate = {
        key: value
        for key, value in candidate.items()
        if key not in {"target_tool_call_id", "target_tool_name", "target_json_pointer", "rule_id"}
    }
    candidate["consumer_binding_kind"] = "provider_request"
    _refresh_refs(candidate, consumer, records)

    result = verify_context_candidate(
        trajectory=trajectory,
        source_artifact=artifact,
        source_event=source,
        consumer_event=consumer,
        candidate=candidate,
        records=records,
        bundle_status={"state": "observed", "reason_code": "test_bundle"},
    )

    assert result["state"] == "observed"
    assert result["reason_code"] == "provider_request_context_recomputed"

    consumer.public_payload["provider_request_id"] = "different-request"
    mismatch = verify_context_candidate(
        trajectory=trajectory,
        source_artifact=artifact,
        source_event=source,
        consumer_event=consumer,
        candidate=candidate,
        records=records,
        bundle_status={"state": "observed", "reason_code": "test_bundle"},
    )
    assert mismatch["state"] == "failed"
    assert mismatch["reason_code"] == "provider_request_event_identity_mismatch"


def test_verified_provider_results_adapt_to_port_scoped_v3_claims() -> None:
    trajectory, artifact, source, consumer, candidate, records = _fixture()
    claims, evidence = verify_and_adapt_provider_claims(
        trajectory=trajectory,
        source_artifact=artifact,
        source_event=source,
        consumer_event=consumer,
        candidate=candidate,
        records=records,
        bundle_status={"state": "observed", "reason_code": "test_bundle"},
        source_port_id="port:source",
        consumer_input_port_id="port:request-input",
        consumer_output_port_id="port:tool-argument",
    )
    assert [item.relation.value for item in claims] == ["available_input", "data_dep"]
    assert all(item.evidence_ids for item in claims)
    assert {item.method.value for item in evidence} == {
        "provider_request_context_recomputed_v1",
        "exact_utf8_projection_recomputed_v1",
    }


def test_disabled_provider_policy_adapts_strong_relation_as_unknown() -> None:
    trajectory, artifact, source, consumer, candidate, records = _fixture()
    policy = disabled_provider_evidence_policy()
    trajectory = trajectory.model_copy(
        update={
            "provenance": {
                **trajectory.provenance,
                "provider_evidence_policy_hash": provider_evidence_policy_hash(policy),
                "provider_evidence_policy_json": json.dumps(
                    policy, sort_keys=True, separators=(",", ":")
                ),
            }
        }
    )
    claims, evidence = verify_and_adapt_provider_claims(
        trajectory=trajectory,
        source_artifact=artifact,
        source_event=source,
        consumer_event=consumer,
        candidate=candidate,
        records=records,
        bundle_status={"state": "observed", "reason_code": "test_bundle"},
        source_port_id="port:source",
        consumer_input_port_id="port:request-input",
        consumer_output_port_id="port:tool-argument",
    )
    derivation = next(item for item in claims if item.relation.value == "data_dep")
    assert derivation.evidence_ids == []
    assert derivation.reason_code == "experimental_derivation_policy_disabled"
    assert not any(item.method.value == "exact_utf8_projection_recomputed_v1" for item in evidence)


@pytest.mark.parametrize(
    ("mutation", "reason"),
    [
        ("response_workspace", "provider_workspace_identity_sha256_mismatch"),
        ("closed_session", "provider_actual_session_identity_mismatch"),
        ("candidate_action", "provider_candidate_action_id_mismatch"),
        ("candidate_request", "provider_candidate_request_id_mismatch"),
        ("response_batch", "provider_batch_id_mismatch"),
        ("missing_session", "provider_context_scope_identity_missing"),
        ("duplicate_attempt", "provider_request_attempt_ambiguous"),
        ("lifecycle_order", "provider_evidence_lifecycle_order_invalid"),
    ],
)
def test_context_binding_matrix_fails_closed(mutation: str, reason: str) -> None:
    fixture = _fixture()
    _, _, source, consumer, candidate, records = fixture
    if mutation == "response_workspace":
        records["response"]["workspace_identity_sha256"] = stable_hash("wrong")
        _rehash(records["response"])
    elif mutation == "closed_session":
        records["closed"]["actual_session_identity_sha256"] = stable_hash("wrong")
        _rehash(records["closed"])
    elif mutation == "candidate_action":
        candidate["action_id"] = "wrong"
    elif mutation == "candidate_request":
        candidate["request_id"] = "wrong"
    elif mutation == "response_batch":
        records["response"]["batch_id"] = "wrong"
        _rehash(records["response"])
    elif mutation == "missing_session":
        consumer.public_payload["actual_session_identity_sha256"] = None
    elif mutation == "duplicate_attempt":
        duplicate = deepcopy(records["attempted"])
        duplicate["record_id"] = "attempted-duplicate"
        duplicate["evidence_sequence"] = 30
        _rehash(duplicate)
        records["attempted-duplicate"] = duplicate
    elif mutation == "lifecycle_order":
        records["response"]["evidence_sequence"] = 2
        _rehash(records["response"])
    _refresh_refs(candidate, consumer, records)
    result = _verify(fixture)
    assert result["state"] in {"failed", "unknown"}
    assert result["reason_code"] == reason


def test_derivation_rejects_rehashed_projection_contradiction() -> None:
    fixture = _fixture()
    _, _, _, consumer, candidate, records = fixture
    target = records["response"]["target_tool_arguments"][0]
    arguments = b'{"command":"DIFFERENT"}'
    target["arguments_json_base64"] = base64.b64encode(arguments).decode()
    target["arguments_json_sha256"] = hashlib.sha256(arguments).hexdigest()
    target["arguments_json_byte_length"] = len(arguments)
    target["arguments_value_sha256"] = hashlib.sha256(arguments).hexdigest()
    _rehash(records["response"])
    _refresh_refs(candidate, consumer, records)
    result = _verify(fixture, derivation=True)
    assert result["state"] == "failed"
    assert result["reason_code"] == "target_projection_not_selected_argument"


def test_derivation_policy_is_not_inferred_from_records() -> None:
    fixture = _fixture()
    trajectory, artifact, source, consumer, candidate, records = fixture
    missing = trajectory.model_copy(update={"provenance": {"provider_evidence_batch_id": "batch"}})
    result = verify_derivation_candidate(
        trajectory=missing,
        source_artifact=artifact,
        source_event=source,
        consumer_event=consumer,
        candidate=candidate,
        records=records,
        bundle_status={"state": "observed", "reason_code": "test_bundle"},
    )
    assert result["state"] == "unknown"
    assert result["reason_code"] == "provider_evidence_policy_missing"


@pytest.mark.parametrize(
    "mutation",
    [
        {"enabled": True},
        {**_policy(), "rule_id": "unknown"},
        {**_policy(), "target_selectors": [{"tool_name": "unknown", "json_pointer": "/x"}]},
        {
            **_policy(),
            "target_selectors": [
                {"tool_name": "exec", "json_pointer": "/command"},
                {"tool_name": "exec", "json_pointer": "/command"},
            ],
        },
    ],
)
def test_policy_validation_rejects_incomplete_or_ambiguous_contract(
    mutation: dict[str, object],
) -> None:
    with pytest.raises(ValueError):
        validate_provider_evidence_policy(mutation)


def test_disabled_policy_cannot_claim_experimental_derivation() -> None:
    policy = disabled_provider_evidence_policy()
    assert policy["enabled"] is False
    assert policy["mode"] == "disabled"


def test_bundle_seal_detects_missing_or_truncated_record_sequence(tmp_path: Path) -> None:
    fixture = _fixture()
    trajectory, _, _, _, _, records = fixture
    path = tmp_path / "evidence.jsonl"
    ordered = sorted(records.values(), key=lambda item: int(item["evidence_sequence"]))
    path.write_text("".join(json.dumps(item, sort_keys=True) + "\n" for item in ordered))
    reference = SourceReference(
        ref_id="evidence",
        kind="provider_boundary_evidence",
        relative_path=path.name,
        content_hash=file_hash(path),
    )
    unsealed = trajectory.model_copy(update={"evidence_refs": [reference]})
    _, status = load_provider_evidence(unsealed, tmp_path)
    assert status["state"] == "unknown"
    assert status["reason_code"] == "provider_evidence_bundle_seal_missing"
    sealed = trajectory.model_copy(
        update={
            "evidence_refs": [reference],
            "provenance": {
                **trajectory.provenance,
                "provider_evidence_record_count": str(len(ordered)),
                "provider_evidence_ordered_digest": stable_hash(
                    [item["record_sha256"] for item in ordered]
                ),
            },
        }
    )
    _, status = load_provider_evidence(sealed, tmp_path)
    assert status["state"] == "observed"
    path.write_text("".join(json.dumps(item, sort_keys=True) + "\n" for item in ordered[:-1]))
    truncated_reference = reference.model_copy(update={"content_hash": file_hash(path)})
    truncated = sealed.model_copy(update={"evidence_refs": [truncated_reference]})
    _, status = load_provider_evidence(truncated, tmp_path)
    assert status["state"] == "failed"
    assert status["reason_code"] == "provider_evidence_bundle_seal_mismatch"
