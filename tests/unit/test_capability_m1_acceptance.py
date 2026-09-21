from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

from stac_attack_lab.capability.compatibility import (
    _verified_followup_context,
    assess_compatibility_stage,
)
from stac_attack_lab.capability.compiler import compile_cases
from stac_attack_lab.capability.models import RuntimeTask
from stac_attack_lab.capability.runner import _write_result, run_fake_pipeline
from stac_attack_lab.environments.safeclaw.capability_runtime import map_safeclaw_capability_events
from stac_attack_lab.hashing import stable_hash

ROOT = Path(__file__).resolve().parents[2]
CONFIG = ROOT / "configs/capability/f1_status_acceptance.json"


def _events(*kinds: tuple[str, str, str, str | None]) -> list[dict[str, object]]:
    result = []
    for index, (kind, status, text, ref) in enumerate(kinds):
        result.append(
            {
                "event_id": f"e{index}",
                "sequence_no": index + 1,
                "event_type": kind,
                "status": status,
                "tool_name": text if kind == "tool_request" else None,
                "resource_id": text if kind == "state_read" else None,
                "evidence": {"request_event_id": ref, "text": text if kind == "response" else None},
            }
        )
    return result


@pytest.mark.parametrize("response", ["", "   "])
def test_p0_rejects_empty_response(response: str) -> None:
    verdict, reasons = assess_compatibility_stage(
        "P0",
        _events(("response", "observed", response, None)),
        attempts=1,
        execution_status="completed",
        cleanup_status="completed",
    )
    assert verdict != "passed"
    assert "response_empty" in reasons


def test_p1_orphan_read_does_not_pass() -> None:
    verdict, _ = assess_compatibility_stage(
        "P1",
        _events(("state_read", "observed", "workspace/trusted/acceptance-ledger.json", None)),
        attempts=2,
        execution_status="completed",
        cleanup_status="completed",
    )
    assert verdict != "passed"


def test_p1_complete_explicitly_instrumented_round_trip() -> None:
    events = [
        {
            "event_id": "req",
            "sequence_no": 1,
            "event_type": "tool_request",
            "status": "attempted",
            "tool_name": "read",
            "arguments": {"path": "trusted/acceptance-ledger.json"},
            "invocation_id": "call-1",
        },
        {
            "event_id": "result",
            "sequence_no": 2,
            "event_type": "tool_result",
            "status": "observed",
            "evidence": {"request_event_id": "req"},
        },
        {
            "event_id": "read",
            "sequence_no": 3,
            "event_type": "state_read",
            "status": "observed",
            "resource_id": "workspace/trusted/acceptance-ledger.json",
            "evidence": {"request_event_id": "req", "read_complete": True},
        },
        {
            "event_id": "reply",
            "sequence_no": 4,
            "event_type": "response",
            "status": "observed",
            "evidence": {"text": "proof exists", "provider_finish_reason": "stop"},
        },
    ]
    verdict, reasons = assess_compatibility_stage(
        "P1",
        events,
        attempts=2,
        execution_status="completed",
        cleanup_status="completed",
        context_matches={"call-1"},
    )
    assert (verdict, reasons) == ("passed", ["p1_compatibility_verified"])
    assert (
        assess_compatibility_stage(
            "P1", events, attempts=2, execution_status="completed", cleanup_status="completed"
        )[0]
        != "passed"
    )


def test_p1_boundary_requires_unique_matching_response_and_session() -> None:
    identity = {
        "batch_id": "batch-12345678",
        "control_context_id": "context-1",
        "action_id": "action-1",
        "workspace_identity_sha256": "a" * 64,
        "logical_session_id": "s1",
    }
    request = {
        **identity,
        "record_type": "provider_request",
        "send_state": "attempted",
        "request_id": "request-1",
        "source_tool_results": [
            {
                "tool_result_call_id": "call-1",
                "projection_complete": True,
                "projection_sha256": "b" * 64,
            }
        ],
    }
    response = {
        **identity,
        "record_type": "provider_response",
        "send_state": "response_received",
        "request_id": "request-1",
    }
    closed = {
        **identity,
        "record_type": "control_context",
        "context_state": "closed",
        "close_state": "completed",
        "actual_session_identity_sha256": "c" * 64,
    }

    def rehash(items: list[dict[str, object]]) -> list[dict[str, object]]:
        for index, item in enumerate(items, 1):
            item.update(record_id=f"record-{index}", evidence_sequence=index)
            item["record_sha256"] = hashlib.sha256(
                json.dumps(item, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()
            ).hexdigest()
        return items

    records = rehash([request, response, closed])
    ledger = [
        {
            "request_id": "request-1",
            "status": 200,
            "response_evidence_ref": (
                f"provider-evidence:{response['record_id']}:{response['record_sha256']}"
            ),
        }
    ]
    review = {
        "provider_evidence_record_count": 3,
        "provider_evidence_ordered_digest": stable_hash(
            [item["record_sha256"] for item in records]
        ),
    }
    events = [
        {
            "event_type": "tool_result",
            "invocation_id": "call-1",
            "status": "observed",
            "actual_session_key": "c" * 64,
            "evidence": {"raw_result_projection_sha256": "b" * 64},
        }
    ]
    assert _verified_followup_context(events, ledger, records, review, "batch-12345678") == {
        "call-1"
    }
    duplicate = rehash([dict(item) for item in [request, response, closed, response]])
    duplicate_review = {
        "provider_evidence_record_count": 4,
        "provider_evidence_ordered_digest": stable_hash(
            [item["record_sha256"] for item in duplicate]
        ),
    }
    assert (
        _verified_followup_context(events, ledger, duplicate, duplicate_review, "batch-12345678")
        == set()
    )
    altered = rehash(
        [dict(request), {**response, "workspace_identity_sha256": "d" * 64}, dict(closed)]
    )
    altered_ledger = [
        {
            **ledger[0],
            "response_evidence_ref": (
                f"provider-evidence:{altered[1]['record_id']}:{altered[1]['record_sha256']}"
            ),
        }
    ]
    altered_review = {
        "provider_evidence_record_count": 3,
        "provider_evidence_ordered_digest": stable_hash(
            [item["record_sha256"] for item in altered]
        ),
    }
    assert (
        _verified_followup_context(
            events, altered_ledger, altered, altered_review, "batch-12345678"
        )
        == set()
    )


def test_p0_tool_call_and_failed_response_are_not_accepted() -> None:
    events = _events(
        ("response", "observed", "ok", None), ("tool_request", "attempted", "read", None)
    )
    verdict, reasons = assess_compatibility_stage(
        "P0", events, attempts=1, execution_status="completed", cleanup_status="completed"
    )
    assert verdict == "failed" and "p0_unexpected_tool_call" in reasons
    verdict, reasons = assess_compatibility_stage(
        "P0",
        _events(("response", "observed", "ok", None)),
        attempts=1,
        execution_status="completed",
        cleanup_status="completed",
        ledger=[{"accepted": True, "status": 502, "error_category": "provider_5xx"}],
    )
    assert verdict != "passed" and "provider_response_ledger_incomplete" in reasons


def test_p0_truncated_finish_cannot_pass_with_nonempty_text() -> None:
    response = _events(("response", "observed", "partial answer", None))
    response[0]["evidence"]["provider_finish_reason"] = "length"  # type: ignore[index]
    verdict, reasons = assess_compatibility_stage(
        "P0", response, attempts=1, execution_status="completed", cleanup_status="completed"
    )
    assert verdict != "passed" and "final_response_not_normally_finished" in reasons


def test_p2_business_utility_does_not_substitute_for_commit_or_cleanup() -> None:
    state = {"projects": {"project-a": {"status": "pending"}}, "trusted_ledger": {}}
    final = {"projects": {"project-a": {"status": "accepted"}}, "trusted_ledger": {}}
    verdict, reasons = assess_compatibility_stage(
        "P2",
        _events(("response", "observed", "done", None)),
        attempts=2,
        execution_status="completed",
        cleanup_status="failed",
        initial=state,
        final=final,
        utility="true",
    )
    assert verdict != "passed"
    assert "p2_write_commit_missing" in reasons and "cleanup_not_verified" in reasons


def test_p2_orphan_commit_cannot_certify_business_write() -> None:
    initial = {"projects": {"project-b": {"status": "pending"}}, "trusted_ledger": {}}
    final = {"projects": {"project-b": {"status": "accepted"}}, "trusted_ledger": {}}
    events = _events(("response", "observed", "done", None))
    events.append(
        {
            "event_id": "write",
            "sequence_no": 4,
            "event_type": "state_write",
            "status": "committed",
            "resource_id": "workspace/reports/status.json",
            "resource_version_after": "v2",
            "evidence": {"receipt": "some-ref", "request_event_id": "missing"},
        }
    )
    verdict, reasons = assess_compatibility_stage(
        "P2",
        events,
        attempts=2,
        execution_status="completed",
        cleanup_status="completed",
        initial=initial,
        final=final,
        utility="true",
    )
    assert verdict != "passed" and "p2_write_commit_missing" in reasons


def test_p2_task_contract_ledger_is_not_runtime_immutability_evidence() -> None:
    initial = {"projects": {"project-b": {"status": "pending"}}, "trusted_ledger": {}}
    final = {"projects": {"project-b": {"status": "accepted"}}, "trusted_ledger": {}}
    events = [
        {
            "event_id": "request",
            "sequence_no": 1,
            "event_type": "tool_request",
            "tool_name": "write",
            "arguments": {"path": "reports/status.json"},
            "actual_session_key": "s1",
        },
        {
            "event_id": "result",
            "sequence_no": 2,
            "event_type": "tool_result",
            "status": "observed",
            "actual_session_key": "s1",
            "evidence": {"request_event_id": "request"},
        },
        {
            "event_id": "write",
            "sequence_no": 3,
            "event_type": "state_write",
            "status": "committed",
            "resource_id": "workspace/reports/status.json",
            "resource_version_after": "v2",
            "actual_session_key": "s1",
            "evidence": {"request_event_id": "request", "receipt": "receipt"},
        },
        {
            "event_id": "response",
            "sequence_no": 4,
            "event_type": "response",
            "status": "observed",
            "evidence": {"text": "done"},
        },
    ]
    verdict, reasons = assess_compatibility_stage(
        "P2",
        events,
        attempts=2,
        execution_status="completed",
        cleanup_status="completed",
        initial=initial,
        final=final,
        utility="true",
    )
    assert verdict == "unknown" and "p2_trusted_ledger_unobserved" in reasons


def test_runner_preserves_runtime_failure_after_business_success(tmp_path: Path) -> None:
    compiled = compile_cases(CONFIG, tmp_path / "compiled")
    episodes = run_fake_pipeline(compiled, tmp_path / "episodes")
    episode = episodes / "cap-f1-001-benign"
    review = episode / "runtime_review.json"
    payload = json.loads(review.read_text(encoding="utf-8"))
    payload.update(
        status="failed", failure_category="finish_failed", cleanup_error="cleanup_failed"
    )
    review.write_text(json.dumps(payload), encoding="utf-8")
    result = _write_result(
        episode,
        RuntimeTask.model_validate_json(
            (episode / "runtime_task.json").read_text(encoding="utf-8")
        ),
    )
    assert result.benign_utility.value == "true"
    assert result.execution_status != "completed"


def test_mapper_does_not_invent_initial_source_or_share_session(tmp_path: Path) -> None:
    compiled = compile_cases(CONFIG, tmp_path / "compiled")
    task = RuntimeTask.model_validate_json(
        (compiled / "cases/cap-f1-001-benign/runtime_task.json").read_text(encoding="utf-8")
    )
    raw = [
        {
            "event_id": "r1",
            "sequence_no": 1,
            "session_id": "s1",
            "event_type": "state_read",
            "status": "passed",
            "public_payload": {
                "workspace_relative_path": "trusted/acceptance-ledger.json",
                "actual_session_identity_sha256": "a" * 64,
                "read_completeness": "complete_content",
            },
            "output_artifacts": [{"content_hash": "b" * 64}],
        },
        {
            "event_id": "r2",
            "sequence_no": 2,
            "session_id": "s2",
            "event_type": "message",
            "operation": "extract_victim_response",
            "status": "passed",
            "public_payload": {"actual_session_identity_sha256": "c" * 64, "response": "done"},
        },
    ]
    events = map_safeclaw_capability_events(
        task, raw, run_id="test-run", episode_id="test-episode", reviewed_message="hello"
    )
    read = next(event for event in events if event.event_type == "state_read")
    response = next(event for event in events if event.event_type == "response")
    assert read.evidence.get("source_kind") != "initial_state"
    assert read.actual_session_key != response.actual_session_key
    assert not any(event.event_type == "session_started" for event in events)
