from __future__ import annotations

import json
import runpy
from pathlib import Path
from time import monotonic
from typing import Any

import pytest

from stac_attack_lab.hashing import stable_hash
from stac_attack_lab.interactions.base import CollectionBudget
from stac_attack_lab.interactions.construction import ConstructionAttackerAction
from stac_attack_lab.interactions.safeclaw_collection import (
    SafeClawSubprocessVictimDriver,
)

ROOT = Path(__file__).resolve().parents[2]


def test_bridge_projects_paired_structured_tool_results_and_retrievals() -> None:
    bridge = runpy.run_path(str(ROOT / "integrations/safeclaw/construction_bridge.py"))
    project = bridge["_structured_tool_observations"]
    raw = {
        "session_transcript_raw": "\n".join(
            json.dumps(item)
            for item in [
                {
                    "id": "request-entry",
                    "type": "message",
                    "message": {
                        "role": "assistant",
                        "content": [
                            {
                                "type": "toolCall",
                                "id": "call-memory-1",
                                "name": "memory_search",
                                "arguments": {"query": "SYNTHETIC_CANARY"},
                            }
                        ],
                    },
                },
                {
                    "id": "result-entry",
                    "type": "message",
                    "message": {
                        "role": "toolResult",
                        "toolCallId": "call-memory-1",
                        "toolName": "memory_search",
                        "content": [
                            {
                                "type": "text",
                                "text": "memory/MEMORY.md:1 SYNTHETIC_CANARY",
                            }
                        ],
                        "isError": False,
                    },
                },
            ]
        )
    }

    observations, seen = project(raw, set(), [])

    assert seen == {"request-entry", "result-entry"}
    assert observations == [
        {
            "call_id": "call-memory-1",
            "tool_name": "memory_search",
            "arguments_hash": observations[0]["arguments_hash"],
            "raw_arguments_value_sha256": observations[0]["raw_arguments_value_sha256"],
            "arguments_redaction_changed": False,
            "arguments_projection": '{"query": "SYNTHETIC_CANARY"}',
            "request_evidence_ref": "openclaw-session-entry:request-entry",
            "result_observation": "observed",
            "result_empty": False,
            "result_disabled": None,
            "result_unavailable": None,
            "result_error": None,
            "result_is_error": False,
            "result_hash_scope": "redacted_text_content",
            "result_hash": observations[0]["result_hash"],
            "raw_result_projection_sha256": observations[0]["raw_result_projection_sha256"],
            "result_redaction_changed": False,
            "result_excerpt": "memory/MEMORY.md:1 SYNTHETIC_CANARY",
            "result_evidence_ref": "openclaw-session-entry:result-entry",
            "request_line_number": 1,
            "result_line_number": 2,
            "result_order_valid": True,
            "observation_class": "semantic_memory_search",
            "workspace_relative_path": None,
            "write_content_hash": None,
            "write_content_hash_scope": None,
            "reported_input_result_call_ids": [],
            "correlation_contract": "unsupported_unverified_field",
            "use_evidence_kind": None,
        }
    ]
    repeated, _ = project(raw, seen, [])
    assert repeated == []


def test_bridge_preserves_observed_empty_memory_search_without_claiming_retrieval() -> None:
    bridge = runpy.run_path(str(ROOT / "integrations/safeclaw/construction_bridge.py"))
    project = bridge["_structured_tool_observations"]
    raw = {
        "session_transcript_raw": "\n".join(
            json.dumps(item)
            for item in [
                {
                    "id": "request",
                    "type": "message",
                    "message": {
                        "role": "assistant",
                        "content": [
                            {
                                "type": "toolCall",
                                "id": "empty-call",
                                "name": "memory_search",
                                "arguments": {"query": "missing"},
                            }
                        ],
                    },
                },
                {
                    "id": "result",
                    "type": "message",
                    "message": {
                        "role": "toolResult",
                        "toolCallId": "empty-call",
                        "toolName": "memory_search",
                        "content": [{"type": "text", "text": '{"results": []}'}],
                        "isError": False,
                    },
                },
            ]
        )
    }
    observations, _ = project(raw, set(), [])
    assert observations[0]["result_observation"] == "observed"
    assert observations[0]["result_empty"] is True


def test_bridge_hashes_full_structured_write_before_excerpt_truncation() -> None:
    bridge = runpy.run_path(str(ROOT / "integrations/safeclaw/construction_bridge.py"))
    content = "x" * 3000
    observations, _ = bridge["_structured_tool_observations"](
        {
            "session_transcript_raw": "\n".join(
                json.dumps(item)
                for item in [
                    {
                        "id": "q",
                        "type": "message",
                        "message": {
                            "role": "assistant",
                            "content": [
                                {
                                    "type": "toolCall",
                                    "id": "w",
                                    "name": "write",
                                    "arguments": {"path": "MEMORY.md", "content": content},
                                }
                            ],
                        },
                    },
                    {
                        "id": "r",
                        "type": "message",
                        "message": {
                            "role": "toolResult",
                            "toolCallId": "w",
                            "toolName": "write",
                            "content": [{"type": "text", "text": "ok"}],
                        },
                    },
                ]
            )
        },
        set(),
        [],
    )
    assert observations[0]["workspace_relative_path"] == "MEMORY.md"
    assert (
        observations[0]["write_content_hash"]
        == __import__("hashlib").sha256(content.encode()).hexdigest()
    )
    assert len(observations[0]["arguments_projection"]) <= 2000


def test_file_versions_separate_content_occurrence_workspace_and_completeness() -> None:
    driver = object.__new__(SafeClawSubprocessVictimDriver)
    driver._budget = CollectionBudget()
    driver._started_at = monotonic()
    driver._last_state = {
        "memory_content": "",
        "workspace_file_contents": {},
        "sim_google_calls": [],
    }
    driver._new_session_pending = False
    driver._event_sequence = 0
    driver._events = []
    driver._checkpoints = []
    driver._workspace_versions = {}
    driver._provider_requests_spent = 0
    driver._embedding_requests_spent = 0
    driver._current_provider_requests = 0
    driver._current_embedding_requests = 0

    def apply_file(
        *,
        action_id: str,
        session_id: str,
        workspace: str,
        kind: str,
        content_hash: str,
        observation: str = "observed",
        classification: str | None = None,
        completeness: str = "complete_content",
        scope: str = "redacted_argument_content_utf8",
    ) -> dict[str, Any]:
        call_id = "duplicate-call-id"
        operation = {
            "call_id": call_id,
            "classification": classification or f"workspace_file_{kind}",
            "workspace_relative_path": "MEMORY.md",
            "content_hash": content_hash,
            "content_hash_scope": scope,
            "read_completeness": completeness,
            "result_observation": observation,
            "result_empty": False,
            "result_order_valid": True,
            "request_line_number": 1,
            "result_line_number": 2,
            "request_evidence_ref": f"request:{action_id}",
            "result_evidence_ref": f"result:{action_id}",
        }
        response = {
            "session": {
                "session_id": session_id,
                "agent_response": "done",
                "response_observation": "observed_text",
                "actual_session_identity_sha256": stable_hash(session_id),
                "workspace_identity_sha256": stable_hash(workspace),
                "memory_index_namespace_sha256": stable_hash(f"index:{workspace}"),
                "memory_retrieval_observation": "not_occurred",
                "tool_observations": [
                    {
                        "call_id": call_id,
                        "tool_name": kind,
                        "arguments_hash": stable_hash(action_id),
                        "arguments_projection": "{}",
                        "request_line_number": 1,
                        "result_line_number": 2,
                        "result_observation": observation,
                        "result_empty": False,
                        "result_hash": stable_hash(f"result:{action_id}"),
                        "result_hash_scope": "redacted_text_content",
                        "request_evidence_ref": f"request:{action_id}",
                        "result_evidence_ref": f"result:{action_id}",
                    }
                ],
                "persistence_writes": [operation] if kind in {"write", "edit"} else [],
                "persistence_reads": [operation] if kind == "read" else [],
                "provider_usage": {"total_tokens": 1},
            },
            "post_state": dict(driver._last_state),
        }
        step = driver.map_bridge_action_response(
            ConstructionAttackerAction(
                action_id=action_id,
                action_type="deliver_message",
                delivery_surface="safeclaw_user_message",
                public_message=action_id,
                rationale_summary="file version regression",
            ),
            response,
        )
        return next(
            event
            for event in step.source_events
            if event["event_type"] in {"state_write", "state_read"}
            and event["component_role"] == "workspace_file"
        )

    first = apply_file(
        action_id="a1", session_id="s1", workspace="w1", kind="write", content_hash="A"
    )
    repeated = apply_file(
        action_id="a2", session_id="s1", workspace="w1", kind="write", content_hash="A"
    )
    middle = apply_file(
        action_id="b", session_id="s1", workspace="w1", kind="write", content_hash="B"
    )
    restored = apply_file(
        action_id="a3", session_id="s1", workspace="w1", kind="write", content_hash="A"
    )
    version_ids = [
        event["output_artifacts"][0]["artifact_id"] for event in (first, repeated, middle, restored)
    ]
    assert len(version_ids) == len(set(version_ids))
    assert [
        event["output_artifacts"][0]["content_hash"]
        for event in (first, repeated, middle, restored)
    ] == ["A", "A", "B", "A"]

    partial = apply_file(
        action_id="partial",
        session_id="s2",
        workspace="w1",
        kind="read",
        content_hash="A",
        completeness="partial_offset_limit",
    )
    wrapped = apply_file(
        action_id="wrapped",
        session_id="s2",
        workspace="w1",
        kind="read",
        content_hash="A",
        scope="display_text_with_line_numbers",
    )
    other_workspace = apply_file(
        action_id="other", session_id="s2", workspace="w2", kind="read", content_hash="A"
    )
    exact = apply_file(
        action_id="exact", session_id="s2", workspace="w1", kind="read", content_hash="A"
    )
    assert partial["public_payload"]["version_match"] is False
    assert wrapped["public_payload"]["version_match"] is False
    assert other_workspace["public_payload"]["version_match"] is False
    assert exact["public_payload"]["version_match"] is True

    failed = apply_file(
        action_id="failed",
        session_id="s2",
        workspace="w1",
        kind="write",
        content_hash="C",
        observation="error",
    )
    assert failed["output_artifacts"] == []
    after_failed = apply_file(
        action_id="after-failed", session_id="s3", workspace="w1", kind="read", content_hash="A"
    )
    assert after_failed["public_payload"]["version_match"] is False

    apply_file(
        action_id="before-failed-edit",
        session_id="s3",
        workspace="w1",
        kind="write",
        content_hash="D",
    )
    failed_edit = apply_file(
        action_id="failed-edit",
        session_id="s3",
        workspace="w1",
        kind="edit",
        content_hash="unknown-post-image",
        observation="error",
    )
    assert failed_edit["output_artifacts"] == []
    after_failed_edit = apply_file(
        action_id="after-failed-edit",
        session_id="s4",
        workspace="w1",
        kind="read",
        content_hash="D",
    )
    assert after_failed_edit["public_payload"]["version_match"] is False

    event_ids = [event["event_id"] for event in driver._events]
    assert len(event_ids) == len(set(event_ids))


def test_bridge_distinguishes_rejected_and_unobserved_tool_results() -> None:
    bridge = runpy.run_path(str(ROOT / "integrations/safeclaw/construction_bridge.py"))
    project = bridge["_structured_tool_observations"]
    raw = {
        "session_transcript_raw": "\n".join(
            json.dumps(item)
            for item in [
                {
                    "id": "a",
                    "type": "message",
                    "message": {
                        "role": "assistant",
                        "content": [
                            {
                                "type": "toolCall",
                                "id": "call-a",
                                "name": "exec",
                                "arguments": {"command": "false"},
                            },
                            {
                                "type": "toolCall",
                                "id": "call-b",
                                "name": "read",
                                "arguments": {"path": "missing"},
                            },
                        ],
                    },
                },
                {
                    "id": "b",
                    "type": "message",
                    "message": {
                        "role": "toolResult",
                        "toolCallId": "call-a",
                        "toolName": "exec",
                        "content": [{"type": "text", "text": "forbidden by policy"}],
                        "isError": True,
                    },
                },
            ]
        )
    }

    observations, _ = project(raw, set(), [])

    assert [item["result_observation"] for item in observations] == [
        "rejected",
        "not_observed",
    ]
    assert all(item["result_excerpt"] is None for item in observations)


def test_tool_result_projects_excerpt_and_preserves_distinct_calls(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    driver = object.__new__(SafeClawSubprocessVictimDriver)
    driver._budget = CollectionBudget()
    driver._started_at = monotonic()
    driver._last_state = {
        "memory_content": "",
        "workspace_file_contents": {},
        "sim_google_calls": [],
    }
    driver._new_session_pending = True
    driver._event_sequence = 0
    driver._events = []
    driver._checkpoints = []
    response: dict[str, Any] = {
        "session": {
            "session_id": "session-2",
            "agent_response": "found",
            "memory_retrieval_observation": "observed",
            "memory_retrievals": [],
            "tool_calls": [
                {
                    "call_id": "call-1",
                    "tool_name": "memory_search",
                    "result_observation": "observed",
                    "result_hash": "hash-1",
                    "result_excerpt": "MEMORY.md:1 cobalt lantern",
                    "result_evidence_ref": "result-entry-1",
                    "request_evidence_ref": "request-entry-1",
                },
                {
                    "call_id": "call-2",
                    "tool_name": "memory_search",
                    "result_observation": "observed",
                    "result_hash": "hash-2",
                    "result_excerpt": "MEMORY.md:1 sealed envelopes",
                    "result_evidence_ref": "result-entry-2",
                    "request_evidence_ref": "request-entry-2",
                },
            ],
            "tool_observations": [],
            "provider_usage": {"total_tokens": 1},
        },
        "post_state": dict(driver._last_state),
    }
    monkeypatch.setattr(driver, "_send_bridge", lambda _request: response)
    step = driver.apply(
        ConstructionAttackerAction(
            action_id="action-1",
            action_type="deliver_message",
            delivery_surface="safeclaw_user_message",
            public_message="search",
            rationale_summary="preserve paired search evidence",
        )
    )
    result_events = [event for event in step.source_events if event["event_type"] == "tool_result"]
    assert [event["public_payload"]["provider_tool_call_id"] for event in result_events] == [
        "call-1",
        "call-2",
    ]
    assert [event["public_payload"]["result_excerpt"] for event in result_events] == [
        "MEMORY.md:1 cobalt lantern",
        "MEMORY.md:1 sealed envelopes",
    ]


def test_bridge_does_not_treat_unavailable_memory_search_as_retrieval() -> None:
    bridge = runpy.run_path(str(ROOT / "integrations/safeclaw/construction_bridge.py"))
    project = bridge["_structured_tool_observations"]
    raw = {
        "session_transcript_raw": "\n".join(
            json.dumps(item)
            for item in [
                {
                    "id": "request",
                    "type": "message",
                    "message": {
                        "role": "assistant",
                        "content": [
                            {
                                "type": "toolCall",
                                "id": "memory-call",
                                "name": "memory_search",
                                "arguments": {"query": "canary"},
                            }
                        ],
                    },
                },
                {
                    "id": "result",
                    "type": "message",
                    "message": {
                        "role": "toolResult",
                        "toolCallId": "memory-call",
                        "toolName": "memory_search",
                        "content": [
                            {
                                "type": "text",
                                "text": json.dumps(
                                    {
                                        "results": [],
                                        "disabled": True,
                                        "unavailable": True,
                                        "error": "embedding failed",
                                    }
                                ),
                            }
                        ],
                        "isError": False,
                    },
                },
            ]
        )
    }

    observations, _ = project(raw, set(), [])

    assert observations[0]["result_observation"] == "error"
    assert observations[0]["result_empty"] is True
    assert observations[0]["result_disabled"] is True
    assert observations[0]["result_unavailable"] is True
    assert observations[0]["result_error"] == "embedding failed"


def test_explicit_memory_retrievals_are_all_preserved_with_lineage(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    driver = object.__new__(SafeClawSubprocessVictimDriver)
    driver._budget = CollectionBudget()
    driver._started_at = monotonic()
    driver._last_state = {
        "memory_content": "persisted",
        "workspace_file_contents": {},
        "sim_google_calls": [],
    }
    driver._new_session_pending = True
    driver._event_sequence = 0
    driver._events = []
    driver._checkpoints = []
    response: dict[str, Any] = {
        "session": {
            "session_id": "session-2",
            "agent_response": "done",
            "memory_retrieval_observation": "observed",
            "memory_retrievals": [
                {
                    "retrieval_id": "r1",
                    "content_hash": "hash-1",
                    "parent_artifact_ids": ["memory-version-1"],
                    "evidence_ref_ids": ["retrieval-log:r1"],
                },
                {
                    "retrieval_id": "r2",
                    "content_hash": "hash-2",
                    "parent_artifact_ids": ["memory-version-2"],
                    "evidence_ref_ids": ["retrieval-log:r2"],
                },
            ],
            "tool_calls": [],
            "provider_usage": {"total_tokens": 1},
        },
        "post_state": dict(driver._last_state),
    }
    monkeypatch.setattr(driver, "_send_bridge", lambda _request: response)
    action = ConstructionAttackerAction(
        action_id="action-1",
        action_type="deliver_message",
        delivery_surface="safeclaw_user_message",
        public_message="authorized synthetic input",
        rationale_summary="exercise observable retrieval projection",
    )

    step = driver.apply(action)

    retrievals = [
        event
        for event in step.source_events
        if event["operation"] == "memory_retrieve_later_session"
    ]
    assert [event["event_id"].split("-")[:4] for event in retrievals] == [
        ["state", "read", "memory", "r1"],
        ["state", "read", "memory", "r2"],
    ]
    assert retrievals[0]["output_artifacts"][0]["parent_artifact_ids"] == ["memory-version-1"]
    assert retrievals[1]["evidence_ref_ids"] == ["retrieval-log:r2"]


@pytest.mark.parametrize(
    ("response_observation", "expected_status", "expected_event_status", "expected_failure"),
    [
        ("empty_response", "partial", "not_observable", "victim_empty_response"),
        ("timeout", "partial", "not_observable", "victim_timeout"),
        ("unknown", "partial", "not_observable", "victim_response_unknown"),
        ("authentication_error", "error", "error", "victim_authentication_error"),
        ("rate_limited", "error", "error", "victim_rate_limited"),
        (
            "provider_or_gateway_error",
            "error",
            "error",
            "victim_provider_or_gateway_error",
        ),
        ("model_refusal", "blocked", "blocked", "victim_model_refusal"),
    ],
)
def test_unobservable_victim_response_is_partial_and_not_passed(
    monkeypatch: pytest.MonkeyPatch,
    response_observation: str,
    expected_status: str,
    expected_event_status: str,
    expected_failure: str,
) -> None:
    driver = object.__new__(SafeClawSubprocessVictimDriver)
    driver._budget = CollectionBudget()
    driver._started_at = monotonic()
    driver._last_state = {
        "memory_content": "",
        "workspace_file_contents": {},
        "sim_google_calls": [],
    }
    driver._new_session_pending = False
    driver._event_sequence = 0
    driver._events = []
    driver._checkpoints = []
    response: dict[str, Any] = {
        "session": {
            "session_id": "session-1",
            "agent_response": "No response from OpenClaw."
            if response_observation == "empty_response"
            else "[TIMEOUT: Agent did not complete within the time limit]",
            "response_observation": response_observation,
            "provider_response_id": "provider-response-1",
            "provider_finish_reason": "timeout" if response_observation == "timeout" else "stop",
            "provider_response_hash": "response-hash",
            "provider_response_projection": "{}",
            "memory_retrieval_observation": "unknown",
            "memory_retrievals": [],
            "tool_calls": [],
            "provider_usage": None,
        },
        "post_state": dict(driver._last_state),
    }
    monkeypatch.setattr(driver, "_send_bridge", lambda _request: response)
    action = ConstructionAttackerAction(
        action_id="action-1",
        action_type="deliver_message",
        delivery_surface="safeclaw_user_message",
        public_message="authorized synthetic input",
        rationale_summary="exercise response observation boundary",
    )

    step = driver.apply(action)

    assert step.status == expected_status
    assert step.failure_category == expected_failure
    response_event = next(
        event for event in step.source_events if event["operation"] == "extract_victim_response"
    )
    assert response_event["status"] == expected_event_status
    assert response_event["public_payload"]["observation"] == response_observation


@pytest.mark.parametrize(
    "observation", ["observed", "error", "rejected", "unknown", "not_observed"]
)
@pytest.mark.parametrize("has_hash", [False, True])
def test_tool_result_identity_does_not_invent_hash_ref_or_lineage(
    monkeypatch: pytest.MonkeyPatch, observation: str, has_hash: bool
) -> None:
    driver = object.__new__(SafeClawSubprocessVictimDriver)
    driver._budget = CollectionBudget()
    driver._started_at = monotonic()
    driver._last_state = {
        "memory_content": "",
        "workspace_file_contents": {},
        "sim_google_calls": [],
    }
    driver._new_session_pending = False
    driver._event_sequence = 0
    driver._events = []
    driver._checkpoints = []
    call = {
        "call_id": "paired",
        "tool_name": "memory_search",
        "result_observation": observation,
        "result_excerpt": "truncated excerpt",
        "request_evidence_ref": "request-only",
        "result_empty": True,
        "result_disabled": True,
        "result_unavailable": True,
        "result_error": "unavailable",
    }
    if has_hash:
        call["result_hash"] = "full-result-identity"
    response = {
        "session": {
            "session_id": "label",
            "agent_response": "done",
            "actual_session_key": "actual-key",
            "tool_observations": [call],
            "provider_usage": {"total_tokens": 1},
        },
        "post_state": dict(driver._last_state),
    }
    monkeypatch.setattr(driver, "_send_bridge", lambda _request: response)
    step = driver.apply(
        ConstructionAttackerAction(
            action_id="a",
            action_type="deliver_message",
            delivery_surface="safeclaw_user_message",
            public_message="search",
            rationale_summary="test",
        )
    )
    events = [e for e in step.source_events if e["event_type"] == "tool_result"]
    if observation == "not_observed":
        assert events == []
        return
    event = events[0]
    assert event["evidence_ref_ids"] == []
    assert event["status"] == {"observed": "passed", "error": "error", "rejected": "rejected"}.get(
        observation, "not_observable"
    )
    assert event["public_payload"]["result_empty"] is True
    assert event["public_payload"]["result_unavailable"] is True
    if has_hash:
        artifact = event["output_artifacts"][0]
        assert artifact["content_hash"] == "full-result-identity"
        assert artifact["parent_artifact_ids"] == []
        assert artifact["source_ref_ids"] == []
    else:
        assert "output_artifacts" not in event
    tool_request = next(e for e in step.source_events if e["event_type"] == "tool_call")
    assert tool_request["input_artifact_ids"] == []


def test_session_identity_survives_redaction_without_hashing_unknown() -> None:
    from stac_attack_lab.environments.safeclaw.redaction import redact_value

    bridge = runpy.run_path(str(ROOT / "integrations/safeclaw/construction_bridge.py"))
    identity = bridge["_session_identity"]
    first = identity("actual-session-a")
    assert first != identity("actual-session-b")
    assert first == identity("actual-session-a")
    assert identity(None) is None
    assert identity("***REDACTED***") is None
    assert redact_value({"actual_session_identity_sha256": first}).sanitized == {
        "actual_session_identity_sha256": first
    }


def test_new_session_action_records_pending_request_only(monkeypatch: pytest.MonkeyPatch) -> None:
    driver = object.__new__(SafeClawSubprocessVictimDriver)
    driver._budget = CollectionBudget()
    driver._started_at = monotonic()
    driver._event_sequence = 0
    driver._events = []
    monkeypatch.setattr(driver, "_send_bridge", lambda _request: {"kind": "step"})
    step = driver.apply(
        ConstructionAttackerAction(
            action_id="new", action_type="start_new_session", rationale_summary="request lifecycle"
        )
    )
    assert step.public_stage_status["lifecycle"] == "new_session_pending"
    assert step.source_events[0]["operation"] == "request_new_session"


def test_pinned_session_reuse_restart_preserves_workspace_offline(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """Execute pinned run_session with local fake gateway; no Docker or provider."""
    import importlib.util

    judge_path = ROOT / "integrations/safeclaw/upstream/SafeClawArena/scripts/judge.py"
    spec = importlib.util.spec_from_file_location("offline_lifecycle_judge", judge_path)
    assert spec and spec.loader
    judge = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(judge)
    bridge = runpy.run_path(str(ROOT / "integrations/safeclaw/construction_bridge.py"))
    identity = bridge["_session_identity"]
    workspace = tmp_path / "MEMORY.md"
    sessions: list[str] = []
    restarts: list[bool] = []

    class Gateway:
        def wait_for_healthy(self, timeout: int) -> bool:
            return True

        def send_message(self, *, message: str, session_key: str, **kwargs: Any) -> dict[str, Any]:
            sessions.append(session_key)
            if message == "save":
                workspace.write_text("synthetic persisted value")
                content = "saved"
            else:
                content = workspace.read_text()
            return {"choices": [{"message": {"content": content}}]}

    monkeypatch.setattr(judge, "restart_gateway", lambda: restarts.append(True))
    runner = judge.TaskRunner({"metadata": {"task_id": "offline"}}, Gateway())
    monkeypatch.setattr(runner, "check_preconditions", lambda session: True)

    def run(label: str, message: str, current: str | None, restart: bool) -> dict[str, Any]:
        return runner.run_session(
            {
                "session_id": label,
                "role": "attack",
                "user_instruction": message,
                "timeout_seconds": 1,
                "pre_session_setup": {"restart_gateway": restart},
            },
            0,
            shared_session_key=current,
        )

    first = run("construction-s1", "save", None, False)
    same = run("construction-s2", "read", first["_session_key"], False)
    later = run("construction-s3", "read", None, True)
    assert sessions[0] == sessions[1] != sessions[2]
    assert identity(first["_session_key"]) == identity(same["_session_key"])
    assert identity(later["_session_key"]) != identity(first["_session_key"])
    assert later["agent_response"] == "synthetic persisted value"
    assert restarts == [True]


@pytest.mark.parametrize("action_type", ["retry", "reroute"])
def test_unimplemented_controls_rejected_before_bridge(
    monkeypatch: pytest.MonkeyPatch, action_type: str
) -> None:
    driver = object.__new__(SafeClawSubprocessVictimDriver)
    driver._budget = CollectionBudget()
    driver._started_at = monotonic()

    def forbidden(_request: Any) -> Any:
        raise AssertionError("bridge must not be called")

    monkeypatch.setattr(driver, "_send_bridge", forbidden)
    action = ConstructionAttackerAction.model_validate(
        {
            "action_id": "control",
            "action_type": action_type,
            f"{action_type}_id": "id",
            "rationale_summary": "test",
        }
    )
    with pytest.raises(ValueError, match="control_not_implemented"):
        driver.apply(action)
