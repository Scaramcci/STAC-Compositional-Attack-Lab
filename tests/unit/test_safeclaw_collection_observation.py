from __future__ import annotations

import json
import runpy
from pathlib import Path
from time import monotonic
from typing import Any

import pytest

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
            "arguments_projection": '{"query": "SYNTHETIC_CANARY"}',
            "request_evidence_ref": "openclaw-session-entry:request-entry",
            "result_observation": "observed",
            "result_hash": observations[0]["result_hash"],
            "result_excerpt": "memory/MEMORY.md:1 SYNTHETIC_CANARY",
            "result_evidence_ref": "openclaw-session-entry:result-entry",
        }
    ]
    repeated, _ = project(raw, seen, [])
    assert repeated == []


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
    assert [event["event_id"] for event in retrievals] == [
        "state-read-memory-r1",
        "state-read-memory-r2",
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
