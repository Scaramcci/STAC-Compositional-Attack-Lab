from __future__ import annotations

from time import monotonic
from typing import Any

import pytest

from stac_attack_lab.interactions.base import CollectionBudget
from stac_attack_lab.interactions.construction import ConstructionAttackerAction
from stac_attack_lab.interactions.safeclaw_collection import (
    SafeClawSubprocessVictimDriver,
)


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
