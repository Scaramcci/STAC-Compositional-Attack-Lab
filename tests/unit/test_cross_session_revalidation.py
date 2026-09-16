from __future__ import annotations

import json
import runpy
from pathlib import Path

from stac_attack_lab.execution.construction_admission import construction_admission
from stac_attack_lab.hashing import stable_hash
from stac_attack_lab.interactions.models import RawInteractionTrajectory
from stac_attack_lab.interactions.normalizer import normalize_source_events


def _trajectory() -> RawInteractionTrajectory:
    return RawInteractionTrajectory(
        trajectory_id="s1-s2-s3",
        source_adapter_id="fixture",
        source_adapter_version="1",
        source_environment_family="safeclaw",
        source_environment_version="1",
        source_task_id="task",
        source_split="synthetic",
        episode_id="episode",
        session_ids=["s1", "s2", "s3"],
        event_refs=[], checkpoint_refs=[], model_hashes={}, config_hash="c", collection_seed=1,
        collection_status="complete", provenance={},
    )


def test_bridge_classifies_workspace_read_and_rejects_response_before_result() -> None:
    bridge = runpy.run_path("integrations/safeclaw/construction_bridge.py")
    project = bridge["_structured_tool_observations"]
    raw = {"session_transcript_raw": "\n".join(json.dumps(item) for item in [
        {"id": "r", "type": "message", "message": {"role": "toolResult", "toolCallId": "c", "toolName": "read", "content": [{"type": "text", "text": "x"}]}},
        {"id": "c", "type": "message", "message": {"role": "assistant", "content": [{"type": "toolCall", "id": "c", "name": "read", "arguments": {"path": "memory/../secret"}}]}},
    ])}
    observations, _ = project(raw, set(), [])
    assert observations[0]["observation_class"] == "workspace_file"
    assert observations[0]["workspace_relative_path"] is None
    assert observations[0]["result_order_valid"] is False
    assert observations[0]["result_observation"] == "not_observed"


def test_s1_write_s2_gap_s3_read_and_use_is_admitted() -> None:
    scope = {"actual_session_identity_sha256": stable_hash("s1"), "workspace_identity_sha256": stable_hash("w"), "memory_index_namespace_sha256": stable_hash("i")}
    later = {**scope, "actual_session_identity_sha256": stable_hash("s3"), "retrieval_hit": True, "new_session_request_action_id": "restart-s2"}
    events = [
        {"event_id": "write", "session_id": "s1", "sequence_no": 1, "actor_role": "system", "event_type": "state_write", "component_role": "persistent_memory", "operation": "memory_write", "status": "passed", "post_state_ref": "m:v1", "write_state_refs": ["m"], "output_artifacts": [{"artifact_id": "a-write", "artifact_type": "memory", "content_hash": "v1", "parent_artifact_ids": [], "taint_labels": ["persistent"], "trust_label": "workspace_state", "source_ref_ids": ["w"]}], "public_payload": scope},
        {"event_id": "restart", "session_id": "s2", "sequence_no": 2, "actor_role": "runner", "event_type": "lifecycle", "component_role": "session_lifecycle", "operation": "request_new_session", "status": "passed", "lifecycle_id": "restart-s2", "public_payload": {}, "evidence_ref_ids": ["l"]},
        {"event_id": "gap", "session_id": "s2", "sequence_no": 3, "actor_role": "agent", "event_type": "message", "component_role": "agent_context", "operation": "benign", "status": "passed", "public_payload": {}},
        {"event_id": "read", "session_id": "s3", "sequence_no": 4, "actor_role": "system", "event_type": "state_read", "component_role": "persistent_memory", "operation": "memory_retrieve_later_session", "status": "passed", "read_state_refs": ["m"], "input_artifact_ids": ["a-write"], "output_artifacts": [{"artifact_id": "a-read", "artifact_type": "retrieved", "content_hash": "v1", "parent_artifact_ids": ["a-write"], "taint_labels": ["persistent"], "trust_label": "workspace_state", "source_ref_ids": ["r"]}], "public_payload": later},
        {"event_id": "use", "session_id": "s3", "sequence_no": 5, "actor_role": "agent", "event_type": "tool_call", "component_role": "effect_tool", "operation": "effect", "status": "passed", "input_artifact_ids": ["a-read"], "public_payload": later},
    ]
    graph, audit = normalize_source_events(_trajectory(), events, audit_ref="a")
    assert audit.passed
    report = construction_admission(_trajectory(), graph, accepted_count=1, library_audit_passed=True)
    assert report["checks"]["cross_session_persistence_read_use"] is True
    assert report["evidence_diagnostics"]["downstream_consumption"]["state"] == "observed"
