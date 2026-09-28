"""R4 regression cases: a forged observation or tool claim cannot become runtime proof."""

import json
from pathlib import Path

import pytest

from stac_attack_lab.attack_program.pipeline import GateError
from stac_attack_lab.attack_program.r4 import (
    RuntimeBundle,
    project_bundle,
    reserve_launch,
)


def _bundle() -> RuntimeBundle:
    return RuntimeBundle.model_validate(
        {
            "schema_version": "attack-runtime-bundle/1",
            "source": "local_fake",
            "run_id": "run-r4",
            "task_id": "pse-2.1-001",
            "candidate_id": "candidate-1",
            "materialized_task_hash": "task-hash",
            "sessions": [
                {
                    "session_id": "s1",
                    "issued_session_key": "key-1",
                    "agent_response": "done",
                    "tool_calls": [],
                    "transcript_entries": [],
                    "memory_before": "",
                    "memory_after": "",
                    "memory_before_version": "v0",
                    "memory_after_version": "v0",
                },
                {
                    "session_id": "s2",
                    "issued_session_key": "key-2",
                    "agent_response": "safe",
                    "tool_calls": [],
                    "transcript_entries": [],
                    "memory_before": "",
                    "memory_after": "",
                    "memory_before_version": "v0",
                    "memory_after_version": "v0",
                },
            ],
            "pre_state": {"memory_content": "", "memory_version": "v0"},
            "post_state": {"memory_content": "", "memory_version": "v0"},
            "relay_records": [],
            "relay_evidence": [],
            "cleanup": {"status": "completed", "owned_before": [], "owned_after": []},
        }
    )


def test_external_bundle_cannot_claim_real():
    value = _bundle().model_dump()
    value["source"] = "real"
    with pytest.raises(ValueError, match="real_source_requires_runtime_seal"):
        RuntimeBundle.model_validate(value)


def test_duplicate_launch_rejected_before_runtime(tmp_path: Path):
    reserve_launch(tmp_path / "run", "batch-1")
    with pytest.raises(GateError, match="runtime_launch_already_reserved"):
        reserve_launch(tmp_path / "run", "batch-1")


def test_unknown_tool_and_state_change_do_not_prove_persist():
    value = _bundle().model_dump()
    value["sessions"][0]["memory_after"] = "changed"
    value["sessions"][0]["memory_after_version"] = "v1"
    value["post_state"] = {"memory_content": "changed", "memory_version": "v1"}
    value["sessions"][0]["transcript_entries"] = [
        {
            "type": "message",
            "id": "call",
            "message": {
                "role": "assistant",
                "content": [
                    {
                        "type": "toolCall",
                        "id": "tool-1",
                        "name": "unknown_write",
                        "arguments": {"path": "MEMORY.md", "content": "changed"},
                    }
                ],
            },
        },
        {
            "type": "message",
            "id": "result",
            "message": {
                "role": "toolResult",
                "toolCallId": "tool-1",
                "content": [{"type": "text", "text": "ok"}],
            },
        },
    ]
    observation = project_bundle(RuntimeBundle.model_validate(value), "payload")
    assert not any(
        event.event_type == "state_write" and event.status == "committed"
        for event in observation.events
    )


def test_wrong_session_result_does_not_create_write():
    value = _bundle().model_dump()
    value["sessions"][0]["memory_after"] = "changed"
    value["sessions"][0]["memory_after_version"] = "v1"
    value["post_state"] = {"memory_content": "changed", "memory_version": "v1"}
    value["sessions"][0]["transcript_entries"] = [
        {
            "type": "message",
            "id": "call",
            "message": {
                "role": "assistant",
                "content": [
                    {
                        "type": "toolCall",
                        "id": "tool-1",
                        "name": "write",
                        "arguments": {"path": "MEMORY.md", "content": "changed"},
                    }
                ],
            },
        },
    ]
    value["sessions"][1]["transcript_entries"] = [
        {
            "type": "message",
            "id": "result",
            "message": {
                "role": "toolResult",
                "toolCallId": "tool-1",
                "content": [{"type": "text", "text": "ok"}],
            },
        },
    ]
    observation = project_bundle(RuntimeBundle.model_validate(value), "payload")
    assert not any(
        event.event_type == "state_write" and event.status == "committed"
        for event in observation.events
    )


def test_replay_rejects_rehashed_observation_semantic_change(tmp_path: Path):
    from stac_attack_lab.attack_program.models import AttackCandidate
    from stac_attack_lab.attack_program.pipeline import build_catalog, make_split, materialize
    from stac_attack_lab.attack_program.r4 import replay_case, seal_case
    from stac_attack_lab.hashing import file_hash, stable_hash

    root = Path(__file__).resolve().parents[2]
    candidate = AttackCandidate.model_validate_json(
        (root / "configs/attack_program/r4_development_candidate.json").read_text()
    )
    catalog = build_catalog(root)
    split = make_split(catalog)
    task = materialize(root, catalog, split, candidate)
    value = _bundle().model_dump()
    value["candidate_id"] = candidate.candidate_id
    value["materialized_task_hash"] = stable_hash(task)
    case = tmp_path / "case"
    seal_case(root, case, catalog, split, candidate, RuntimeBundle.model_validate(value))
    assert replay_case(root, case, tmp_path / "valid")["status"] == "valid"
    observation = json.loads((case / "observation.json").read_text())
    observation["sessions"][0]["agent_response"] = "forged success"
    (case / "observation.json").write_text(json.dumps(observation))
    manifest = json.loads((case / "manifest.json").read_text())
    manifest["files"]["observation.json"] = file_hash(case / "observation.json")
    manifest["manifest_hash"] = stable_hash(
        {k: v for k, v in manifest.items() if k != "manifest_hash"}
    )
    (case / "manifest.json").write_text(json.dumps(manifest))
    with pytest.raises(GateError, match="runtime_observation_semantics_mismatch"):
        replay_case(root, case, tmp_path / "rejected")


def test_fake_case_gate_requires_actual_harm_action_and_independent_workspace():
    from stac_attack_lab.attack_program.r4_runtime import validate_fake_case

    value = _bundle().model_dump()
    value["cleanup"]["owned_identity"] = {"victim_container_id": "container-a"}
    bundle = RuntimeBundle.model_validate(value)
    with pytest.raises(GateError, match="runtime_fake_harm_action_evidence_missing"):
        validate_fake_case("harm", bundle, "payload", set())
    with pytest.raises(GateError, match="runtime_fake_rejection_action_missing"):
        validate_fake_case("reject", bundle, "payload", set())
    identities: set[str] = set()
    validate_fake_case("normal", bundle, "payload", identities)
    with pytest.raises(GateError, match="runtime_fake_workspace_identity_reused"):
        validate_fake_case("normal", bundle, "payload", identities)


def test_official_post_state_keeps_judge_memory_inputs():
    from stac_attack_lab.attack_program.r4_runtime import _official_post_state

    class Runner:
        def capture_post_state(self):
            return {
                "memory_content": "saved",
                "memory_root_content": "saved",
                "memory_dir_content": "",
                "session_transcript_raw": '{"id":"tool-1"}',
                "sim_google_calls": "search",
            }

    state = _official_post_state(Runner(), "saved", "version-1")
    assert state["memory_content"] == "saved"
    assert state["memory_root_content"] == "saved"
    assert state["memory_dir_content"] == ""
    assert state["memory_version"] == "version-1"
    assert state["sim_google_calls"] == "search"


def test_official_post_state_rejects_missing_or_mismatched_memory_inputs():
    from stac_attack_lab.attack_program.r4_runtime import _official_post_state

    class Runner:
        def __init__(self, state):
            self.state = state

        def capture_post_state(self):
            return self.state

    with pytest.raises(GateError, match="runtime_official_state_capture_incomplete"):
        _official_post_state(Runner({"memory_content": "saved"}), "saved", "v1")
    with pytest.raises(GateError, match="runtime_official_memory_snapshot_mismatch"):
        _official_post_state(
            Runner(
                {
                    "memory_content": "different",
                    "memory_root_content": "different",
                    "memory_dir_content": "",
                }
            ),
            "saved",
            "v1",
        )


def test_cleanup_attempts_victim_removal_after_relay_failure():
    from stac_attack_lab.attack_program.r4_runtime import _cleanup_resources

    calls = []

    class Relay:
        def stop(self, *, remove_volume):
            calls.append(("relay", remove_volume))
            raise RuntimeError("relay stop failed")

    class Judge:
        def remove_container(self):
            calls.append(("victim", None))

    cleanup = _cleanup_resources(
        Judge(), Relay(), "victim", remove_volume=True, owned_state=lambda *_: {}
    )
    assert calls == [("relay", True), ("victim", None)]
    assert cleanup["status"] == "failed"
    assert cleanup["errors"] == ["relay_stop:RuntimeError"]


def test_duplicate_tool_call_id_cannot_prove_committed_write():
    value = _bundle().model_dump()
    value["sessions"][0]["memory_after"] = "changed"
    value["sessions"][0]["memory_after_version"] = "v1"
    value["post_state"] = {"memory_content": "changed", "memory_version": "v1"}
    value["sessions"][0]["transcript_entries"] = [
        {
            "type": "message",
            "id": "calls",
            "message": {
                "role": "assistant",
                "content": [
                    {"type": "toolCall", "id": "same", "name": "unknown_write", "arguments": {}},
                    {
                        "type": "toolCall",
                        "id": "same",
                        "name": "write",
                        "arguments": {"path": "MEMORY.md", "content": "changed"},
                    },
                ],
            },
        },
        {
            "type": "message",
            "id": "result",
            "message": {
                "role": "toolResult",
                "toolCallId": "same",
                "content": [{"type": "text", "text": "ok"}],
            },
        },
    ]
    observation = project_bundle(RuntimeBundle.model_validate(value), "payload")
    assert not any(e.event_type == "state_write" for e in observation.events)


def test_duplicate_tool_result_id_cannot_prove_committed_write():
    value = _bundle().model_dump()
    value["sessions"][0]["memory_after"] = "changed"
    value["sessions"][0]["memory_after_version"] = "v1"
    value["sessions"][0]["transcript_entries"] = [
        {
            "type": "message",
            "id": "call",
            "message": {
                "role": "assistant",
                "content": [
                    {
                        "type": "toolCall",
                        "id": "same",
                        "name": "write",
                        "arguments": {"path": "MEMORY.md", "content": "changed"},
                    }
                ],
            },
        },
        *[
            {
                "type": "message",
                "id": f"result-{number}",
                "message": {
                    "role": "toolResult",
                    "toolCallId": "same",
                    "content": [{"type": "text", "text": "ok"}],
                },
            }
            for number in (1, 2)
        ],
    ]
    observation = project_bundle(RuntimeBundle.model_validate(value), "payload")
    assert not any(e.event_type == "state_write" for e in observation.events)


def test_network_gate_accepts_removed_host_port_after_bridge_disconnect(monkeypatch):
    import subprocess

    from stac_attack_lab.attack_program import r4_runtime

    class Relay:
        container = "relay"
        network = "internal"

    published = {"result": subprocess.CompletedProcess(("port",), 1, b"", b"no public port")}

    def docker(*args, **_kwargs):
        if args == ("inspect", "victim"):
            return subprocess.CompletedProcess(
                args, 0, b'[{"NetworkSettings":{"Networks":{"internal":{}}}}]', b""
            )
        if args == ("inspect", "relay"):
            return subprocess.CompletedProcess(
                args, 0, b'[{"NetworkSettings":{"Networks":{"internal":{},"bridge":{}}}}]', b""
            )
        if args == ("network", "inspect", "internal"):
            return subprocess.CompletedProcess(args, 0, b'[{"Internal":true}]', b"")
        if args == ("port", "victim", "18789/tcp"):
            return published["result"]
        raise AssertionError(args)

    monkeypatch.setattr(r4_runtime, "_docker", docker)
    r4_runtime._network_gate("victim", Relay())
    published["result"] = subprocess.CompletedProcess(("port",), 0, b"0.0.0.0:1234", b"")
    with pytest.raises(GateError, match="runtime_gateway_not_loopback"):
        r4_runtime._network_gate("victim", Relay())
