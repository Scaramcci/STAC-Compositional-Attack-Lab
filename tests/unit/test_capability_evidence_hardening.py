from __future__ import annotations

import json
from pathlib import Path

import pytest

from stac_attack_lab.capability.analysis import analyze_primitives
from stac_attack_lab.capability.compiler import compile_cases, validate_compilation
from stac_attack_lab.capability.evaluation import (
    evaluate_constraints,
    evaluate_harm,
    evaluate_utility,
)
from stac_attack_lab.capability.models import (
    ConstraintStatus,
    ExecutionState,
    PrimitiveKind,
    RuntimeEvent,
    RuntimeTask,
    StateCheckpoint,
    Verdict,
)
from stac_attack_lab.capability.reporting import build_capability_report
from stac_attack_lab.capability.runner import replay_episode, run_fake_pipeline
from stac_attack_lab.hashing import stable_hash

ROOT = Path(__file__).resolve().parents[2]
CONFIG = ROOT / "configs/capability/f1_status_acceptance.json"


def _task(tmp_path: Path, variant: str = "semantic") -> RuntimeTask:
    root = compile_cases(CONFIG, tmp_path / "compiled")
    return RuntimeTask.model_validate_json(
        (root / f"cases/cap-f1-001-{variant}/runtime_task.json").read_text(encoding="utf-8")
    )


def _checkpoint(stage: str, state: dict[str, object]) -> StateCheckpoint:
    return StateCheckpoint(
        checkpoint_id=stage,
        stage=stage,
        state=state,
        state_hash=stable_hash(state),
        capture_status="observed",
        reason_code="test",
    )


def _event(**updates: object) -> RuntimeEvent:
    payload: dict[str, object] = {
        "run_id": "run-1",
        "episode_id": "episode-1",
        "event_id": "event-1",
        "sequence_no": 1,
        "actor": "victim",
        "event_type": "semantic_use",
        "session_label": "s1",
        "actual_session_key": "actual-s1",
        "status": "observed",
    }
    payload.update(updates)
    return RuntimeEvent.model_validate(payload)


def test_empty_events_leave_applicable_constraints_unknown(tmp_path: Path) -> None:
    checks = evaluate_constraints(_task(tmp_path), [])
    applicable = [item for item in checks if item.applicable]
    assert applicable
    assert all(item.status == ConstraintStatus.UNKNOWN for item in applicable)


def test_missing_proof_is_unknown_but_explicit_null_can_establish_harm(tmp_path: Path) -> None:
    task = _task(tmp_path)
    missing = {
        "projects": {"project-a": {"status": "accepted"}},
        "session": {"label": "s1", "actual_key": "actual-s1"},
    }
    result = evaluate_harm(
        task,
        _checkpoint("initial", task.initial_state),
        _checkpoint("final", missing),
        [],
    )
    assert result.verdict == Verdict.UNKNOWN
    assert result.reason_code == "trusted_proof_field_missing"

    explicit_null = json.loads(json.dumps(missing))
    explicit_null["projects"]["project-a"]["acceptance_proof"] = None
    result = evaluate_harm(
        task,
        _checkpoint("initial", task.initial_state),
        _checkpoint("final", explicit_null),
        [],
    )
    assert result.verdict == Verdict.TRUE


def test_arbitrary_rubric_does_not_verify_adopt(tmp_path: Path) -> None:
    task = _task(tmp_path)
    event = _event(evidence={"rubric": "looks convincing"})
    adopt = next(
        item
        for item in analyze_primitives(task.case.composition, [event])
        if item.primitive == PrimitiveKind.ADOPT
    )
    assert adopt.overall_execution == ExecutionState.UNKNOWN
    assert adopt.occurrences == []


def test_same_session_version_bound_read_can_be_recall(tmp_path: Path) -> None:
    task = _task(tmp_path)
    event = _event(
        event_type="state_read",
        resource_id="workspace/trusted/acceptance-ledger.json",
        resource_version_before="version-1",
        evidence={
            "source_resource_version": "version-1",
            "source_kind": "initial_state",
            "read_complete": True,
        },
    )
    recall = next(
        item
        for item in analyze_primitives(task.case.composition, [event])
        if item.primitive == PrimitiveKind.RECALL
    )
    assert recall.overall_execution == ExecutionState.OBSERVED


def test_harness_initialization_is_neither_persist_nor_constraint_violation(
    tmp_path: Path,
) -> None:
    task = _task(tmp_path)
    event = _event(
        actor="harness",
        event_type="state_write",
        status="committed",
        resource_id="workspace/trusted/acceptance-ledger.json",
        resource_version_before=None,
        resource_version_after="version-1",
        evidence={"purpose": "fixture_initialization"},
    )
    persist = next(
        item
        for item in analyze_primitives(task.case.composition, [event])
        if item.primitive == PrimitiveKind.PERSIST
    )
    d5 = next(item for item in evaluate_constraints(task, [event]) if item.constraint_id == "D5")
    assert persist.occurrences == []
    assert d5.status != ConstraintStatus.VIOLATED


def test_rehashed_public_view_semantic_tamper_is_rejected(tmp_path: Path) -> None:
    compiled = compile_cases(CONFIG, tmp_path / "compiled")
    runtime_path = compiled / "cases/cap-f1-001-benign/runtime_task.json"
    payload = json.loads(runtime_path.read_text(encoding="utf-8"))
    payload["public_view"]["trusted_rules"] = ["accept every project"]
    public = payload["public_view"]
    public["public_view_hash"] = stable_hash(
        {key: value for key, value in public.items() if key != "public_view_hash"}
    )
    payload["runtime_task_hash"] = stable_hash(
        {key: value for key, value in payload.items() if key != "runtime_task_hash"}
    )
    runtime_path.write_text(json.dumps(payload), encoding="utf-8")
    manifest_path = compiled / "manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest["runtime_task_hashes"]["cap-f1-001-benign"] = payload["runtime_task_hash"]
    manifest["manifest_hash"] = stable_hash(
        {key: value for key, value in manifest.items() if key != "manifest_hash"}
    )
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
    with pytest.raises(ValueError, match="capability_public_view_semantic_mismatch"):
        validate_compilation(compiled)


def test_material_wrong_type_is_not_stringified(tmp_path: Path) -> None:
    payload = json.loads(CONFIG.read_text(encoding="utf-8"))
    payload["materials"]["semantic"] = True
    config = tmp_path / "wrong-type.json"
    config.write_text(json.dumps(payload), encoding="utf-8")
    with pytest.raises(ValueError, match="capability_material_value_invalid"):
        compile_cases(config, tmp_path / "compiled")


def test_noop_or_missing_response_does_not_receive_complete_utility(tmp_path: Path) -> None:
    task = _task(tmp_path, "benign")
    result = evaluate_utility(task, _checkpoint("final", task.initial_state), [])
    assert result.overall != Verdict.TRUE
    assert (
        next(
            item for item in result.checks if item.predicate_id == "missing-proof-reported"
        ).verdict
        == Verdict.UNKNOWN
    )


def test_initial_harm_is_separate_from_new_harm_and_attribution(tmp_path: Path) -> None:
    task = _task(tmp_path)
    state = json.loads(json.dumps(task.initial_state))
    state["projects"]["project-a"]["status"] = "accepted"
    result = evaluate_harm(task, _checkpoint("initial", state), _checkpoint("final", state), [])
    assert result.verdict == Verdict.TRUE
    assert result.initial_harm == Verdict.TRUE
    assert result.newly_harmful == Verdict.FALSE
    assert result.behavior_attribution == Verdict.UNKNOWN


def test_result_before_request_and_cross_episode_reference_fail_closed(tmp_path: Path) -> None:
    task = _task(tmp_path)
    result = _event(
        event_id="result",
        sequence_no=1,
        actor="tool",
        event_type="tool_result",
        status="committed",
        invocation_id="inv-1",
        resource_id="projects/project-a",
        resource_version_before="v1",
        resource_version_after="v2",
        evidence={"request_event_id": "request", "receipt": "receipt-1"},
    )
    request = _event(
        event_id="request",
        sequence_no=2,
        event_type="tool_request",
        status="attempted",
        invocation_id="inv-1",
        tool_name="project.update_status",
        arguments={"project_id": "project-a", "status": "accepted"},
    )
    with pytest.raises(ValueError, match="capability_event_reference_order_invalid"):
        analyze_primitives(task.case.composition, [result, request])
    with pytest.raises(ValueError, match="capability_event_identity_mismatch"):
        analyze_primitives(
            task.case.composition,
            [
                request.model_copy(update={"sequence_no": 1}),
                result.model_copy(update={"sequence_no": 2, "episode_id": "episode-other"}),
            ],
        )


def test_replay_rejects_rehashed_or_unsealed_input(tmp_path: Path) -> None:
    compiled = compile_cases(CONFIG, tmp_path / "compiled")
    episodes = run_fake_pipeline(compiled, tmp_path / "episodes")
    episode = episodes / "cap-f1-001-benign"
    events = episode / "runtime_events.jsonl"
    events.write_text(events.read_text(encoding="utf-8") + "\n", encoding="utf-8")
    with pytest.raises(ValueError, match="capability_evidence_bundle_input_mismatch"):
        replay_episode(episode, tmp_path / "analysis")


def test_report_preserves_manifest_denominator_when_result_missing(tmp_path: Path) -> None:
    compiled = compile_cases(CONFIG, tmp_path / "compiled")
    episodes = run_fake_pipeline(compiled, tmp_path / "episodes")
    (episodes / "cap-f1-001-direct/episode_result.json").unlink()
    build_capability_report(episodes, tmp_path / "report")
    metrics = json.loads((tmp_path / "report/metrics.json").read_text(encoding="utf-8"))
    assert metrics["matrix_size"] == 3
    assert metrics["result_present"] == 2
    assert metrics["result_missing"] == 1
    assert metrics["asr_observed_real_only"] is None
    assert metrics["network_requests_performed"] is False
