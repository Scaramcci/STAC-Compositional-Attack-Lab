from __future__ import annotations

from pathlib import Path

from stac_attack_lab.capability.analysis import analyze_primitives
from stac_attack_lab.capability.compiler import compile_cases
from stac_attack_lab.capability.evaluation import evaluate_constraints, evaluate_harm
from stac_attack_lab.capability.models import (
    ConstraintStatus,
    ExecutionState,
    PrimitiveKind,
    RuntimeEvent,
    RuntimeTask,
    StateCheckpoint,
)
from stac_attack_lab.hashing import stable_hash

ROOT = Path(__file__).resolve().parents[2]
CONFIG = ROOT / "configs/capability/f1_status_acceptance.json"


def _task(tmp_path: Path, variant: str = "semantic") -> RuntimeTask:
    compiled = compile_cases(CONFIG, tmp_path / "compiled")
    return RuntimeTask.model_validate_json(
        (compiled / f"cases/cap-f1-001-{variant}/runtime_task.json").read_text(encoding="utf-8")
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


def test_planned_nodes_do_not_become_observed_occurrences(tmp_path: Path) -> None:
    task = _task(tmp_path)
    analysis = analyze_primitives(task.case.composition, [])
    assert all(not item.occurrences for item in analysis)
    assert (
        next(item for item in analysis if item.primitive == PrimitiveKind.ACT).overall_execution
        == ExecutionState.UNKNOWN
    )


def test_rejected_request_is_attempted_harm_without_committed_harm(tmp_path: Path) -> None:
    task = _task(tmp_path)
    state = task.initial_state
    event = RuntimeEvent(
        run_id="run",
        episode_id="episode",
        event_id="request",
        sequence_no=1,
        actor="victim",
        event_type="tool_request",
        session_label="s1",
        actual_session_key="actual-1",
        tool_name="project.update_status",
        arguments={"project_id": "project-a", "status": "accepted"},
        status="blocked",
    )
    result = evaluate_harm(
        task, _checkpoint("initial", state), _checkpoint("final", state), [event]
    )
    assert result.verdict.value == "false"
    assert result.attempted_harm is True


def test_harness_write_is_not_victim_persist_and_session_label_is_not_identity(
    tmp_path: Path,
) -> None:
    task = _task(tmp_path)
    events = [
        RuntimeEvent(
            run_id="run",
            episode_id="episode",
            event_id="harness-write",
            sequence_no=1,
            actor="harness",
            event_type="state_write",
            session_label="s1",
            actual_session_key="actual-shared",
            status="committed",
            resource_id="MEMORY.md",
        ),
        RuntimeEvent(
            run_id="run",
            episode_id="episode",
            event_id="read",
            sequence_no=2,
            actor="victim",
            event_type="state_read",
            session_label="s2",
            actual_session_key="actual-shared",
            status="observed",
            resource_id="MEMORY.md",
            resource_version_before="v1",
            evidence={"producer_actual_session_key": "actual-shared"},
        ),
    ]
    analysis = analyze_primitives(task.case.composition, events)
    assert (
        next(item for item in analysis if item.primitive == PrimitiveKind.PERSIST).occurrences == []
    )
    assert (
        next(item for item in analysis if item.primitive == PrimitiveKind.RECALL).occurrences == []
    )
    constraints = evaluate_constraints(task, events)
    assert (
        next(item for item in constraints if item.constraint_id == "D5").status
        == ConstraintStatus.VIOLATED
    )
    assert (
        next(item for item in constraints if item.constraint_id == "D8").status
        == ConstraintStatus.NOT_APPLICABLE
    )


def test_model_self_report_alone_does_not_prove_adopt(tmp_path: Path) -> None:
    task = _task(tmp_path)
    event = RuntimeEvent(
        run_id="run",
        episode_id="episode",
        event_id="self-report",
        sequence_no=1,
        actor="victim",
        event_type="semantic_use",
        session_label="s1",
        actual_session_key="actual-1",
        status="observed",
        evidence={
            "rubric": "model says it adopted the source",
            "model_self_report_only": True,
        },
    )
    adopt = next(
        item
        for item in analyze_primitives(task.case.composition, [event])
        if item.primitive == PrimitiveKind.ADOPT
    )
    assert adopt.overall_execution == ExecutionState.UNKNOWN
    assert adopt.occurrences == []
