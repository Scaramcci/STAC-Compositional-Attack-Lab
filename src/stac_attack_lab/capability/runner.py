from __future__ import annotations

import json
from pathlib import Path
from typing import Protocol, cast

from stac_attack_lab.capability.analysis import analyze_primitives, validate_runtime_events
from stac_attack_lab.capability.evaluation import (
    evaluate_constraints,
    evaluate_harm,
    evaluate_residual,
    evaluate_utility,
)
from stac_attack_lab.capability.evidence import EVIDENCE_FILES, verify_episode_evidence
from stac_attack_lab.capability.models import (
    BatchManifest,
    BatchUnit,
    ConstraintStatus,
    EpisodeResult,
    ReplayAnalysisManifest,
    RuntimeEvent,
    RuntimeTask,
    StateCheckpoint,
    Verdict,
)
from stac_attack_lab.environments.safeclaw.capability_adapter import (
    FakeCapabilityTransport,
    FixtureCapabilitySafeClawAdapter,
)
from stac_attack_lab.environments.safeclaw.redaction import scan_tree
from stac_attack_lab.hashing import file_hash, stable_hash
from stac_attack_lab.interactions.base import CollectionBudget


def _hashed_model(
    model_type: type[BatchManifest] | type[ReplayAnalysisManifest], payload: dict[str, object]
) -> BatchManifest | ReplayAnalysisManifest:
    schema_version = (
        "capability-batch/1.0" if model_type is BatchManifest else "capability-replay-analysis/1.0"
    )
    canonical = {"schema_version": schema_version, **payload}
    return model_type.model_validate({**canonical, "manifest_hash": stable_hash(canonical)})


class CapabilityEpisodeAdapter(Protocol):
    def run(
        self,
        task: RuntimeTask,
        output_root: Path,
        *,
        run_id: str,
        budget: CollectionBudget,
    ) -> tuple[list[RuntimeEvent], StateCheckpoint, StateCheckpoint]: ...


def _write_batch_manifest(
    output_root: Path,
    *,
    batch_id: str,
    source_manifest_hash: str,
    units: list[BatchUnit],
) -> BatchManifest:
    payload: dict[str, object] = {
        "batch_id": batch_id,
        "source_compilation_manifest_hash": source_manifest_hash,
        "units": [item.model_dump(mode="json") for item in units],
        "provider_ledger_ref": "*/provider_attempt_ledger.jsonl",
    }
    batch = cast(BatchManifest, _hashed_model(BatchManifest, payload))
    (output_root / "batch_manifest.json").write_text(
        batch.model_dump_json(indent=2) + "\n", encoding="utf-8"
    )
    return batch


def _load_events(path: Path) -> list[RuntimeEvent]:
    events = [
        RuntimeEvent.model_validate_json(line)
        for line in path.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]
    validate_runtime_events(events)
    return events


def _write_result(episode_root: Path, task: RuntimeTask) -> EpisodeResult:
    events = _load_events(episode_root / "runtime_events.jsonl")
    initial = StateCheckpoint.model_validate_json(
        (episode_root / "checkpoints/initial.json").read_text(encoding="utf-8")
    )
    final = StateCheckpoint.model_validate_json(
        (episode_root / "checkpoints/final.json").read_text(encoding="utf-8")
    )
    harm = evaluate_harm(task, initial, final, events)
    utility = evaluate_utility(task, final, events)
    residual, residual_reason = evaluate_residual(task, final)
    constraints = evaluate_constraints(task, events)
    primitives = analyze_primitives(task.case.composition, events)
    unknown_constraints = [
        item.constraint_id for item in constraints if item.status == ConstraintStatus.UNKNOWN
    ]
    review_path = episode_root / "runtime_review.json"
    review = json.loads(review_path.read_text(encoding="utf-8")) if review_path.is_file() else {}
    if review.get("status") == "failed" or review.get("cleanup_error"):
        execution_status = "error"
    elif (
        review.get("status") not in {"completed", "synthetic_contract_check"}
        or final.capture_status != "observed"
        or initial.capture_status != "observed"
    ):
        execution_status = "partial"
    elif any(event.status == "error" for event in events):
        execution_status = "error"
    elif (requests := [event for event in events if event.event_type == "tool_request"]) and all(
        event.status == "blocked" for event in requests
    ):
        execution_status = "blocked"
    else:
        execution_status = "completed"
    result_payload = {
        "episode_id": f"episode-{task.case.case_id}",
        "case_id": task.case.case_id,
        "variant": task.case.variant,
        "execution_status": execution_status,
        "official_verdict": Verdict.NOT_APPLICABLE,
        "harm": harm,
        "benign_utility": utility.overall,
        "goal_fidelity": utility.overall,
        "utility": utility,
        "constraints": constraints,
        "pp_success": (
            harm.verdict == Verdict.TRUE
            and all(item.status == ConstraintStatus.SATISFIED for item in constraints)
        ),
        "primitive_analysis": primitives,
        "residual_compromise": residual,
        "residual_reason_code": residual_reason,
        "missing_information": [f"constraint:{item}" for item in unknown_constraints]
        + (["runtime_review_incomplete"] if execution_status != "completed" else []),
        "event_count": len(events),
    }
    hash_payload = EpisodeResult.model_construct(
        _fields_set=set(result_payload), **result_payload
    ).model_dump(mode="json")
    result = EpisodeResult.model_validate(
        {**result_payload, "report_hash": stable_hash(hash_payload)}
    )
    (episode_root / "harm_result.json").write_text(
        harm.model_dump_json(indent=2) + "\n", encoding="utf-8"
    )
    (episode_root / "constraint_report.json").write_text(
        json.dumps([item.model_dump(mode="json") for item in constraints], indent=2, sort_keys=True)
        + "\n",
        encoding="utf-8",
    )
    (episode_root / "primitive_analysis.json").write_text(
        json.dumps([item.model_dump(mode="json") for item in primitives], indent=2, sort_keys=True)
        + "\n",
        encoding="utf-8",
    )
    (episode_root / "episode_result.json").write_text(
        result.model_dump_json(indent=2) + "\n", encoding="utf-8"
    )
    (episode_root / "official_result.json").write_text(
        json.dumps(
            {
                "verdict": "not_applicable",
                "reason_code": "safeclaw_derived_extension_fixture",
                "official_evaluator_invoked": False,
            },
            indent=2,
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )
    (episode_root / "utility_result.json").write_text(
        json.dumps(
            {
                "benign_utility": result.benign_utility.value,
                "goal_fidelity": result.goal_fidelity.value,
                "checks": [item.model_dump(mode="json") for item in result.utility.checks],
                "reason_code": result.utility.reason_code,
            },
            indent=2,
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )
    return result


def run_fake_pipeline(compilation_root: Path, output_root: Path) -> Path:
    manifest = json.loads((compilation_root / "manifest.json").read_text(encoding="utf-8"))
    output_root.mkdir(parents=True, exist_ok=False)
    results: list[EpisodeResult] = []
    outcomes = {
        "benign": "state_change",
        "direct": "tool_rejected",
        "semantic": "missing_adopt_evidence",
    }
    tasks = [
        RuntimeTask.model_validate_json((compilation_root / str(ref)).read_text(encoding="utf-8"))
        for ref in manifest["case_refs"]
    ]
    units = [
        BatchUnit(
            unit_id=f"unit-{task.case.case_id}-r0",
            case_id=task.case.case_id,
            variant=task.case.variant,
            repeat_index=0,
            transport="fixture",
            stage="preregistered",
            result_ref=f"{task.case.case_id}/episode_result.json",
            reason_code="unit_preregistered",
        )
        for task in tasks
    ]

    def write_batch() -> None:
        _write_batch_manifest(
            output_root,
            batch_id=output_root.name,
            source_manifest_hash=str(manifest["manifest_hash"]),
            units=units,
        )

    write_batch()
    for index, task in enumerate(tasks):
        episode_root = output_root / task.case.case_id
        adapter = FixtureCapabilitySafeClawAdapter(
            FakeCapabilityTransport(outcome=outcomes[task.case.variant.value])
        )
        try:
            adapter.run(task, episode_root, run_id=output_root.name)
            result = _write_result(episode_root, task)
            results.append(result)
            units[index] = units[index].model_copy(
                update={
                    "stage": result.execution_status,
                    "reason_code": "episode_result_persisted",
                }
            )
        except Exception as exc:
            episode_root.mkdir(parents=True, exist_ok=True)
            (episode_root / "episode_error.json").write_text(
                json.dumps(
                    {"stage": "fixture_execution", "reason_code": str(exc)},
                    indent=2,
                    sort_keys=True,
                )
                + "\n",
                encoding="utf-8",
            )
            units[index] = units[index].model_copy(
                update={"stage": "error", "reason_code": f"fixture_execution_failed:{exc}"}
            )
        write_batch()
    findings = scan_tree(output_root)
    if findings:
        raise ValueError("capability_demo_secret_scan_failed:" + ",".join(findings))
    summary = {
        "schema_version": "capability-offline-demo/1.0",
        "source_compilation_manifest_hash": manifest["manifest_hash"],
        "episodes": [
            {
                "case_id": result.case_id,
                "variant": result.variant.value,
                "harm": result.harm.verdict.value,
                "attempted_harm": result.harm.attempted_harm,
                "pp_success": result.pp_success,
                "result_ref": f"{result.case_id}/episode_result.json",
            }
            for result in results
        ],
        "network_requests_performed": False,
        "official_outcome": "not_applicable_extension_fixture",
        "runtime_review": "synthetic_contract_check",
    }
    (output_root / "summary.json").write_text(
        json.dumps(summary, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    return output_root


def run_safeclaw_capability_episode(
    task: RuntimeTask,
    adapter: CapabilityEpisodeAdapter,
    output_root: Path,
    *,
    batch_id: str,
    source_compilation_manifest_hash: str,
    budget: CollectionBudget,
    transport: str = "safeclaw_live",
) -> EpisodeResult:
    output_root.mkdir(parents=True, exist_ok=False)
    unit = BatchUnit(
        unit_id=f"unit-{task.case.case_id}-r0",
        case_id=task.case.case_id,
        variant=task.case.variant,
        repeat_index=0,
        transport=transport,  # type: ignore[arg-type]
        stage="preregistered",
        result_ref=f"{task.case.case_id}/episode_result.json",
        reason_code="unit_preregistered",
    )
    _write_batch_manifest(
        output_root,
        batch_id=batch_id,
        source_manifest_hash=source_compilation_manifest_hash,
        units=[unit],
    )
    episode_root = output_root / task.case.case_id
    try:
        adapter.run(task, episode_root, run_id=batch_id, budget=budget)
        result = _write_result(episode_root, task)
        unit = unit.model_copy(
            update={"stage": result.execution_status, "reason_code": "episode_result_persisted"}
        )
    except Exception as exc:
        unit = unit.model_copy(
            update={"stage": "error", "reason_code": f"safeclaw_execution_failed:{exc}"}
        )
        _write_batch_manifest(
            output_root,
            batch_id=batch_id,
            source_manifest_hash=source_compilation_manifest_hash,
            units=[unit],
        )
        raise
    _write_batch_manifest(
        output_root,
        batch_id=batch_id,
        source_manifest_hash=source_compilation_manifest_hash,
        units=[unit],
    )
    return result


def replay_episode(episode_root: Path, output_root: Path) -> EpisodeResult:
    bundle = verify_episode_evidence(episode_root)
    output_root.mkdir(parents=True, exist_ok=False)
    task = RuntimeTask.model_validate_json(
        (episode_root / "runtime_task.json").read_text(encoding="utf-8")
    )
    for relative in EVIDENCE_FILES:
        source = episode_root / relative
        target = output_root / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(source.read_bytes())
    (output_root / "evidence_bundle.json").write_bytes(
        (episode_root / "evidence_bundle.json").read_bytes()
    )
    result = _write_result(output_root, task)
    output_hashes = {
        name: file_hash(output_root / name)
        for name in (
            "harm_result.json",
            "constraint_report.json",
            "primitive_analysis.json",
            "episode_result.json",
            "utility_result.json",
        )
    }
    payload: dict[str, object] = {
        "analysis_id": output_root.name,
        "source_bundle_hash": bundle.bundle_hash,
        "source_input_hashes": bundle.input_hashes,
        "processing_source_hashes": {
            "runner.py": file_hash(Path(__file__)),
            "analysis.py": file_hash(Path(__file__).with_name("analysis.py")),
            "evaluation.py": file_hash(Path(__file__).with_name("evaluation.py")),
        },
        "output_hashes": output_hashes,
    }
    analysis_manifest = _hashed_model(ReplayAnalysisManifest, payload)
    (output_root / "analysis_manifest.json").write_text(
        analysis_manifest.model_dump_json(indent=2) + "\n", encoding="utf-8"
    )
    return result
