from __future__ import annotations

import json
from pathlib import Path

from stac_attack_lab.capability.analysis import analyze_primitives
from stac_attack_lab.capability.evaluation import evaluate_constraints, evaluate_harm
from stac_attack_lab.capability.models import (
    ConstraintStatus,
    EpisodeResult,
    RuntimeEvent,
    RuntimeTask,
    StateCheckpoint,
    Verdict,
)
from stac_attack_lab.environments.safeclaw.capability_adapter import (
    CapabilitySafeClawAdapter,
    FakeCapabilityTransport,
)
from stac_attack_lab.environments.safeclaw.redaction import scan_tree
from stac_attack_lab.hashing import stable_hash


def _load_events(path: Path) -> list[RuntimeEvent]:
    events = [
        RuntimeEvent.model_validate_json(line)
        for line in path.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]
    if [event.sequence_no for event in events] != list(range(1, len(events) + 1)):
        raise ValueError("capability_event_sequence_not_contiguous")
    if len({event.event_id for event in events}) != len(events):
        raise ValueError("capability_event_id_duplicate")
    if (
        len({event.episode_id for event in events}) > 1
        or len({event.run_id for event in events}) > 1
    ):
        raise ValueError("capability_event_identity_mismatch")
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
    constraints = evaluate_constraints(task, events)
    primitives = analyze_primitives(task.case.composition, events)
    unknown_constraints = [
        item.constraint_id for item in constraints if item.status == ConstraintStatus.UNKNOWN
    ]
    utility = (
        Verdict.FALSE
        if harm.verdict == Verdict.TRUE
        else (Verdict.TRUE if harm.verdict == Verdict.FALSE else Verdict.UNKNOWN)
    )
    result_payload = {
        "episode_id": f"episode-{task.case.case_id}",
        "case_id": task.case.case_id,
        "variant": task.case.variant,
        "execution_status": "completed",
        "official_verdict": Verdict.NOT_APPLICABLE,
        "harm": harm,
        "benign_utility": utility,
        "goal_fidelity": utility,
        "constraints": constraints,
        "pp_success": (
            harm.verdict == Verdict.TRUE
            and all(item.status == ConstraintStatus.SATISFIED for item in constraints)
        ),
        "primitive_analysis": primitives,
        "residual_compromise": Verdict.FALSE,
        "missing_information": [f"constraint:{item}" for item in unknown_constraints],
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
    for ref in manifest["case_refs"]:
        task = RuntimeTask.model_validate_json(
            (compilation_root / str(ref)).read_text(encoding="utf-8")
        )
        episode_root = output_root / task.case.case_id
        adapter = CapabilitySafeClawAdapter(
            FakeCapabilityTransport(outcome=outcomes[task.case.variant.value])
        )
        adapter.run(task, episode_root, run_id=output_root.name)
        results.append(_write_result(episode_root, task))
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


def replay_episode(episode_root: Path, output_root: Path) -> EpisodeResult:
    output_root.mkdir(parents=True, exist_ok=False)
    task = RuntimeTask.model_validate_json(
        (episode_root / "runtime_task.json").read_text(encoding="utf-8")
    )
    for relative in (
        "runtime_events.jsonl",
        "checkpoints/initial.json",
        "checkpoints/final.json",
    ):
        source = episode_root / relative
        target = output_root / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(source.read_bytes())
    (output_root / "runtime_task.json").write_text(
        task.model_dump_json(indent=2) + "\n", encoding="utf-8"
    )
    return _write_result(output_root, task)
