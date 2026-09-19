from __future__ import annotations

import json
import os
import subprocess
import uuid
from datetime import UTC, datetime
from pathlib import Path
from types import SimpleNamespace
from typing import Any

from stac_attack_lab.hashing import file_hash, stable_hash


def _read_bridge_replay_records(path: Path) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    records: list[dict[str, Any]] = []
    malformed: list[dict[str, Any]] = []
    for line_number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
        if not line.strip():
            continue
        try:
            value = json.loads(line)
        except json.JSONDecodeError as exc:
            malformed.append({"line": line_number, "reason": str(exc)})
            continue
        if not isinstance(value, dict):
            malformed.append({"line": line_number, "reason": "row_not_object"})
            continue
        records.append(value)
    diagnostic = {
        "line_count": len(records) + len(malformed),
        "valid_line_count": len(records),
        "malformed_line_count": len(malformed),
        "malformed_lines": malformed,
        "integrity_status": "passed" if not malformed else "failed",
    }
    if malformed:
        raise ValueError("bridge_replay_malformed_jsonl:" + json.dumps(diagnostic, sort_keys=True))
    return records, diagnostic


def _materialize_bridge_replay(
    root: Path, run_root: Path, bridge_responses: Path, analysis_id: str
) -> tuple[Path, dict[str, Any]]:
    from stac_attack_lab.execution.sample_generation import (
        _record_collection_stage,
        load_sample_generation_config,
    )
    from stac_attack_lab.interactions.base import CollectedInteraction, SourceInteractionTask
    from stac_attack_lab.interactions.collector import _write_collected
    from stac_attack_lab.interactions.models import ConstructionManifest
    from stac_attack_lab.interactions.safeclaw_collection import replay_bridge_action_responses
    from stac_attack_lab.primitives.formal_registry import load_formal_registry

    records, diagnostic = _read_bridge_replay_records(bridge_responses)
    if not records:
        raise ValueError("bridge_replay_empty")
    events, checkpoints, sessions = replay_bridge_action_responses(records, task_id="bridge-replay")
    config_path = run_root / "runtime_config.json"
    config = load_sample_generation_config(config_path)
    replay_config = config.model_copy(
        update={
            "pipeline_id": analysis_id,
            "execution_enabled": False,
            "source_task_ids": ["bridge-replay"],
        }
    )
    collection = run_root / "analyses" / analysis_id / "bridge-replay-collection"
    collection.mkdir(parents=True, exist_ok=False)
    task = SourceInteractionTask(
        source_task_id="bridge-replay",
        source_split="synthetic",
        public_summary="Offline replay of recorded bridge action/response boundaries.",
        environment_family="safeclaw_openclaw",
    )
    manifest = ConstructionManifest(
        acquisition_mode="adversarial_trace",
        construction_objective_id=config.construction_objective_id,
        public_attack_goal=config.public_attack_goal,
        allowed_delivery_surfaces=config.allowed_delivery_surfaces,
        required_trust_boundary_crossings=config.required_trust_boundary_crossings,
        public_terminal_predicate_ids=config.public_terminal_predicate_ids,
        safety_constraint_ids=config.safety_constraint_ids,
        construction_attacker_model_hash=config.construction_attacker_model_hash,
        construction_prompt_hash=config.construction_prompt_hash,
    )
    trajectory_id = (
        f"trajectory-bridge-replay-{stable_hash([analysis_id, file_hash(bridge_responses)])[:16]}"
    )
    collected = CollectedInteraction(
        source_task=task,
        episode_id=f"episode-{analysis_id}",
        session_ids=sessions,
        source_events=events,
        checkpoints=checkpoints,
        model_hashes={"victim": config.victim_model_hash or "unknown"},
        config_hash=stable_hash(replay_config.model_dump(mode="json")),
        status="complete",
        provenance={
            "mode": "bridge_driver_replay",
            "replay_version": "1",
            "bridge_input_sha256": file_hash(bridge_responses),
            "missing_or_compatibility_notes": (
                "strong consumption remains unavailable unless deterministic "
                "edge instrumentation is present"
            ),
        },
    )
    adapter = SimpleNamespace(
        adapter_id="safeclaw_bridge_driver_replay",
        adapter_version="1.0.0",
        environment_version="pinned-safeclaw-offline-replay",
    )
    trajectory_path = _write_collected(
        collection, adapter, collected, trajectory_id, config.effective_seeds[0], manifest
    )
    collection_manifest = {
        "schema_version": "2.0",
        "collection_id": analysis_id,
        "adapter_id": adapter.adapter_id,
        "adapter_version": adapter.adapter_version,
        "acquisition_mode": "adversarial_trace",
        "construction_attacker_id": "recorded_bridge_actions",
        "plan_hash": stable_hash(
            {"analysis_id": analysis_id, "input": file_hash(bridge_responses)}
        ),
        "trajectory_count": 1,
        "failure_count": 0,
        "formal_exclusion_hash": stable_hash(sorted(config.formal_excluded_task_ids)),
        "trajectory_hashes": {trajectory_id: file_hash(trajectory_path)},
    }
    (collection / "collection_manifest.json").write_text(
        json.dumps(collection_manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    registry = load_formal_registry(root / config.registry_path)
    _record_collection_stage(collection, replay_config, registry.registry_hash)
    diagnostic.update({"mode": "bridge_driver_replay", "source_event_count": len(events)})
    return collection, diagnostic


def _git(root: Path, *args: str) -> str:
    try:
        return subprocess.check_output(["git", *args], cwd=root, text=True).strip()
    except (OSError, subprocess.CalledProcessError):
        return "unknown"


def _controlled_source_hash(root: Path) -> str:
    return stable_hash(
        {
            str(path.relative_to(root)): file_hash(path)
            for base in (root / "src", root / "integrations" / "safeclaw", root / "scripts")
            for path in sorted(base.rglob("*"))
            if path.is_file() and (path.suffix in {".py", ".sh"} or path.name == "README.md")
        }
    )


def _ledger_derived_budget_summary(collection: Path | None) -> dict[str, Any]:
    """Project recorded request counts, preserving unknown/corrupt as non-zero-free states."""
    if collection is None:
        return {"status": "unknown", "reason_code": "collection_unavailable"}
    trajectories = sorted(collection.glob("trajectories/*/raw_trajectory.json"))
    if len(trajectories) != 1:
        return {
            "status": "unknown",
            "reason_code": "single_trajectory_budget_summary_required",
        }
    try:
        raw = json.loads(trajectories[0].read_text(encoding="utf-8"))
        provenance = raw["provenance"]
        keys = {
            "attacker": "collection_attacker_request_count",
            "victim": "victim_provider_http_request_count",
            "embedding": "embedding_http_request_count",
        }
        counts = {role: int(provenance[key]) for role, key in keys.items()}
        if any(value < 0 for value in counts.values()):
            raise ValueError("negative_count")
    except (OSError, ValueError, TypeError, KeyError, json.JSONDecodeError) as exc:
        return {
            "status": "unknown",
            "reason_code": "ledger_derived_counts_missing_or_invalid",
            "detail": str(exc)[:200],
        }
    return {
        "status": "observed",
        "source": "sealed_trajectory_ledger_derived_provenance",
        "request_counts": counts,
    }


def prepare_revalidation(root: Path, template: Path, run_id: str | None = None) -> Path:
    """Create a fresh disabled run directory without reading historical runs."""
    if run_id is None:
        import datetime
        import uuid

        run_id = (
            "construction-cross-session-"
            + datetime.datetime.now(datetime.UTC).strftime("%Y%m%d-%H%M%S")
            + "-"
            + uuid.uuid4().hex[:8]
        )
    if Path(run_id).name != run_id or not run_id:
        raise ValueError("invalid_revalidation_run_id")
    run_root = root / "experiments" / "runs" / run_id
    run_root.mkdir(parents=True, exist_ok=False)
    config = json.loads(template.read_text(encoding="utf-8"))
    if config.get("execution_enabled") is not False:
        raise ValueError("revalidation_template_must_be_disabled")
    config["pipeline_id"] = run_id
    config["output_root"] = str(run_root)
    config["execution_enabled"] = False
    (run_root / "runtime_config.json").write_text(
        json.dumps(config, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    from stac_attack_lab.execution.sample_generation import load_sample_generation_config

    load_sample_generation_config(run_root / "runtime_config.json")
    provenance = {
        "run_id": run_id,
        "head": _git(root, "rev-parse", "HEAD"),
        "dirty": bool(_git(root, "status", "--porcelain")),
        "config_sha256": file_hash(run_root / "runtime_config.json"),
        "template_sha256": file_hash(template),
        "prepare_config_sha256": file_hash(run_root / "runtime_config.json"),
        "controlled_source_sha256": _controlled_source_hash(root),
        "command": "stac-attack-lab revalidation prepare",
        "execution_enabled": False,
    }
    (run_root / "provenance.json").write_text(
        json.dumps(provenance, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    (run_root / "configuration_review.json").write_text(
        json.dumps(
            {
                "run_id": run_id,
                "execution_status": "disabled",
                "live_authorization": "not_granted",
                "checks": {"execution_enabled": False},
            },
            indent=2,
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )
    return run_root


def launch_live_revalidation(root: Path, run_root: Path, *, authorized: bool) -> dict[str, Any]:
    """Launch exactly once inside one prepared run after explicit authorization."""
    if not authorized:
        raise ValueError("live_authorization_flag_required")
    config_path = run_root / "runtime_config.json"
    try:
        config_data = json.loads(config_path.read_text(encoding="utf-8"))
        if config_data.get("execution_enabled") is not True:
            raise ValueError("live_execution_disabled_in_runtime_config")
        if run_root.resolve() != (root / "experiments" / "runs" / run_root.name).resolve():
            raise ValueError("revalidation_run_root_outside_allowed_directory")
        if config_data.get("pipeline_id") != run_root.name:
            raise ValueError("revalidation_pipeline_id_mismatch")
        if Path(str(config_data.get("output_root"))).resolve() != run_root.resolve():
            raise ValueError("revalidation_output_root_mismatch")
    except Exception as exc:
        failure = {
            "execution_status": "failed_before_launch_reservation",
            "pipeline_execution": {"status": "not_started"},
            "execution_authorization": {"status": "explicit_command_flag"},
            "stages": [
                {"stage": "configuration_binding", "status": "failed", "reason": str(exc)[:500]}
            ],
            "official_outcome": "not_evaluated",
        }
        failure_path = run_root / f"launch_validation_failure-{uuid.uuid4().hex[:8]}.json"
        failure_path.write_text(
            json.dumps(failure, indent=2, sort_keys=True) + "\n", encoding="utf-8"
        )
        raise
    marker = run_root / "launch.marker"
    descriptor = os.open(marker, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        os.write(descriptor, b"live launch reserved\n")
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    from stac_attack_lab.execution.sample_generation import (
        collect_sample_interactions,
        load_sample_generation_config,
    )
    from stac_attack_lab.execution.sample_preflight import run_sample_collection_preflight

    summary: dict[str, Any]
    stages: list[dict[str, Any]] = []
    collection: Path | None = None
    current_stage = "execution_snapshot"
    try:
        prepare_provenance = json.loads((run_root / "provenance.json").read_text(encoding="utf-8"))
        live_review = {
            "run_id": run_root.name,
            "execution_status": "authorized_pending_launch",
            "live_authorization": "explicit_command_flag",
            "checks": {
                "execution_enabled": True,
                "run_root_identity": True,
                "pipeline_identity": True,
                "output_root_identity": True,
                "launch_reservation_acquired": True,
            },
            "prepare_config_sha256": prepare_provenance.get("prepare_config_sha256"),
            "execution_config_sha256": file_hash(config_path),
            "prepare_source_sha256": prepare_provenance.get("controlled_source_sha256"),
            "execution_source_sha256": _controlled_source_hash(root),
            "head": _git(root, "rev-parse", "HEAD"),
            "dirty": bool(_git(root, "status", "--porcelain")),
        }
        (run_root / "configuration_review.live.json").write_text(
            json.dumps(live_review, indent=2, sort_keys=True) + "\n", encoding="utf-8"
        )
        stages.append({"stage": "execution_snapshot", "status": "passed"})
        current_stage = "configuration_load"
        config = load_sample_generation_config(config_path)
        stages.append({"stage": "configuration_load", "status": "passed"})
        current_stage = "preflight"
        preflight = run_sample_collection_preflight(root, config)
        if not preflight.passed:
            raise RuntimeError("revalidation_live_preflight_failed")
        stages.append({"stage": "preflight", "status": "passed"})
        current_stage = "collection"
        collection = collect_sample_interactions(root, config)
        stages.append({"stage": "collection", "status": "passed", "output": str(collection)})
        current_stage = "offline"
        offline = offline_revalidation(root, run_root, Path(collection))
    except Exception as exc:
        stages.append({"stage": current_stage, "status": "failed", "reason": str(exc)[:500]})
        candidates = sorted(run_root.glob("**/collection_stage_manifest.json"))
        if collection is None and len(candidates) == 1:
            collection = candidates[0].parent
        offline = None
        if collection is not None and (collection / "collection_stage_manifest.json").is_file():
            try:
                offline = offline_revalidation(root, run_root, collection)
                stages.append(
                    {
                        "stage": "offline_after_collection_error",
                        "status": offline.get("overall_status"),
                    }
                )
            except Exception as followup:
                stages.append(
                    {
                        "stage": "offline_after_collection_error",
                        "status": "failed",
                        "reason": str(followup)[:500],
                    }
                )
        summary = {
            "execution_status": "failed",
            "reason": str(exc)[:500],
            "launch_marker": str(marker),
            "stages": stages,
            "partial_collection": str(collection) if collection else None,
            "offline_status": offline.get("overall_status")
            if isinstance(offline, dict)
            else "blocked",
            "budget_accounting": _ledger_derived_budget_summary(collection),
            "official_outcome": "not_evaluated",
        }
        (run_root / "live_summary.json").write_text(
            json.dumps(summary, indent=2, sort_keys=True) + "\n", encoding="utf-8"
        )
        raise
    assert offline is not None
    summary = {
        "execution_status": (
            "completed" if offline.get("overall_status") == "passed" else "completed_offline_failed"
        ),
        "collection": str(collection),
        "launch_marker": str(marker),
        "offline_status": offline.get("overall_status"),
        "offline_summary": str(run_root / "offline_summary.json"),
        "official_outcome": "not_evaluated",
        "stages": stages,
        "budget_accounting": _ledger_derived_budget_summary(collection),
    }
    (run_root / "live_summary.json").write_text(
        json.dumps(summary, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    return summary


def offline_revalidation(
    root: Path,
    run_root: Path,
    collection: Path | None = None,
    library: Path | None = None,
    bridge_responses: Path | None = None,
) -> dict[str, Any]:
    """Run only local mine/audit/admission stages and preserve stage outcomes."""
    analysis_id = (
        "offline-" + datetime.now(UTC).strftime("%Y%m%d-%H%M%S") + "-" + uuid.uuid4().hex[:8]
    )
    analysis_root = run_root / "analyses" / analysis_id
    analysis_root.mkdir(parents=True, exist_ok=False)
    result: dict[str, Any] = {
        "analysis_id": analysis_id,
        "analysis_root": str(analysis_root),
        "mode": "bridge_driver_replay" if bridge_responses is not None else "collection_reanalysis",
        "pipeline_execution": {"status": "completed"},
        "input_integrity": {"status": "unknown"},
        "structural_admission": {"status": "not_run"},
        "execution_authorization": {"status": "absent"},
        "execution_status": "not_executed",
        "accepted": {"count": None, "audit_passed": None},
        "admission": "not_run",
        "runtime_review": {"status": "pending"},
        "official_outcome": "not_evaluated",
        "stages": [],
    }
    bridge_diagnostic: dict[str, Any] | None = None
    if bridge_responses is not None:
        try:
            collection, bridge_diagnostic = _materialize_bridge_replay(
                root, run_root, bridge_responses, analysis_id
            )
            result["stages"].append(
                {"stage": "bridge_driver_replay", "status": "passed", "output": str(collection)}
            )
            result["input_integrity"] = {"status": "passed"}
        except Exception as exc:
            result["pipeline_execution"] = {"status": "completed_with_failed_stage"}
            result["input_integrity"] = {"status": "failed"}
            result["stages"].append(
                {"stage": "bridge_driver_replay", "status": "failed", "reason": str(exc)[:2000]}
            )
            result["overall_status"] = "error"
            (analysis_root / "offline_summary.json").write_text(
                json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8"
            )
            (run_root / "offline_summary.json").write_text(
                json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8"
            )
            return result
    if collection is None:
        candidates = sorted(run_root.glob("single-construction/interactions/raw/*"))
        if len(candidates) > 1:
            result["stages"].append(
                {"stage": "input", "status": "failed", "reason_code": "collection_ambiguous"}
            )
            result["overall_status"] = "error"
            (analysis_root / "offline_summary.json").write_text(
                json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8"
            )
            return result
        collection = candidates[0] if candidates else None
    if collection is None or not collection.exists():
        result["stages"].append(
            {"stage": "mine", "status": "blocked", "reason_code": "collection_missing"}
        )
        result["input_integrity"] = {"status": "failed"}
        result["overall_status"] = "error"
        (run_root / "offline_summary.json").write_text(
            json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8"
        )
        return result
    input_hashes = {
        str(path.resolve()): file_hash(path)
        for path in sorted(collection.rglob("*"))
        if path.is_file()
    }
    config_path = run_root / "runtime_config.json"
    if config_path.is_file():
        input_hashes[str(config_path.resolve())] = file_hash(config_path)
    if bridge_responses is not None:
        input_hashes[str(bridge_responses.resolve())] = file_hash(bridge_responses)
        (analysis_root / "bridge_replay_diagnostics.json").write_text(
            json.dumps(bridge_diagnostic, indent=2, sort_keys=True) + "\n", encoding="utf-8"
        )
    offline_provenance = {
        "command": "stac-attack-lab revalidation offline",
        "head": _git(root, "rev-parse", "HEAD"),
        "dirty": bool(_git(root, "status", "--porcelain")),
        "input_sha256": input_hashes,
        "processing_source_sha256": stable_hash(
            {
                str(path.relative_to(root)): file_hash(path)
                for path in sorted((root / "src" / "stac_attack_lab").rglob("*.py"))
            }
        ),
        "bridge_diagnostic": bridge_diagnostic,
    }
    offline_provenance.update(
        {
            "analysis_id": analysis_id,
            "mode": result["mode"],
            "parameters": {
                "collection": str(collection.resolve()),
                "bridge_responses": str(bridge_responses.resolve()) if bridge_responses else None,
            },
            "bridge_source_sha256": file_hash(
                root / "integrations/safeclaw/construction_bridge.py"
            ),
            "driver_source_sha256": file_hash(
                root / "src/stac_attack_lab/interactions/safeclaw_collection.py"
            ),
            "replay_version": "1",
            "cache_reused": False,
        }
    )
    (analysis_root / "offline_provenance.json").write_text(
        json.dumps(offline_provenance, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    from stac_attack_lab.execution.sample_generation import (
        audit_sample_library_stage,
        mine_sample_collection,
    )

    mining_root = analysis_root / "offline-mining"
    library_path: Path | None
    try:
        library_path = Path(mine_sample_collection(root, collection, output_root=mining_root))
        result["stages"].append({"stage": "mine", "status": "passed", "output": str(library_path)})
    except Exception as exc:  # diagnostics must survive partial/corrupt ledgers
        result["stages"].append({"stage": "mine", "status": "failed", "reason": str(exc)[:500]})
        library_path = library
    if library_path is not None and library_path.exists():
        try:
            audit = audit_sample_library_stage(library_path)
            result["stages"].append(
                {
                    "stage": "audit",
                    "status": "passed" if audit.passed else "failed",
                    "errors": audit.error_codes,
                }
            )
            mining_manifest = json.loads(
                (library_path.parent / "mining_stage_manifest.json").read_text(encoding="utf-8")
            )
            result["accepted"] = {
                "count": mining_manifest.get("accepted_count"),
                "audit_passed": audit.passed,
            }
        except Exception as exc:
            result["stages"].append(
                {"stage": "audit", "status": "failed", "reason": str(exc)[:500]}
            )
        try:
            from stac_attack_lab.execution.construction_admission import (
                audit_construction_collection,
            )

            report = audit_construction_collection(collection, library_path)
            structural = report.get("structural_admission", {}).get("status")
            result["admission"] = structural or "failed"
            result["structural_admission"] = {"status": result["admission"]}
            result["admission_report"] = report
            result["stages"].append({"stage": "admission", "status": result["admission"]})
        except Exception as exc:
            result["stages"].append(
                {"stage": "admission", "status": "failed", "reason": str(exc)[:500]}
            )
    result["execution_status"] = "completed"
    failed = any(stage.get("status") == "failed" for stage in result["stages"])
    result["overall_status"] = "failed" if failed else "passed"
    (analysis_root / "offline_summary.json").write_text(
        json.dumps(result, indent=2, sort_keys=True, default=str) + "\n", encoding="utf-8"
    )
    (run_root / "offline_summary.json").write_text(
        json.dumps(result, indent=2, sort_keys=True, default=str) + "\n", encoding="utf-8"
    )
    return result
