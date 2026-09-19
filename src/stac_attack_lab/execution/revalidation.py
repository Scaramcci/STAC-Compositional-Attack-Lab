from __future__ import annotations

import json
import os
import subprocess
import uuid
from datetime import UTC, datetime
from pathlib import Path
from time import monotonic
from typing import Any

from stac_attack_lab.hashing import file_hash, stable_hash

REPLAY_VERSION = "bridge-driver-replay-v1"


def _atomic_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(json.dumps(value, indent=2, sort_keys=True, default=str) + "\n")
    temporary.replace(path)


def _new_analysis_root(run_root: Path, mode: str) -> tuple[str, Path]:
    analysis_id = f"{mode}-{datetime.now(UTC).strftime('%Y%m%d-%H%M%S')}-{uuid.uuid4().hex[:8]}"
    target = run_root / "analyses" / analysis_id
    target.mkdir(parents=True, exist_ok=False)
    return analysis_id, target


def _input_label(root: Path, path: Path) -> str:
    resolved_root, resolved = root.resolve(), path.resolve()
    if resolved == resolved_root or resolved_root in resolved.parents:
        return resolved.relative_to(resolved_root).as_posix()
    return f"external-{stable_hash(str(resolved))[:16]}-{path.name}"


def _processing_source_hashes(root: Path) -> dict[str, str]:
    return {
        "driver": file_hash(root / "src/stac_attack_lab/interactions/safeclaw_collection.py"),
        "bridge": file_hash(root / "integrations/safeclaw/construction_bridge.py"),
        "revalidation": file_hash(Path(__file__)),
        "admission": file_hash(root / "src/stac_attack_lab/execution/construction_admission.py"),
    }


def _bridge_replay_provenance(
    root: Path,
    analysis_id: str,
    bridge_responses: Path,
    config_path: Path,
    *,
    compatibility_notes: list[str] | None = None,
) -> dict[str, Any]:
    inputs = {
        _input_label(root, path): file_hash(path)
        for path in (bridge_responses, config_path)
        if path.is_file()
    }
    return {
        "analysis_id": analysis_id,
        "mode": "bridge-replay",
        "replay_version": REPLAY_VERSION,
        "parameters": {
            "bridge_responses": str(bridge_responses),
            "runtime_config": str(config_path),
        },
        "command": "stac-attack-lab revalidation offline --bridge-responses",
        "head": _git(root, "rev-parse", "HEAD"),
        "dirty": bool(_git(root, "status", "--porcelain")),
        "input_sha256": inputs,
        "processing_source_sha256": _processing_source_hashes(root),
        "compatibility_notes": [
            "production strong-consumption evidence is not currently available",
            *(compatibility_notes or []),
        ],
    }


def _parse_bridge_records(path: Path) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    valid: list[dict[str, Any]] = []
    malformed: list[dict[str, Any]] = []
    for line_number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
        if not line.strip():
            continue
        try:
            value = json.loads(line)
        except json.JSONDecodeError as exc:
            malformed.append(
                {
                    "line_number": line_number,
                    "reason_code": "malformed_json",
                    "detail": str(exc)[:200],
                }
            )
            continue
        if not isinstance(value, dict):
            malformed.append({"line_number": line_number, "reason_code": "jsonl_row_not_object"})
            continue
        valid.append({"line_number": line_number, "record": value})
    return valid, malformed


def replay_bridge_responses(
    root: Path,
    analysis_root: Path,
    bridge_responses: Path,
    config_path: Path,
) -> dict[str, Any]:
    """Replay recorded bridge action/response pairs through the live driver mapper."""
    from stac_attack_lab.execution.sample_generation import (
        _record_collection_stage,
        load_sample_generation_config,
    )
    from stac_attack_lab.interactions.base import CollectionBudget
    from stac_attack_lab.interactions.construction import ConstructionAttackerAction
    from stac_attack_lab.interactions.models import (
        ConstructionManifest,
        RawInteractionTrajectory,
        SourceReference,
    )
    from stac_attack_lab.interactions.safeclaw_collection import SafeClawSubprocessVictimDriver

    valid, malformed = _parse_bridge_records(bridge_responses)
    diagnostics: dict[str, Any] = {
        "valid_line_count": len(valid),
        "malformed_line_count": len(malformed),
        "malformed_lines": malformed,
        "integrity_status": "failed" if malformed else "passed",
        "missing": [],
        "tool_observation_count": 0,
        "ordered_tool_observation_count": 0,
        "tool_counts": {},
    }
    action_pairs: list[tuple[ConstructionAttackerAction, dict[str, Any]]] = []
    finish_seen = False
    initial_state: dict[str, Any] | None = None
    for item in valid:
        record = item["record"]
        request = record.get("request") if isinstance(record.get("request"), dict) else record
        response = record.get("response")
        if request.get("kind") == "initialize":
            if (
                isinstance(response, dict)
                and response.get("kind") == "ready"
                and isinstance(response.get("pre_state"), dict)
                and initial_state is None
            ):
                initial_state = dict(response["pre_state"])
            else:
                diagnostics["missing"].append(
                    {
                        "line_number": item["line_number"],
                        "reason_code": "bridge_replay_initial_state_invalid",
                    }
                )
            continue
        if request.get("kind") == "finish" or record.get("kind") == "finish":
            finish_seen = isinstance(response, dict) and response.get("kind") == "finished"
            continue
        action_value = request.get("action")
        if not isinstance(action_value, dict) or not isinstance(response, dict):
            diagnostics["missing"].append(
                {
                    "line_number": item["line_number"],
                    "reason_code": "bridge_replay_action_or_response_missing",
                }
            )
            continue
        try:
            action = ConstructionAttackerAction.model_validate(action_value)
        except Exception as exc:
            diagnostics["missing"].append(
                {
                    "line_number": item["line_number"],
                    "reason_code": "bridge_replay_action_invalid",
                    "detail": str(exc)[:300],
                }
            )
            continue
        if action.action_type == "deliver_message" and (
            not isinstance(response.get("session"), dict)
            or not isinstance(response.get("post_state"), dict)
        ):
            diagnostics["missing"].append(
                {
                    "line_number": item["line_number"],
                    "reason_code": "bridge_replay_session_or_state_missing",
                }
            )
            continue
        session = response.get("session")
        observations = session.get("tool_observations", []) if isinstance(session, dict) else []
        if isinstance(observations, list):
            for observation in observations:
                if not isinstance(observation, dict):
                    continue
                diagnostics["tool_observation_count"] += 1
                if isinstance(observation.get("order"), int):
                    diagnostics["ordered_tool_observation_count"] += 1
                tool_name = observation.get("tool_name")
                if isinstance(tool_name, str) and tool_name:
                    tool_counts = diagnostics["tool_counts"]
                    tool_counts[tool_name] = int(tool_counts.get(tool_name, 0)) + 1
        action_pairs.append((action, response))
    if initial_state is None:
        diagnostics["missing"].append(
            {
                "line_number": None,
                "reason_code": "bridge_replay_initial_state_missing",
            }
        )
    if malformed or diagnostics["missing"] or not action_pairs:
        diagnostics["integrity_status"] = "failed"
        return {
            "status": "blocked",
            "reason_code": "insufficient_inputs",
            "diagnostics": diagnostics,
            "collection": None,
        }
    assert initial_state is not None

    config = load_sample_generation_config(config_path)
    driver = object.__new__(SafeClawSubprocessVictimDriver)
    driver._budget = CollectionBudget(
        max_sessions=config.max_sessions,
        max_turns=config.max_turns,
        max_actions=config.max_actions,
        max_tool_calls=config.max_tool_calls,
        max_tokens=config.max_tokens,
        max_wall_time_seconds=config.max_wall_time_seconds,
        max_events=config.max_events,
        timeout_seconds=config.timeout_seconds,
    )
    driver._started_at = monotonic()
    driver._pre_state = dict(initial_state)
    driver._last_state = dict(initial_state)
    driver._new_session_pending = False
    driver._event_sequence = 0
    driver._events = []
    driver._checkpoints = []
    driver._workspace_versions = {}
    driver._provider_requests_spent = 0
    driver._embedding_requests_spent = 0
    driver._current_provider_requests = 0
    driver._current_embedding_requests = 0
    source_events: list[dict[str, Any]] = []
    session_ids: list[str] = []
    for action, response in action_pairs:
        step = driver.map_bridge_action_response(action, response)
        source_events.extend(step.source_events)
        if step.session_id not in session_ids:
            session_ids.append(step.session_id)

    collection = analysis_root / "bridge-replay-collection"
    trajectory_id = f"trajectory-{analysis_root.name}"
    trajectory_root = collection / "trajectories" / trajectory_id
    trajectory_root.mkdir(parents=True)
    events_path = trajectory_root / "source_events.jsonl"
    events_path.write_text(
        "".join(json.dumps(event, sort_keys=True) + "\n" for event in source_events),
        encoding="utf-8",
    )
    checkpoints_path = trajectory_root / "checkpoints.jsonl"
    checkpoints_path.write_text(
        "".join(json.dumps(item, sort_keys=True) + "\n" for item in driver._checkpoints),
        encoding="utf-8",
    )
    evidence_path = trajectory_root / "provider_boundary_evidence.jsonl"
    evidence_records = driver.boundary_evidence_snapshot()
    evidence_path.write_text(
        "".join(json.dumps(item, sort_keys=True) + "\n" for item in evidence_records),
        encoding="utf-8",
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
        attempt_outcome="completed" if finish_seen else "partial",
    )
    trajectory = RawInteractionTrajectory(
        trajectory_id=trajectory_id,
        source_adapter_id="safeclaw_bridge_replay",
        source_adapter_version=REPLAY_VERSION,
        source_environment_family="safeclaw",
        source_environment_version="pinned",
        source_task_id=config.source_task_ids[0],
        source_split="synthetic",
        episode_id=f"replay-{analysis_root.name}",
        session_ids=session_ids,
        event_refs=[
            SourceReference(
                ref_id=f"{trajectory_id}:events",
                kind="source_events",
                relative_path=str(events_path.relative_to(collection)),
                content_hash=file_hash(events_path),
            )
        ],
        checkpoint_refs=[
            SourceReference(
                ref_id=f"{trajectory_id}:checkpoints",
                kind="state_checkpoints",
                relative_path=str(checkpoints_path.relative_to(collection)),
                content_hash=file_hash(checkpoints_path),
            )
        ]
        if driver._checkpoints
        else [],
        evidence_refs=[
            SourceReference(
                ref_id=f"{trajectory_id}:provider-boundary-evidence",
                kind="provider_boundary_evidence",
                relative_path=str(evidence_path.relative_to(collection)),
                content_hash=file_hash(evidence_path),
            )
        ]
        if evidence_records
        else [],
        model_hashes={"victim": str(config.victim_model_hash or "recorded-unknown")},
        config_hash=stable_hash(config.model_dump(mode="json")),
        collection_seed=config.effective_seeds[0],
        collection_status="complete" if finish_seen else "partial",
        failure_category=None if finish_seen else "bridge_finish_record_missing",
        construction_manifest=manifest,
        provenance={
            "mode": "bridge_response_driver_replay",
            "replay_version": REPLAY_VERSION,
            "live_requests_performed": "false",
            "synthetic_instrumentation": "false",
            "provider_evidence_policy_mode": (
                "experimental"
                if evidence_records
                and all(
                    item.get("rule_id") == "stac.experimental.exact_tool_result_to_argument.v1"
                    for item in evidence_records
                    if item.get("record_type") in {"provider_request", "provider_response"}
                )
                else "disabled"
            ),
            "provider_evidence_batch_id": str(
                next(
                    (item.get("batch_id") for item in evidence_records if item.get("batch_id")),
                    "",
                )
            ),
        },
    )
    raw_path = trajectory_root / "raw_trajectory.json"
    _atomic_json(raw_path, trajectory.model_dump(mode="json"))
    collection_manifest = {
        "schema_version": "2.0",
        "collection_id": config.pipeline_id,
        "adapter_id": "safeclaw_bridge_replay",
        "adapter_version": REPLAY_VERSION,
        "acquisition_mode": "adversarial_trace",
        "construction_attacker_id": "recorded",
        "plan_hash": stable_hash({"input": file_hash(bridge_responses), "version": REPLAY_VERSION}),
        "trajectory_count": 1,
        "failure_count": 0 if finish_seen else 1,
        "formal_exclusion_hash": stable_hash(sorted(config.formal_excluded_task_ids)),
        "trajectory_hashes": {trajectory_id: file_hash(raw_path)},
    }
    _atomic_json(collection / "collection_manifest.json", collection_manifest)
    from stac_attack_lab.primitives.formal_registry import load_formal_registry

    registry = load_formal_registry(root / config.registry_path)
    _record_collection_stage(collection, config, registry.registry_hash)
    diagnostics["finish_seen"] = finish_seen
    diagnostics["source_event_count"] = len(source_events)
    return {
        "status": "passed",
        "collection": collection,
        "trajectory": raw_path,
        "diagnostics": diagnostics,
    }


def _git(root: Path, *args: str) -> str:
    try:
        return subprocess.check_output(["git", *args], cwd=root, text=True).strip()
    except (OSError, subprocess.CalledProcessError):
        return "unknown"


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
    from stac_attack_lab.execution.sample_generation import SampleGenerationConfig

    template_value = json.loads(template.read_text(encoding="utf-8"))
    template_config = SampleGenerationConfig.model_validate(template_value)
    if template_config.execution_enabled:
        raise ValueError("revalidation_template_must_be_disabled")
    config = template_config.model_dump(mode="json")
    config["pipeline_id"] = run_id
    config["output_root"] = str(run_root)
    config["execution_enabled"] = False
    _atomic_json(run_root / "runtime_config.json", config)
    _atomic_json(run_root / "prepared_runtime_config.json", config)
    provenance = {
        "run_id": run_id,
        "head": _git(root, "rev-parse", "HEAD"),
        "dirty": bool(_git(root, "status", "--porcelain")),
        "config_sha256": file_hash(run_root / "runtime_config.json"),
        "prepared_config_sha256": file_hash(run_root / "prepared_runtime_config.json"),
        "template_sha256": file_hash(template),
        "controlled_source_sha256": stable_hash(
            {
                str(p.relative_to(root)): file_hash(p)
                for base in (root / "src", root / "integrations" / "safeclaw", root / "scripts")
                for p in sorted(base.rglob("*"))
                if p.is_file() and (p.suffix in {".py", ".sh"} or p.name == "README.md")
            }
        ),
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


def _validate_live_binding(root: Path, run_root: Path, config_data: dict[str, Any]) -> None:
    expected_parent = (root / "experiments" / "runs").resolve()
    resolved_run = run_root.resolve()
    if resolved_run.parent != expected_parent:
        raise ValueError("revalidation_run_root_outside_allowed_directory")
    if config_data.get("pipeline_id") != run_root.name:
        raise ValueError("revalidation_pipeline_id_mismatch")
    if Path(str(config_data.get("output_root", ""))).resolve() != resolved_run:
        raise ValueError("revalidation_output_root_mismatch")
    prepared_path = run_root / "prepared_runtime_config.json"
    provenance_path = run_root / "provenance.json"
    if not prepared_path.is_file() or not provenance_path.is_file():
        raise ValueError("revalidation_prepare_snapshot_missing")
    prepared = json.loads(prepared_path.read_text(encoding="utf-8"))
    comparable = dict(config_data)
    comparable["execution_enabled"] = False
    if comparable != prepared:
        raise ValueError("revalidation_execution_config_changed_beyond_authorization")
    provenance = json.loads(provenance_path.read_text(encoding="utf-8"))
    if provenance.get("run_id") != run_root.name:
        raise ValueError("revalidation_provenance_run_id_mismatch")
    if provenance.get("prepared_config_sha256") != file_hash(prepared_path):
        raise ValueError("revalidation_prepared_config_hash_mismatch")


def launch_live_revalidation(root: Path, run_root: Path, *, authorized: bool) -> dict[str, Any]:
    """Launch exactly once inside one prepared run after explicit authorization."""
    if not authorized:
        raise ValueError("live_authorization_flag_required")
    from stac_attack_lab.execution.sample_generation import (
        _validate_collection_stage,
        collect_sample_interactions,
        load_sample_generation_config,
    )
    from stac_attack_lab.execution.sample_preflight import run_sample_collection_preflight

    config_path = run_root / "runtime_config.json"
    marker = run_root / "launch.marker"
    try:
        config_data = json.loads(config_path.read_text(encoding="utf-8"))
        if config_data.get("execution_enabled") is not True:
            raise ValueError("live_execution_disabled_in_runtime_config")
        _validate_live_binding(root, run_root, config_data)
        config = load_sample_generation_config(config_path)
        preflight = run_sample_collection_preflight(root, config)
        if not preflight.passed:
            raise RuntimeError("revalidation_live_preflight_failed")
    except Exception as exc:
        validation = {
            "pipeline_execution": {"status": "not_started"},
            "input_integrity": {"status": "failed"},
            "structural_admission": {"status": "not_run"},
            "runtime_review": {"status": "not_run"},
            "execution_authorization": {"status": "granted"},
            "official_outcome": {"status": "not_evaluated"},
            "stage_errors": [{"stage": "config_or_preflight", "error": str(exc)[:500]}],
            "exit_code": 30,
        }
        _atomic_json(run_root / "launch_validation_summary.json", validation)
        raise

    descriptor = os.open(marker, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        os.write(descriptor, b"live launch reserved\n")
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    live_review = {
        "run_id": run_root.name,
        "execution_status": "authorized_pending_launch",
        "live_authorization": "explicit_command_flag",
        "checks": {
            "execution_enabled": True,
            "run_root_unique": marker.is_file(),
            "pipeline_id_matches": config.pipeline_id == run_root.name,
            "output_root_matches": Path(config.output_root).resolve() == run_root.resolve(),
        },
        "execution_config_sha256": file_hash(config_path),
        "prepared_config_sha256": file_hash(run_root / "prepared_runtime_config.json"),
        "execution_source_sha256": stable_hash(
            {
                str(path.relative_to(root)): file_hash(path)
                for path in sorted((root / "src/stac_attack_lab").rglob("*.py"))
            }
        ),
        "head": _git(root, "rev-parse", "HEAD"),
        "dirty": bool(_git(root, "status", "--porcelain")),
    }
    _atomic_json(run_root / "configuration_review.live.json", live_review)
    _atomic_json(run_root / "execution_snapshot.json", {**live_review, "config": config_data})

    stage_errors: list[dict[str, str]] = []
    collection: Path | None = None
    offline: dict[str, Any] | None = None
    try:
        collection = Path(collect_sample_interactions(root, config))
    except Exception as exc:
        stage_errors.append({"stage": "collection", "error": str(exc)[:500]})
        candidate = (
            root
            / config.output_root
            / config.library_version
            / "interactions"
            / "raw"
            / config.pipeline_id
        )
        try:
            _validate_collection_stage(candidate, expected_config=config)
            collection = candidate
        except Exception as followup:
            stage_errors.append(
                {"stage": "partial_collection_validation", "error": str(followup)[:500]}
            )
    if collection is not None:
        try:
            offline = offline_revalidation(root, run_root, collection)
        except Exception as exc:
            stage_errors.append({"stage": "offline", "error": str(exc)[:500]})

    offline_status = offline.get("overall_status") if offline else "not_run"
    offline_structural_value = offline.get("structural_admission") if offline else None
    offline_structural = (
        str(offline_structural_value.get("status", "not_run"))
        if isinstance(offline_structural_value, dict)
        else str(offline_structural_value or "not_run")
    )
    execution_status = (
        "completed_awaiting_runtime_review"
        if not stage_errors and offline_status == "passed"
        else "completed_with_stage_failures"
        if collection is not None
        else "blocked_no_valid_collection"
    )
    summary: dict[str, Any] = {
        "pipeline_execution": {"status": execution_status},
        "execution_status": execution_status,
        "input_integrity": {"status": "passed" if collection is not None else "failed"},
        "structural_admission": {"status": offline_structural},
        "runtime_review": {"status": "pending" if collection is not None else "not_run"},
        "execution_authorization": {"status": "granted", "source": "explicit_command_flag"},
        "official_outcome": {"status": "not_evaluated"},
        "budget_accounting": {
            "status": "unknown",
            "reason_code": "ledger_not_validated_by_revalidation_summary",
        },
        "collection": str(collection) if collection else None,
        "launch_marker": str(marker),
        "offline_status": offline_status,
        "offline_summary": (
            str(Path(offline["analysis_root"]) / "offline_summary.json")
            if offline and offline.get("analysis_root")
            else None
        ),
        "stage_errors": stage_errors,
        "exit_code": 2 if not stage_errors and offline_status == "passed" else 30,
    }
    _atomic_json(run_root / "live_summary.json", summary)
    return summary


def offline_revalidation(
    root: Path,
    run_root: Path,
    collection: Path | None = None,
    library: Path | None = None,
    bridge_responses: Path | None = None,
) -> dict[str, Any]:
    """Run a collection reanalysis or a true bridge-response driver replay."""
    mode = "bridge-replay" if bridge_responses is not None else "collection-reanalysis"
    analysis_id, analysis_root = _new_analysis_root(run_root, mode)
    result: dict[str, Any] = {
        "analysis_id": analysis_id,
        "analysis_root": str(analysis_root),
        "mode": mode,
        "pipeline_execution": {"status": "not_executed"},
        "execution_status": "not_executed",
        "input_integrity": {"status": "unknown"},
        "accepted": {"count": None, "audit_passed": None},
        "structural_admission": {"status": "not_run"},
        "runtime_review": {"status": "pending"},
        "execution_authorization": {"status": "absent", "granted": False},
        "official_outcome": {"status": "not_evaluated"},
        "stages": [],
    }
    config_path = run_root / "runtime_config.json"
    if bridge_responses is not None:
        provenance_path = analysis_root / "offline_provenance.json"
        _atomic_json(
            provenance_path,
            _bridge_replay_provenance(
                root,
                analysis_id,
                bridge_responses,
                config_path,
            ),
        )
        if not bridge_responses.is_file():
            result["stages"].append(
                {
                    "stage": "bridge_replay",
                    "status": "blocked",
                    "reason_code": "bridge_response_input_missing",
                }
            )
            result.update(
                overall_status="blocked",
                completion_class="insufficient_inputs",
                exit_code=20,
                input_integrity={"status": "failed"},
            )
            _atomic_json(analysis_root / "offline_summary.json", result)
            return result
        if not config_path.is_file():
            result["stages"].append(
                {
                    "stage": "bridge_replay",
                    "status": "blocked",
                    "reason_code": "runtime_config_missing",
                }
            )
            result.update(
                overall_status="blocked", completion_class="input_or_config_error", exit_code=20
            )
            _atomic_json(analysis_root / "offline_summary.json", result)
            return result
        replay = replay_bridge_responses(root, analysis_root, bridge_responses, config_path)
        result["bridge_replay"] = replay
        _atomic_json(analysis_root / "bridge_replay_diagnostics.json", replay["diagnostics"])
        result["stages"].append(
            {
                "stage": "bridge_replay",
                "status": replay["status"],
                "reason_code": replay.get("reason_code"),
            }
        )
        if replay["status"] != "passed":
            _atomic_json(
                provenance_path,
                _bridge_replay_provenance(
                    root,
                    analysis_id,
                    bridge_responses,
                    config_path,
                    compatibility_notes=[f"replay blocked: {replay.get('reason_code', 'unknown')}"],
                ),
            )
            result["input_integrity"] = {"status": "failed"}
            result.update(
                overall_status="blocked", completion_class="insufficient_inputs", exit_code=20
            )
            _atomic_json(analysis_root / "offline_summary.json", result)
            return result
        collection = Path(replay["collection"])
    elif collection is None:
        candidates = sorted(run_root.glob("single-construction/interactions/raw/*"))
        if len(candidates) > 1:
            result["stages"].append(
                {
                    "stage": "input",
                    "status": "blocked",
                    "reason_code": "multiple_collection_candidates",
                    "count": len(candidates),
                }
            )
            result.update(
                overall_status="blocked", completion_class="insufficient_inputs", exit_code=20
            )
            _atomic_json(analysis_root / "offline_summary.json", result)
            return result
        collection = candidates[0] if candidates else None
    if collection is None or not collection.exists():
        result["stages"].append(
            {"stage": "mine", "status": "blocked", "reason_code": "collection_missing"}
        )
        result.update(
            overall_status="blocked",
            completion_class="insufficient_inputs",
            exit_code=20,
            input_integrity={"status": "failed"},
        )
        _atomic_json(analysis_root / "offline_summary.json", result)
        return result
    input_hashes = {
        _input_label(root, path): file_hash(path)
        for path in sorted(collection.rglob("*"))
        if path.is_file()
    }
    if bridge_responses is not None:
        input_hashes[_input_label(root, bridge_responses)] = file_hash(bridge_responses)
    if config_path.is_file():
        input_hashes[_input_label(root, config_path)] = file_hash(config_path)
    result["input_integrity"] = {"status": "passed"}
    offline_provenance = {
        "analysis_id": analysis_id,
        "mode": mode,
        "replay_version": REPLAY_VERSION if bridge_responses is not None else None,
        "parameters": {
            "collection": str(collection),
            "library": str(library) if library else None,
            "bridge_responses": str(bridge_responses) if bridge_responses else None,
            "runtime_config": str(config_path) if config_path.is_file() else None,
        },
        "command": "stac-attack-lab revalidation offline",
        "head": _git(root, "rev-parse", "HEAD"),
        "dirty": bool(_git(root, "status", "--porcelain")),
        "input_sha256": input_hashes,
        "processing_source_sha256": _processing_source_hashes(root),
        "compatibility_notes": (
            ["production strong-consumption evidence is not currently available"]
            if bridge_responses is not None
            else []
        ),
    }
    _atomic_json(analysis_root / "offline_provenance.json", offline_provenance)
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
            structural_status = structural or "failed"
            result["structural_admission"] = {"status": structural_status}
            result["admission"] = structural_status  # compatibility alias
            result["admission_report"] = report
            result["stages"].append({"stage": "admission", "status": structural_status})
        except Exception as exc:
            result["stages"].append(
                {"stage": "admission", "status": "failed", "reason": str(exc)[:500]}
            )
    passed = bool(
        result["stages"] and all(stage.get("status") == "passed" for stage in result["stages"])
    )
    result["overall_status"] = "passed" if passed else "failed"
    result["completion_class"] = (
        "offline_checks_passed_runtime_review_pending"
        if passed
        else "checks_completed_threshold_not_met"
    )
    result["exit_code"] = 0 if passed else 10
    _atomic_json(analysis_root / "offline_summary.json", result)
    return result
