from __future__ import annotations

import json
import os
import tempfile
from collections.abc import Callable, Mapping
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Literal

from pydantic import PositiveInt, model_validator

from stac_attack_lab.contracts import StrictModel
from stac_attack_lab.datasets.library import PrimitiveChainLibrary
from stac_attack_lab.environments.safeclaw.contracts import (
    EpisodeRequest,
    SafeClawExecutionStatus,
    SafeClawTrack,
)
from stac_attack_lab.environments.safeclaw.materializer import materialize_safeclaw_task
from stac_attack_lab.environments.safeclaw.preflight import (
    SafeClawPreflightReport,
    load_safeclaw_preflight_config,
    run_safeclaw_preflight,
)
from stac_attack_lab.environments.safeclaw.runner import SafeClawRunner
from stac_attack_lab.environments.safeclaw.task_adapter import parse_safeclaw_task
from stac_attack_lab.environments.safeclaw.trajectory import normalize_safeclaw_episode
from stac_attack_lab.extraction.occurrences import extract_primitive_occurrences
from stac_attack_lab.hashing import file_hash, stable_hash
from stac_attack_lab.planning.formal_base import (
    FormalBudget,
    FormalPlanner,
    FormalPlannerInput,
)
from stac_attack_lab.planning.formal_baselines import (
    FixedSamplePlanner,
    RandomCompatiblePlanner,
    RuleBasedFormalPlanner,
)
from stac_attack_lab.primitives.formal_registry import load_formal_registry
from stac_attack_lab.recording.formal_run_recorder import (
    FormalRunManifest,
    FormalRunRecorder,
    FormalStage,
)
from stac_attack_lab.reporting.formal_report import build_formal_report
from stac_attack_lab.verification.formal_aggregate import (
    FormalMechanismEvaluation,
    aggregate_formal_result,
    evaluate_formal_mechanism,
)
from stac_attack_lab.verification.safeclaw_official import parse_safeclaw_official

FormalCondition = Literal["fixed_sample", "random_compatible", "sample_rule_based"]


class FormalTaskEntry(StrictModel):
    task_id: str
    pair_group: str
    template_path: str
    template_hash: str
    materialization_values: dict[str, Any]


class FormalTaskSetConfig(StrictModel):
    schema_version: Literal["2.0"] = "2.0"
    task_set_id: str
    track: SafeClawTrack
    status: Literal["ready", "blocked"]
    blocked_reason: str | None = None
    upstream_commit: str
    tasks: list[FormalTaskEntry]

    @model_validator(mode="after")
    def validate_status(self) -> FormalTaskSetConfig:
        if self.status == "ready" and (self.blocked_reason is not None or not self.tasks):
            raise ValueError("ready_formal_task_set_requires_tasks_without_blocker")
        if self.status == "blocked" and not self.blocked_reason:
            raise ValueError("blocked_formal_task_set_requires_reason")
        return self


class SafeClawFormalConfig(StrictModel):
    schema_version: Literal["2.0"] = "2.0"
    experiment_id: str
    execution_enabled: bool = False
    track: SafeClawTrack
    environment_config_path: str
    task_set_path: str
    registry_path: str
    library_path: str
    require_frozen_library: bool = True
    conditions: list[FormalCondition]
    seeds: list[int]
    target_model_env: str
    target_base_url_env: str
    target_api_key_env: str
    timeout_seconds: PositiveInt = 1200
    max_attempts: PositiveInt = 2
    budget: FormalBudget
    output_root: str = "experiments/safeclaw_runs"

    @model_validator(mode="after")
    def validate_matrix(self) -> SafeClawFormalConfig:
        if not self.conditions or not self.seeds:
            raise ValueError("formal_conditions_and_seeds_must_be_nonempty")
        if len(self.conditions) != len(set(self.conditions)):
            raise ValueError("duplicate_formal_condition")
        return self


def load_safeclaw_formal_config(path: Path) -> SafeClawFormalConfig:
    return SafeClawFormalConfig.model_validate_json(path.read_text(encoding="utf-8"))


def load_formal_task_set(path: Path) -> FormalTaskSetConfig:
    return FormalTaskSetConfig.model_validate_json(path.read_text(encoding="utf-8"))


def _planner(condition: FormalCondition, first_sample_id: str) -> FormalPlanner:
    if condition == "fixed_sample":
        return FixedSamplePlanner(first_sample_id)
    if condition == "random_compatible":
        return RandomCompatiblePlanner()
    return RuleBasedFormalPlanner()


def _case_matrix(
    config: SafeClawFormalConfig, task_set: FormalTaskSetConfig
) -> list[tuple[str, str, str, FormalCondition, int, FormalTaskEntry]]:
    cases: list[tuple[str, str, str, FormalCondition, int, FormalTaskEntry]] = []
    for task in task_set.tasks:
        for seed in config.seeds:
            pair_id = (
                "pair-"
                + stable_hash(
                    {"pair_group": task.pair_group, "task_id": task.task_id, "seed": seed}
                )[:20]
            )
            for condition in config.conditions:
                case_id = (
                    "case-"
                    + stable_hash(
                        {
                            "experiment_id": config.experiment_id,
                            "task_id": task.task_id,
                            "condition": condition,
                            "seed": seed,
                        }
                    )[:20]
                )
                cases.append((case_id, pair_id, task.task_id, condition, seed, task))
    return cases


def _empty_mechanism() -> FormalMechanismEvaluation:
    return FormalMechanismEvaluation(
        occurrence_verdicts=[],
        edge_verdicts=[],
        macro_verdicts=[],
        forbidden_shortcut=False,
        not_observable_count=0,
    )


def _tool_call_count(sanitized: dict[str, Any] | None) -> int:
    if sanitized is None:
        return 0
    sessions = sanitized.get("sessions", [])
    if not isinstance(sessions, list):
        return 0
    return sum(
        len(tool_calls)
        for session in sessions
        if isinstance(session, dict)
        and isinstance((tool_calls := session.get("tool_calls", [])), list)
    )


def run_safeclaw_formal(
    project_root: Path,
    config: SafeClawFormalConfig,
    *,
    run_id: str | None = None,
    resume: bool = False,
    environment: Mapping[str, str] | None = None,
    preflight_report: SafeClawPreflightReport | None = None,
    runner: SafeClawRunner | None = None,
    after_case: Callable[[int], None] | None = None,
) -> Path:
    if not config.execution_enabled:
        raise ValueError("formal_execution_disabled_by_config")
    env = environment if environment is not None else os.environ
    required_env = [
        config.target_model_env,
        config.target_base_url_env,
        config.target_api_key_env,
    ]
    missing_env = [name for name in required_env if not env.get(name)]
    if missing_env:
        raise ValueError("missing_formal_environment_variables:" + ",".join(missing_env))
    task_set = load_formal_task_set(project_root / config.task_set_path)
    if task_set.status != "ready":
        raise ValueError(f"formal_task_set_blocked:{task_set.blocked_reason}")
    if task_set.track != config.track:
        raise ValueError("formal_task_set_track_mismatch")
    if config.track != SafeClawTrack.compositional:
        raise ValueError("formal_orchestrator_requires_compositional_track")
    library = PrimitiveChainLibrary(project_root / config.library_path)
    if config.require_frozen_library and not library.manifest.frozen:
        raise ValueError("formal_evaluation_requires_frozen_library")
    registry = load_formal_registry(project_root / config.registry_path)
    if registry.registry_hash != library.manifest.registry_hash:
        raise ValueError("formal_library_registry_hash_mismatch")
    environment_config = load_safeclaw_preflight_config(
        project_root / config.environment_config_path
    )
    preflight = preflight_report or run_safeclaw_preflight(
        project_root, environment_config, environment=env
    )
    if not preflight.passed:
        failed = [check.reason_code for check in preflight.checks if not check.passed]
        raise ValueError("safeclaw_preflight_failed:" + ",".join(failed))
    if preflight.upstream_commit != task_set.upstream_commit:
        raise ValueError("formal_task_set_upstream_commit_mismatch")
    config_hash = stable_hash(config.model_dump(mode="json"))
    resolved_run_id = run_id or f"{config.experiment_id}-{config_hash[:12]}"
    run_root = project_root / config.output_root / resolved_run_id
    if run_root.exists() and not resume:
        raise FileExistsError(f"formal_run_already_exists:{run_root}")
    cases = _case_matrix(config, task_set)
    api_key = str(env[config.target_api_key_env])
    recorder = FormalRunRecorder(run_root, [api_key])
    manifest = FormalRunManifest(
        run_id=resolved_run_id,
        experiment_id=config.experiment_id,
        track=config.track.value,
        config_hash=config_hash,
        library_version=library.manifest.library_version,
        library_hash=library.manifest.tree_hash,
        registry_hash=registry.registry_hash,
        upstream_commit=preflight.upstream_commit,
        safety_patch_hash=preflight.patch_hash or "unavailable",
        target_model_id=str(env[config.target_model_env]),
        environment_variable_names=required_env,
        case_ids=[case_id for case_id, *_ in cases],
        created_at=datetime.now(UTC).isoformat(),
    )
    recorder.initialize(
        manifest,
        [
            (case_id, pair_id, task_id, condition, seed)
            for case_id, pair_id, task_id, condition, seed, _ in cases
        ],
    )
    upstream_root = (project_root / environment_config.upstream_dir).resolve()
    safety_patch = (project_root / environment_config.patch_path).resolve()
    episode_runner = runner or SafeClawRunner(
        upstream_root=upstream_root,
        safety_patch=safety_patch,
        output_root=run_root / "runner",
        environment=env,
    )
    completed = 0
    completed_ids = {
        case.case_id
        for case in recorder.load_progress().cases
        if case.stage == FormalStage.recorded
    }
    public_samples = library.public_index()
    first_sample_id = public_samples[0].sample_id
    for case_id, pair_id, task_id, condition, seed, task in cases:
        if case_id in completed_ids:
            continue
        try:
            template_path = project_root / task.template_path
            if file_hash(template_path) != task.template_hash:
                raise ValueError(f"formal_task_template_hash_mismatch:{task_id}")
            descriptor = parse_safeclaw_task(
                template_path,
                upstream_root=project_root,
                upstream_commit=task_set.upstream_commit,
            )
            if descriptor.task_id != task_id:
                raise ValueError("formal_task_entry_identity_mismatch")
            planner_input = FormalPlannerInput(
                planner_input_id=f"input-{case_id}",
                library_id=library.manifest.library_id,
                library_version=library.manifest.library_version,
                library_hash=library.manifest.tree_hash,
                public_samples=public_samples,
                public_task=descriptor.public_view,
                budget=config.budget,
                condition=condition,
                seed=seed,
            )
            plan = _planner(condition, first_sample_id).plan(planner_input)
            if plan.selected_sample_id is None:
                raise ValueError(f"formal_planner_abstained:{plan.abstain_reason}")
            selected_public = next(
                item for item in public_samples if item.sample_id == plan.selected_sample_id
            )
            execution_view = library.execution_view(plan.selected_sample_id)
            recorder.record_artifact(case_id, FormalStage.planned, "planner_input", planner_input)
            recorder.record_artifact(case_id, FormalStage.planned, "evaluation_plan", plan)
            with tempfile.TemporaryDirectory(prefix="formal-materialization-") as temporary:
                materialized = materialize_safeclaw_task(
                    template_path,
                    descriptor,
                    plan,
                    execution_view,
                    task.materialization_values,
                    Path(temporary),
                )
                binding_payload = json.loads(
                    (Path(temporary) / materialized.reference.binding_manifest_ref).read_text(
                        encoding="utf-8"
                    )
                )
                materialized_task_payload = json.loads(
                    materialized.path.read_text(encoding="utf-8")
                )
                recorder.record_artifact(
                    case_id,
                    FormalStage.materialized,
                    "binding_manifest",
                    binding_payload,
                )
                materialized_task_record = recorder.record_artifact(
                    case_id,
                    FormalStage.materialized,
                    "materialized_task",
                    materialized_task_payload,
                )
                request = EpisodeRequest(
                    case_id=case_id,
                    task_ref=materialized.reference,
                    target_model_id=str(env[config.target_model_env]),
                    target_base_url=str(env[config.target_base_url_env]),
                    target_api_key_env=config.target_api_key_env,
                    timeout_seconds=config.timeout_seconds,
                    max_attempts=config.max_attempts,
                    output_root=str(run_root / "runner"),
                    seed=seed,
                    condition=condition,
                )
                episode = episode_runner.run_episode(request, materialized, resume=True)
            recorder.record_artifact(case_id, FormalStage.executed, "episode_result", episode)
            sanitized: dict[str, Any] | None = None
            if episode.sanitized_result_ref:
                sanitized_path = episode_runner.output_root / case_id / episode.sanitized_result_ref
                loaded = json.loads(sanitized_path.read_text(encoding="utf-8"))
                if not isinstance(loaded, dict):
                    raise ValueError("formal_sanitized_result_root_not_mapping")
                sanitized = loaded
                recorder.record_artifact(
                    case_id,
                    FormalStage.executed,
                    "safeclaw_sanitized_result",
                    sanitized,
                )
            official = parse_safeclaw_official(episode, sanitized)
            mechanism = _empty_mechanism()
            graph_payload: dict[str, Any] | None = None
            extraction_payload: dict[str, Any] | None = None
            artifact_paths: dict[str, str] = {
                "materialized_task": materialized_task_record.relative_path
            }
            if episode.status == SafeClawExecutionStatus.completed and sanitized is not None:
                graph, trajectory_audit = normalize_safeclaw_episode(episode, descriptor, sanitized)
                graph_payload = graph.model_dump(mode="json")
                graph_record = recorder.record_artifact(
                    case_id, FormalStage.normalized, "interaction_graph", graph
                )
                audit_record = recorder.record_artifact(
                    case_id,
                    FormalStage.normalized,
                    "trajectory_audit",
                    trajectory_audit,
                )
                extraction = extract_primitive_occurrences(graph, registry)
                extraction_payload = extraction.model_dump(mode="json")
                occurrence_record = recorder.record_artifact(
                    case_id,
                    FormalStage.normalized,
                    "primitive_extraction",
                    extraction,
                )
                mechanism = evaluate_formal_mechanism(
                    planner_view=selected_public.planner_view,
                    execution_view=execution_view,
                    occurrences=extraction.occurrences,
                    graph=graph,
                    registry=registry,
                    official_terminal_success=official.attack_succeeded is True,
                )
                artifact_paths.update(
                    {
                        "interaction_graph": graph_record.relative_path,
                        "trajectory_audit": audit_record.relative_path,
                        "primitive_extraction": occurrence_record.relative_path,
                    }
                )
            official_record = recorder.record_artifact(
                case_id, FormalStage.verified, "official_verdict", official
            )
            mechanism_record = recorder.record_artifact(
                case_id,
                FormalStage.verified,
                "mechanism_evaluation",
                mechanism,
            )
            runner_case_root = episode_runner.output_root / case_id
            attempt_logs = [
                {
                    "relative_path": str(path.relative_to(run_root)),
                    "content": path.read_text(encoding="utf-8"),
                }
                for path in sorted(runner_case_root.glob("attempt-*.log"))
            ]
            complete_interaction_record = {
                "schema_version": "2.0",
                "record_type": "safeclaw_formal_complete_interaction",
                "run_id": resolved_run_id,
                "case_id": case_id,
                "pair_id": pair_id,
                "condition": condition,
                "seed": seed,
                "planner_stage": {
                    "implementation": plan.planner_type,
                    "model_id": None,
                    "prompt_asset": None,
                    "messages": [],
                    "input": planner_input.model_dump(mode="json"),
                    "output": plan.model_dump(mode="json"),
                },
                "attacker_stage": {
                    "implemented": False,
                    "model_id": None,
                    "prompt_asset": None,
                    "messages": [],
                    "reason": (
                        "The formal v1 pipeline deterministically materializes the selected "
                        "primitive chain into a SafeClaw task; it does not call an LLM attacker."
                    ),
                },
                "attack_realization": {
                    "selected_sample": selected_public.model_dump(mode="json"),
                    "execution_view": execution_view.model_dump(mode="json"),
                    "binding_manifest": binding_payload,
                    "materialized_task": materialized_task_payload,
                },
                "victim_stage": {
                    "platform": "openclaw",
                    "model_id": episode.target_model_id,
                    "provider_contract": "openai_compatible",
                    "base_url_env": config.target_base_url_env,
                    "api_key_env": config.target_api_key_env,
                    "episode": episode.model_dump(mode="json"),
                    "sessions": (sanitized or {}).get("sessions", []),
                    "session_transcript_raw": (sanitized or {}).get("session_transcript_raw", ""),
                    "sanitized_result": sanitized,
                    "attempt_logs": attempt_logs,
                },
                "primitive_evaluation": {
                    "interaction_graph": graph_payload,
                    "primitive_extraction": extraction_payload,
                    "mechanism_evaluation": mechanism.model_dump(mode="json"),
                },
                "official_evaluation": official.model_dump(mode="json"),
            }
            complete_record = recorder.record_artifact(
                case_id,
                FormalStage.verified,
                "complete_interaction_record",
                complete_interaction_record,
            )
            artifact_paths.update(
                {
                    "official_verdict": official_record.relative_path,
                    "mechanism_evaluation": mechanism_record.relative_path,
                    "complete_interaction_record": complete_record.relative_path,
                }
            )
            result = aggregate_formal_result(
                run_id=resolved_run_id,
                case_id=case_id,
                pair_id=pair_id,
                seed=seed,
                library_version=library.manifest.library_version,
                plan=plan,
                episode=episode,
                official_verdict=official,
                mechanism=mechanism,
                tool_calls=_tool_call_count(sanitized),
                api_calls=episode.attempt_count,
                artifact_paths=artifact_paths,
                provenance_hashes={
                    "config_hash": config_hash,
                    "library_hash": library.manifest.tree_hash,
                    "registry_hash": registry.registry_hash,
                    "materialized_task_hash": materialized.reference.materialized_task_hash,
                },
            )
            recorder.finalize_result(result)
            completed += 1
            if after_case is not None:
                after_case(completed)
        except Exception as exc:
            recorder.mark_error(case_id, type(exc).__name__)
            raise
    audit = recorder.audit()
    if not audit.passed:
        raise ValueError("formal_recorder_audit_failed:" + ",".join(audit.finding_codes))
    build_formal_report(run_root)
    return run_root
