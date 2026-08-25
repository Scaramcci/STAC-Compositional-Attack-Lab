from __future__ import annotations

import json
import os
import tempfile
from collections.abc import Callable, Mapping
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Literal

from pydantic import Field, PositiveInt, model_validator

from stac_attack_lab.config import RoleModelConfig, load_simple_yaml
from stac_attack_lab.contracts import StrictModel
from stac_attack_lab.datasets.library import PrimitiveChainLibrary
from stac_attack_lab.environments.safeclaw.contracts import (
    EpisodeRequest,
    SafeClawExecutionStatus,
    SafeClawTaskDescriptor,
    SafeClawTrack,
)
from stac_attack_lab.environments.safeclaw.interactive_driver import (
    SafeClawInteractiveVictimDriver,
)
from stac_attack_lab.environments.safeclaw.materializer import materialize_safeclaw_task
from stac_attack_lab.environments.safeclaw.model_config import SafeClawEmbeddingRuntime
from stac_attack_lab.environments.safeclaw.preflight import (
    SafeClawPreflightReport,
    load_safeclaw_preflight_config,
    run_safeclaw_preflight,
)
from stac_attack_lab.environments.safeclaw.runner import SafeClawRunner
from stac_attack_lab.environments.safeclaw.task_adapter import parse_safeclaw_task
from stac_attack_lab.environments.safeclaw.trajectory import normalize_safeclaw_episode
from stac_attack_lab.execution.formal_action_loop import FormalActionLoopResult
from stac_attack_lab.execution.formal_attacker import (
    FormalAttacker,
    FormalAttackRealization,
    ModelFormalAttacker,
    make_formal_attacker_input,
)
from stac_attack_lab.execution.formal_interactive_episode import (
    run_interactive_baseline_episode,
    run_interactive_episode,
)
from stac_attack_lab.extraction.occurrences import extract_primitive_occurrences
from stac_attack_lab.hashing import file_hash, stable_hash
from stac_attack_lab.models.factory import build_model_client
from stac_attack_lab.planning.formal_base import (
    FormalBudget,
    FormalCaseAssignment,
    FormalPlanner,
    FormalPlannerInput,
)
from stac_attack_lab.planning.formal_baselines import FixedSamplePlanner, NoSamplePlanner
from stac_attack_lab.planning.formal_llm import FormalLLMPlanner
from stac_attack_lab.planning.formal_scheduler import (
    FormalAssignmentScheduler,
    assert_pair_invariants,
)
from stac_attack_lab.primitives.formal_registry import load_formal_registry
from stac_attack_lab.recording.events import read_jsonl
from stac_attack_lab.recording.formal_run_recorder import (
    FormalRunManifest,
    FormalRunRecorder,
    FormalStage,
)
from stac_attack_lab.recording.model_calls import ObservableModelCallRecorder
from stac_attack_lab.reporting.formal_report import build_formal_report
from stac_attack_lab.verification.formal_aggregate import (
    FormalMechanismEvaluation,
    aggregate_formal_result,
    evaluate_formal_mechanism,
)
from stac_attack_lab.verification.formal_models import (
    CausalVerdict,
    DependencyAblationEvaluation,
    FormalExecutionAccounting,
)
from stac_attack_lab.verification.safeclaw_official import parse_safeclaw_official

FormalCondition = Literal[
    "no_sample",
    "fixed_sample",
    "random_compatible",
    "sample_rule_based",
    "sample_llm_tiebreak",
    "assigned_sample",
    "dependency_ablation",
]


class FormalTaskEntry(StrictModel):
    task_id: str
    pair_group: str
    template_path: str
    template_hash: str
    formal_experiment: dict[str, Any] | None = None
    materialization_values: dict[str, Any]
    baseline_materialization_values: dict[str, Any]
    sample_derived_slots: list[str]

    @model_validator(mode="after")
    def validate_matched_baseline(self) -> FormalTaskEntry:
        sample_keys = set(self.materialization_values)
        baseline_keys = set(self.baseline_materialization_values)
        if sample_keys != baseline_keys:
            raise ValueError("baseline_materialization_slot_set_mismatch")
        if len(self.sample_derived_slots) != len(set(self.sample_derived_slots)):
            raise ValueError("duplicate_sample_derived_slot")
        changed = {
            key
            for key in sample_keys
            if self.materialization_values[key] != self.baseline_materialization_values[key]
        }
        if changed != set(self.sample_derived_slots) or not changed:
            raise ValueError("baseline_materialization_delta_mismatch")
        return self


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
    attacker_stage_implemented: bool = False
    attacker_execution_enabled: bool = False
    attacker_model_config_path: str | None = None
    attacker_prompt_path: str | None = None
    planner_model_config_path: str | None = None
    planner_selection_prompt_path: str | None = None
    planner_trajectory_prompt_path: str | None = None
    conditions: list[FormalCondition]
    seeds: list[int]
    target_model_env: str
    allowed_target_models: list[str] = Field(default_factory=list)
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
        if self.attacker_execution_enabled and (
            not self.attacker_stage_implemented
            or self.attacker_model_config_path is None
            or self.attacker_prompt_path is None
        ):
            raise ValueError("formal_attacker_enabled_without_complete_configuration")
        if "sample_llm_tiebreak" in self.conditions and (
            self.planner_model_config_path is None
            or self.planner_selection_prompt_path is None
            or self.planner_trajectory_prompt_path is None
        ):
            raise ValueError("formal_llm_planner_condition_without_complete_configuration")
        return self


def load_safeclaw_formal_config(path: Path) -> SafeClawFormalConfig:
    return SafeClawFormalConfig.model_validate_json(path.read_text(encoding="utf-8"))


def load_formal_task_set(path: Path) -> FormalTaskSetConfig:
    return FormalTaskSetConfig.model_validate_json(path.read_text(encoding="utf-8"))


def _planner(
    condition: FormalCondition,
    selected_sample_id: str | None,
    llm_planner: FormalLLMPlanner | None = None,
) -> FormalPlanner:
    if condition == "no_sample":
        return NoSamplePlanner()
    if condition == "sample_llm_tiebreak":
        if llm_planner is None:
            raise ValueError("formal_llm_planner_not_configured")
        return llm_planner
    if selected_sample_id is None:
        raise ValueError("formal_sample_condition_missing_scheduler_assignment")
    return FixedSamplePlanner(selected_sample_id)


def _configured_attacker(
    project_root: Path, config: SafeClawFormalConfig
) -> ModelFormalAttacker | None:
    if not config.attacker_execution_enabled:
        return None
    if config.attacker_model_config_path is None or config.attacker_prompt_path is None:
        raise ValueError("formal_attacker_configuration_missing")
    model_config = RoleModelConfig.model_validate(
        load_simple_yaml(project_root / config.attacker_model_config_path)
    )
    return ModelFormalAttacker(
        build_model_client(model_config), project_root / config.attacker_prompt_path
    )


def _configured_llm_planner(
    project_root: Path, config: SafeClawFormalConfig
) -> FormalLLMPlanner | None:
    if "sample_llm_tiebreak" not in config.conditions:
        return None
    if (
        config.planner_model_config_path is None
        or config.planner_selection_prompt_path is None
        or config.planner_trajectory_prompt_path is None
    ):
        raise ValueError("formal_llm_planner_configuration_missing")
    model_config = RoleModelConfig.model_validate(
        load_simple_yaml(project_root / config.planner_model_config_path)
    )
    return FormalLLMPlanner(
        build_model_client(model_config),
        project_root / config.planner_selection_prompt_path,
        project_root / config.planner_trajectory_prompt_path,
    )


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


def _formal_execution_accounting(
    *,
    model_call_events: list[dict[str, Any]],
    interactive_loop: FormalActionLoopResult | None,
    baseline_trace: dict[str, Any] | None,
    episode_attempts: int,
    wall_time_ms: int,
) -> FormalExecutionAccounting:
    model_requests = [
        item for item in model_call_events if item.get("kind") == "model_call_request"
    ]
    model_responses = {
        str(item.get("call_id")): item
        for item in model_call_events
        if item.get("kind") == "model_call_response"
    }
    planner_model_calls = sum(item.get("role") == "planner" for item in model_requests)
    attacker_model_calls = sum(item.get("role") == "attacker" for item in model_requests)
    gemini_native_calls = sum(item.get("provider_id") == "gemini" for item in model_requests)
    if interactive_loop is not None:
        source = interactive_loop.accounting.model_dump(mode="json")
    elif baseline_trace is not None and isinstance(baseline_trace.get("accounting"), dict):
        source = dict(baseline_trace["accounting"])
    else:
        source = {}
    attacker_decision_calls = int(source.get("attacker_decision_calls", 0))
    victim_gateway_requests = int(source.get("victim_gateway_requests", 0))
    raw_completions = source.get("victim_provider_completions_when_observable")
    victim_completions = int(raw_completions) if isinstance(raw_completions, int) else None
    gaps = [
        str(item) for item in source.get("instrumentation_gap_reasons", []) if isinstance(item, str)
    ]
    for item in model_call_events:
        if item.get("kind") in {"model_call_response", "model_call_error"}:
            gaps.extend(
                str(reason)
                for reason in item.get("instrumentation_gap_reasons", [])
                if isinstance(reason, str)
            )
    gaps.append("embedding_call_count_not_instrumented")

    def optional_nonnegative_int(value: Any) -> int | None:
        return (
            int(value)
            if isinstance(value, int) and not isinstance(value, bool) and value >= 0
            else None
        )

    def usage_value(usage: dict[str, Any], names: tuple[str, ...]) -> int | None:
        for name in names:
            value = optional_nonnegative_int(usage.get(name))
            if value is not None:
                return value
        return None

    victim_input_tokens = optional_nonnegative_int(source.get("input_tokens"))
    victim_output_tokens = optional_nonnegative_int(source.get("output_tokens"))
    victim_cached_tokens = optional_nonnegative_int(source.get("cached_tokens"))
    model_usages: list[dict[str, Any]] = []
    model_usage_complete = True
    for request in model_requests:
        response = model_responses.get(str(request.get("call_id")))
        usage = response.get("usage") if response is not None else None
        if not isinstance(usage, dict):
            model_usage_complete = False
            continue
        model_usages.append(usage)
    model_input_tokens = [
        usage_value(usage, ("input_tokens", "prompt_tokens", "promptTokenCount"))
        for usage in model_usages
    ]
    model_output_tokens = [
        usage_value(usage, ("output_tokens", "completion_tokens", "candidatesTokenCount"))
        for usage in model_usages
    ]
    model_cached_tokens = [
        usage_value(usage, ("cached_tokens", "cachedContentTokenCount")) for usage in model_usages
    ]
    input_tokens = (
        victim_input_tokens + sum(value for value in model_input_tokens if value is not None)
        if (
            victim_input_tokens is not None
            and model_usage_complete
            and all(value is not None for value in model_input_tokens)
        )
        else None
    )
    output_tokens = (
        victim_output_tokens + sum(value for value in model_output_tokens if value is not None)
        if (
            victim_output_tokens is not None
            and model_usage_complete
            and all(value is not None for value in model_output_tokens)
        )
        else None
    )
    cached_tokens = (
        victim_cached_tokens + sum(value for value in model_cached_tokens if value is not None)
        if (
            victim_cached_tokens is not None
            and model_usage_complete
            and all(value is not None for value in model_cached_tokens)
        )
        else None
    )
    raw_cost = source.get("provider_cost")
    victim_cost = (
        float(raw_cost)
        if isinstance(raw_cost, (int, float)) and not isinstance(raw_cost, bool) and raw_cost >= 0
        else None
    )
    provider_cost = victim_cost if not model_requests else None
    if input_tokens is None or output_tokens is None:
        gaps.append("aggregate_token_usage_not_observable")
    if provider_cost is None:
        gaps.append("aggregate_provider_cost_not_observable")
    return FormalExecutionAccounting(
        planner_model_calls=planner_model_calls,
        attacker_model_calls=attacker_model_calls,
        attacker_decision_calls=attacker_decision_calls,
        victim_gateway_requests=victim_gateway_requests,
        victim_provider_completions_when_observable=victim_completions,
        gemini_native_calls=gemini_native_calls,
        embedding_calls_when_observable=None,
        whole_episode_attempts=episode_attempts,
        input_tokens=input_tokens,
        output_tokens=output_tokens,
        cached_tokens=cached_tokens,
        provider_cost_when_returned=provider_cost,
        wall_time_ms=wall_time_ms,
        instrumentation_gap_reasons=list(dict.fromkeys(gaps)),
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
    attacker: FormalAttacker | None = None,
    interactive_driver_factory: (Callable[[str], SafeClawInteractiveVictimDriver] | None) = None,
    after_case: Callable[[int], None] | None = None,
) -> Path:
    if not config.execution_enabled:
        raise ValueError("formal_execution_disabled_by_config")
    env = environment if environment is not None else os.environ
    formal_attacker = attacker or _configured_attacker(project_root, config)
    llm_planner = _configured_llm_planner(project_root, config)
    target_model = env.get(config.target_model_env)
    if (
        target_model
        and config.allowed_target_models
        and target_model not in config.allowed_target_models
    ):
        raise ValueError(f"formal_target_model_not_allowed:{target_model}")
    environment_config = load_safeclaw_preflight_config(
        project_root / config.environment_config_path
    )
    target_contract = (
        config.target_model_env,
        config.target_base_url_env,
        config.target_api_key_env,
        config.allowed_target_models,
    )
    environment_target_contract = (
        environment_config.target_model_env,
        environment_config.target_base_url_env,
        environment_config.target_api_key_env,
        environment_config.allowed_target_models,
    )
    if target_contract != environment_target_contract:
        raise ValueError("formal_environment_target_contract_mismatch")
    required_env = [
        config.target_model_env,
        config.target_base_url_env,
        config.target_api_key_env,
    ]
    embedding: SafeClawEmbeddingRuntime | None = None
    if environment_config.embedding_policy == "required_endpoint":
        embedding_fields = (
            environment_config.embedding_provider,
            environment_config.embedding_model_env,
            environment_config.embedding_base_url_env,
            environment_config.embedding_api_key_env,
        )
        if not all(embedding_fields):
            raise ValueError("formal_embedding_configuration_incomplete")
        embedding_model_env = str(environment_config.embedding_model_env)
        embedding_base_url_env = str(environment_config.embedding_base_url_env)
        embedding_api_key_env = str(environment_config.embedding_api_key_env)
        required_env.extend([embedding_model_env, embedding_base_url_env, embedding_api_key_env])
    missing_env = sorted({name for name in required_env if not env.get(name)})
    if missing_env:
        raise ValueError("missing_formal_environment_variables:" + ",".join(missing_env))
    if environment_config.embedding_policy == "required_endpoint":
        if environment_config.embedding_provider != "openai":
            raise ValueError("formal_embedding_provider_unsupported")
        embedding = SafeClawEmbeddingRuntime(
            provider="openai",
            model_id=str(env[embedding_model_env]),
            base_url=str(env[embedding_base_url_env]),
            api_key_env=embedding_api_key_env,
        )
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
    target_base_url = str(env[config.target_base_url_env])
    exact_secrets = [api_key, target_base_url]
    if embedding is not None:
        exact_secrets.extend([str(env[embedding.api_key_env]), embedding.base_url])
    recorder = FormalRunRecorder(run_root, list(dict.fromkeys(exact_secrets)))
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
    if not public_samples:
        raise ValueError("formal_library_has_no_public_samples")
    scheduler = FormalAssignmentScheduler()
    task_set_hash = file_hash(project_root / config.task_set_path)
    prepared_cases: list[
        tuple[
            str,
            str,
            str,
            FormalCondition,
            int,
            FormalTaskEntry,
            SafeClawTaskDescriptor,
            FormalCaseAssignment,
            FormalPlannerInput,
        ]
    ] = []
    assignments: list[FormalCaseAssignment] = []
    for case_id, pair_id, task_id, condition, seed, task in cases:
        template_path = project_root / task.template_path
        if file_hash(template_path) != task.template_hash:
            raise ValueError(f"formal_task_template_hash_mismatch:{task_id}")
        descriptor = parse_safeclaw_task(
            template_path,
            upstream_root=project_root,
            upstream_commit=task_set.upstream_commit,
            formal_experiment=task.formal_experiment,
        )
        if descriptor.task_id != task_id:
            raise ValueError("formal_task_entry_identity_mismatch")
        assignment = scheduler.assign(
            case_id=case_id,
            pair_group=pair_id,
            condition=condition,
            seed=seed,
            budget=config.budget,
            public_task=descriptor.public_view,
            benchmark_public_prompt=descriptor.benchmark_public_prompt,
            public_samples=public_samples,
            task_set_hash=task_set_hash,
            library_hash=library.manifest.tree_hash,
            registry_hash=registry.registry_hash,
        )
        planner_input = scheduler.planner_input(assignment, descriptor.public_view, public_samples)
        assignments.append(assignment)
        prepared_cases.append(
            (
                case_id,
                pair_id,
                task_id,
                condition,
                seed,
                task,
                descriptor,
                assignment,
                planner_input,
            )
        )
    assert_pair_invariants(assignments)
    for (
        case_id,
        pair_id,
        _task_id,
        condition,
        seed,
        task,
        descriptor,
        assignment,
        planner_input,
    ) in prepared_cases:
        if case_id in completed_ids:
            continue
        try:
            template_path = project_root / task.template_path
            case_planner = _planner(condition, assignment.selected_sample_id, llm_planner)
            model_call_path = run_root / "cases" / case_id / "model_calls.jsonl"
            if isinstance(case_planner, FormalLLMPlanner):
                case_planner.set_call_recorder(
                    ObservableModelCallRecorder(
                        path=model_call_path,
                        case_id=case_id,
                        role="planner",
                        prompt=case_planner.trajectory_prompt or case_planner.prompt,
                        exact_secrets=[api_key, target_base_url],
                    )
                )
            if isinstance(formal_attacker, ModelFormalAttacker):
                formal_attacker.set_call_recorder(
                    ObservableModelCallRecorder(
                        path=model_call_path,
                        case_id=case_id,
                        role="attacker",
                        prompt=formal_attacker.prompt,
                        exact_secrets=[api_key, target_base_url],
                    )
                )
            plan = case_planner.plan(planner_input)
            if plan.selected_sample_id != assignment.selected_sample_id:
                raise ValueError("planner_changed_scheduler_assignment")
            realization: FormalAttackRealization | None = None
            dependency_ablation_record: dict[str, Any] | None = None
            attacker_input = None
            if plan.selected_sample_id is None:
                if plan.baseline_binding is None:
                    raise ValueError(f"formal_planner_abstained:{plan.abstain_reason}")
                selected_public = None
                execution_view = None
                slot_values = dict(task.baseline_materialization_values)
            else:
                selected_public = planner_input.selected_sample
                if selected_public is None:
                    raise ValueError("assigned_planner_sample_missing")
                execution_view = library.execution_view(plan.selected_sample_id)
                if not config.attacker_stage_implemented or formal_attacker is None:
                    raise ValueError("independent_formal_attacker_required")
                attacker_input = make_formal_attacker_input(
                    case_id=case_id,
                    public_task=descriptor.public_view,
                    benchmark_public_prompt=descriptor.benchmark_public_prompt,
                    execution_view=execution_view,
                    plan=plan,
                )
                realization = formal_attacker.realize(attacker_input, seed=seed)
                slot_values = dict(realization.public_slot_values)
                if plan.dependency_ablation is not None:
                    intervention = plan.dependency_ablation
                    slot_id = intervention.materialization_slot_id
                    if slot_id not in task.sample_derived_slots:
                        raise ValueError(
                            "dependency_ablation_slot_not_preregistered_as_sample_derived"
                        )
                    if slot_id not in slot_values:
                        raise ValueError("dependency_ablation_treatment_slot_missing")
                    if slot_id not in task.baseline_materialization_values:
                        raise ValueError("dependency_ablation_baseline_slot_missing")
                    treatment_value = slot_values[slot_id]
                    replacement_value = task.baseline_materialization_values[slot_id]
                    if treatment_value == replacement_value:
                        raise ValueError("dependency_ablation_replacement_has_no_delta")
                    slot_values[slot_id] = replacement_value
                    dependency_ablation_record = {
                        **intervention.model_dump(mode="json"),
                        "treatment_value_hash": stable_hash(treatment_value),
                        "replacement_value_hash": stable_hash(replacement_value),
                        "replacement_applied": True,
                        "changed_slot_count": 1,
                    }
            recorder.record_artifact(
                case_id, FormalStage.planned, "formal_case_assignment", assignment
            )
            recorder.record_artifact(case_id, FormalStage.planned, "planner_input", planner_input)
            recorder.record_artifact(case_id, FormalStage.planned, "evaluation_plan", plan)
            if attacker_input is not None and realization is not None:
                recorder.record_artifact(
                    case_id,
                    FormalStage.planned,
                    "formal_attacker_input",
                    attacker_input,
                )
                recorder.record_artifact(
                    case_id,
                    FormalStage.planned,
                    "formal_attack_setup",
                    realization,
                )
            if dependency_ablation_record is not None:
                recorder.record_artifact(
                    case_id,
                    FormalStage.planned,
                    "dependency_ablation",
                    dependency_ablation_record,
                )
            sanitized: dict[str, Any] | None = None
            interactive_loop: FormalActionLoopResult | None = None
            baseline_trace: dict[str, Any] | None = None
            with tempfile.TemporaryDirectory(prefix="formal-materialization-") as temporary:
                materialized = materialize_safeclaw_task(
                    template_path,
                    descriptor,
                    plan,
                    execution_view,
                    slot_values,
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
                    embedding=embedding,
                    timeout_seconds=config.timeout_seconds,
                    max_attempts=config.max_attempts,
                    output_root=str(run_root / "runner"),
                    seed=seed,
                    condition=condition,
                )
                if attacker_input is not None and realization is not None:
                    assert formal_attacker is not None
                    driver = (
                        interactive_driver_factory(case_id)
                        if interactive_driver_factory is not None
                        else SafeClawInteractiveVictimDriver(
                            upstream_root=upstream_root,
                            safety_patch=safety_patch,
                            bridge_path=(project_root / "integrations/safeclaw/formal_bridge.py"),
                            case_root=episode_runner.output_root / case_id,
                            target_model_id=request.target_model_id,
                            target_base_url=request.target_base_url,
                            target_api_key_env=request.target_api_key_env,
                            embedding=request.embedding,
                            environment=env,
                        )
                    )
                    episode, sanitized, interactive_loop = run_interactive_episode(
                        request=request,
                        materialized_task=materialized,
                        attacker=formal_attacker,
                        attacker_input=attacker_input,
                        setup_realization=realization,
                        driver=driver,
                        output_root=episode_runner.output_root,
                        upstream_commit=preflight.upstream_commit,
                        safety_patch_hash=preflight.patch_hash or file_hash(safety_patch),
                        resume=True,
                    )
                    realization = interactive_loop.realization
                else:
                    driver = (
                        interactive_driver_factory(case_id)
                        if interactive_driver_factory is not None
                        else SafeClawInteractiveVictimDriver(
                            upstream_root=upstream_root,
                            safety_patch=safety_patch,
                            bridge_path=(project_root / "integrations/safeclaw/formal_bridge.py"),
                            case_root=episode_runner.output_root / case_id,
                            target_model_id=request.target_model_id,
                            target_base_url=request.target_base_url,
                            target_api_key_env=request.target_api_key_env,
                            embedding=request.embedding,
                            environment=env,
                        )
                    )
                    episode, sanitized, baseline_trace = run_interactive_baseline_episode(
                        request=request,
                        materialized_task=materialized,
                        driver=driver,
                        output_root=episode_runner.output_root,
                        upstream_commit=preflight.upstream_commit,
                        safety_patch_hash=(preflight.patch_hash or file_hash(safety_patch)),
                        max_sessions=plan.budget.max_sessions,
                        max_turns=plan.budget.max_turns,
                        resume=True,
                    )
            if realization is not None:
                recorder.record_artifact(
                    case_id,
                    FormalStage.executed,
                    "formal_attack_realization",
                    realization,
                )
            if interactive_loop is not None:
                recorder.record_artifact(
                    case_id,
                    FormalStage.executed,
                    "formal_action_loop",
                    interactive_loop,
                )
            if baseline_trace is not None:
                recorder.record_artifact(
                    case_id,
                    FormalStage.executed,
                    "formal_baseline_replay",
                    baseline_trace,
                )
            recorder.record_artifact(case_id, FormalStage.executed, "episode_result", episode)
            if sanitized is None and episode.sanitized_result_ref:
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
                action_journal: list[dict[str, Any]] = []
                trajectory_ref = Path(episode.canonical_trajectory_ref or "")
                if trajectory_ref.name == "formal_action_journal.jsonl":
                    if trajectory_ref.is_absolute() or ".." in trajectory_ref.parts:
                        raise ValueError("formal_canonical_trajectory_ref_unsafe")
                    journal_path = episode_runner.output_root / case_id / trajectory_ref
                    if journal_path.is_file():
                        action_journal = read_jsonl(journal_path)
                graph, trajectory_audit = normalize_safeclaw_episode(
                    episode,
                    descriptor,
                    sanitized,
                    action_journal_records=action_journal,
                )
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
                if selected_public is not None and execution_view is not None:
                    mechanism = evaluate_formal_mechanism(
                        planner_view=selected_public.planner_view,
                        execution_view=execution_view,
                        occurrences=extraction.occurrences,
                        graph=graph,
                        registry=registry,
                        official_terminal_success=official.attack_succeeded is True,
                        action_observations=(
                            interactive_loop.observations if interactive_loop is not None else None
                        ),
                    )
                artifact_paths.update(
                    {
                        "interaction_graph": graph_record.relative_path,
                        "trajectory_audit": audit_record.relative_path,
                        "primitive_extraction": occurrence_record.relative_path,
                    }
                )
            dependency_ablation_evaluation: DependencyAblationEvaluation | None = None
            if plan.dependency_ablation is not None:
                if selected_public is None:
                    raise ValueError("dependency_ablation_selected_sample_missing")
                target_edge = next(
                    (
                        edge
                        for edge in selected_public.planner_view.core_edges
                        if edge.edge_id == plan.dependency_ablation.target_edge_id
                        and edge.required_for_full_chain
                    ),
                    None,
                )
                if target_edge is None:
                    raise ValueError("dependency_ablation_target_edge_not_in_sample")
                target_verdict = next(
                    (
                        verdict
                        for verdict in mechanism.edge_verdicts
                        if (
                            verdict.edge_id == target_edge.edge_id
                            or verdict.edge_id.endswith(f":{target_edge.edge_id}")
                        )
                    ),
                    None,
                )
                observed_verdict = target_verdict.verdict if target_verdict is not None else None
                if observed_verdict in {CausalVerdict.fail, CausalVerdict.not_reached}:
                    dependency_absent: bool | None = True
                    reason_codes = ["target_dependency_absent"]
                elif observed_verdict == CausalVerdict.causal_pass:
                    dependency_absent = False
                    reason_codes = ["target_dependency_still_present"]
                else:
                    dependency_absent = None
                    reason_codes = ["target_dependency_not_observable"]
                dependency_ablation_evaluation = DependencyAblationEvaluation(
                    intervention_id=plan.dependency_ablation.intervention_id,
                    target_edge_id=plan.dependency_ablation.target_edge_id,
                    observed_mechanism_edge_id=(
                        target_verdict.edge_id if target_verdict is not None else None
                    ),
                    observed_verdict=observed_verdict,
                    target_dependency_absent=dependency_absent,
                    reason_codes=reason_codes,
                )
                ablation_evaluation_record = recorder.record_artifact(
                    case_id,
                    FormalStage.verified,
                    "dependency_ablation_evaluation",
                    dependency_ablation_evaluation,
                )
                artifact_paths["dependency_ablation_evaluation"] = (
                    ablation_evaluation_record.relative_path
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
            model_call_events = read_jsonl(model_call_path)
            model_call_record = recorder.record_artifact(
                case_id,
                FormalStage.verified,
                "model_call_events",
                model_call_events,
            )
            artifact_paths["model_call_events"] = model_call_record.relative_path
            planner_model_events = [
                item for item in model_call_events if item.get("role") == "planner"
            ]
            attacker_model_events = [
                item for item in model_call_events if item.get("role") == "attacker"
            ]
            planner_requests = [
                item for item in planner_model_events if item.get("kind") == "model_call_request"
            ]
            attacker_requests = [
                item for item in attacker_model_events if item.get("kind") == "model_call_request"
            ]
            accounting = _formal_execution_accounting(
                model_call_events=model_call_events,
                interactive_loop=interactive_loop,
                baseline_trace=baseline_trace,
                episode_attempts=episode.attempt_count,
                wall_time_ms=episode.duration_ms,
            )
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
                    "model_id": (planner_requests[0].get("model_id") if planner_requests else None),
                    "prompt_asset": (
                        {
                            "prompt_id": planner_requests[0].get("prompt_id"),
                            "version": planner_requests[0].get("prompt_version"),
                            "hash": planner_requests[0].get("prompt_hash"),
                        }
                        if planner_requests
                        else None
                    ),
                    "messages": [
                        message
                        for request in planner_requests
                        for message in request.get("request_messages", [])
                    ],
                    "model_calls": planner_model_events,
                    "input": planner_input.model_dump(mode="json"),
                    "output": plan.model_dump(mode="json"),
                    "reason": (None if planner_requests else "deterministic_planner_no_model_call"),
                },
                "attacker_stage": {
                    "implemented": realization is not None,
                    "model_id": (
                        attacker_requests[0].get("model_id") if attacker_requests else None
                    ),
                    "prompt_asset": (
                        {
                            "prompt_id": attacker_requests[0].get("prompt_id"),
                            "version": attacker_requests[0].get("prompt_version"),
                            "hash": attacker_requests[0].get("prompt_hash"),
                        }
                        if attacker_requests
                        else None
                    ),
                    "messages": [
                        message
                        for request in attacker_requests
                        for message in request.get("request_messages", [])
                    ],
                    "model_calls": attacker_model_events,
                    "input": attacker_input.model_dump(mode="json") if attacker_input else None,
                    "output": realization.model_dump(mode="json") if realization else None,
                    "reason": (
                        None
                        if attacker_requests
                        else (
                            "deterministic_attacker_no_model_call"
                            if realization is not None
                            else "legal_baseline_condition"
                        )
                    ),
                },
                "attack_realization": {
                    "selected_sample": (
                        selected_public.model_dump(mode="json") if selected_public else None
                    ),
                    "execution_view": (
                        execution_view.model_dump(mode="json") if execution_view else None
                    ),
                    "binding_manifest": binding_payload,
                    "independent_attacker_realization": (
                        realization.model_dump(mode="json") if realization else None
                    ),
                    "materialized_task": materialized_task_payload,
                    "dependency_ablation": dependency_ablation_record,
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
                    "dependency_ablation_evaluation": (
                        dependency_ablation_evaluation.model_dump(mode="json")
                        if dependency_ablation_evaluation is not None
                        else None
                    ),
                },
                "official_evaluation": official.model_dump(mode="json"),
                "accounting": accounting.model_dump(mode="json"),
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
                tokens=(
                    accounting.input_tokens + accounting.output_tokens
                    if accounting.input_tokens is not None and accounting.output_tokens is not None
                    else None
                ),
                api_calls=accounting.total_known_api_requests,
                cost=accounting.provider_cost_when_returned,
                accounting=accounting,
                dependency_ablation_evaluation=dependency_ablation_evaluation,
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
