from __future__ import annotations

import json
import os
import re
from collections.abc import Mapping
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Literal

from pydantic import Field, PositiveInt, model_validator

from stac_attack_lab.contracts import StrictModel
from stac_attack_lab.environments.safeclaw.evidence_policy import (
    disabled_provider_evidence_policy,
    validate_provider_evidence_policy,
)
from stac_attack_lab.environments.safeclaw.model_config import SafeClawEmbeddingRuntime
from stac_attack_lab.execution.flow_reanalysis import reanalyze_flow_v3
from stac_attack_lab.flow.analysis import (
    AnalysisManifest,
    AnalysisOutputRef,
    GateStatus,
    LayeredAdmission,
    SliceBudget,
)
from stac_attack_lab.flow.models import ClaimVerdict, DependencyRelation, EffectGraph
from stac_attack_lab.hashing import file_hash, stable_hash
from stac_attack_lab.interactions.base import CollectionBudget
from stac_attack_lab.interactions.benign import (
    BenignScenarioAdapter,
    BenignScenarioSet,
    SafeClawBenignInteractionAdapter,
)
from stac_attack_lab.interactions.collector import InteractionCollectionPlan, collect_interactions
from stac_attack_lab.interactions.safeclaw_collection import (
    SAFECLAW_CONSTRUCTION_TOOLS,
    ConstructionVictimDriver,
    SafeClawConstructionTaskSet,
    SafeClawSubprocessVictimDriver,
)

_SAFE_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]*$")


class BenignCollectionConfig(StrictModel):
    schema_version: Literal["1.0"] = "1.0"
    study_id: str
    collection_id: str
    collection_mode: Literal["benign_interaction"] = "benign_interaction"
    source_mode: Literal["synthetic_fixture", "safeclaw_derived"]
    scenario_set_path: str
    scenario_ids: list[str]
    environment_version: str
    target_agent_config_hash: str
    interaction_policy_id: str
    prompt_path: str
    prompt_version: str
    request_caps_by_role: dict[str, PositiveInt]
    wall_clock_seconds: PositiveInt
    seed: int
    profile_path: str
    registry_path: str
    output_root: str
    execution_enabled: bool = False
    max_events: PositiveInt = 200
    max_sessions: PositiveInt = 4
    max_turns: PositiveInt = 8
    max_actions: PositiveInt = 12
    max_tool_calls: PositiveInt = 16
    timeout_seconds: PositiveInt = 300
    max_tokens: PositiveInt = 8192
    allowed_source_splits: list[Literal["synthetic", "development", "validation"]] = ["synthetic"]
    safeclaw_task_set_path: str | None = None
    upstream_dir: str | None = None
    safety_patch_path: str | None = None
    construction_bridge_path: str | None = None
    victim_model_env: str | None = None
    victim_base_url_env: str | None = None
    victim_api_key_env: str | None = None
    allowed_victim_models: list[str] = Field(default_factory=list)
    victim_model_hash: str | None = None
    embedding_provider: Literal["openai", "ark_multimodal"] | None = None
    embedding_model_env: str | None = None
    embedding_base_url_env: str | None = None
    embedding_api_key_env: str | None = None
    provider_request_budget: PositiveInt = 1
    provider_timeout_seconds: PositiveInt = 90
    provider_allowed_tools: list[str] | None = None
    embedding_request_budget: PositiveInt = 1
    provider_evidence_policy: dict[str, Any] = Field(
        default_factory=disabled_provider_evidence_policy
    )
    image_tag: str = "openclaw-env:2026.3.12"
    minimum_free_disk_gb: PositiveInt = 20
    safety_constraint_ids: list[str] = Field(
        default_factory=lambda: [
            "synthetic_canary_only",
            "no_external_network",
            "no_host_files",
            "no_real_credentials",
            "isolated_container",
        ]
    )

    @model_validator(mode="after")
    def validate_config(self) -> BenignCollectionConfig:
        if self.collection_id in {".", ".."} or not _SAFE_ID.fullmatch(self.collection_id):
            raise ValueError("benign_collection_id_invalid")
        if not self.scenario_ids or len(self.scenario_ids) != len(set(self.scenario_ids)):
            raise ValueError("benign_collection_scenario_ids_invalid")
        if set(self.request_caps_by_role) != {"target_agent", "interaction_policy"}:
            raise ValueError("benign_collection_request_roles_invalid")
        if self.request_caps_by_role["target_agent"] != self.provider_request_budget:
            raise ValueError("benign_collection_target_request_budget_mismatch")
        if self.source_mode == "synthetic_fixture" and self.execution_enabled:
            raise ValueError("benign_fixture_collection_cannot_enable_live_execution")
        if self.interaction_policy_id != "stac.benign.scripted-cooperative":
            raise ValueError("benign_collection_policy_unsupported")
        if self.prompt_version != "1.0.0":
            raise ValueError("benign_collection_prompt_version_unsupported")
        if len(self.target_agent_config_hash) != 64 or any(
            char not in "0123456789abcdef" for char in self.target_agent_config_hash
        ):
            raise ValueError("benign_collection_target_agent_hash_invalid")
        CollectionBudget(
            max_sessions=self.max_sessions,
            max_turns=self.max_turns,
            max_actions=self.max_actions,
            max_tool_calls=self.max_tool_calls,
            max_tokens=self.max_tokens,
            max_wall_time_seconds=self.wall_clock_seconds,
            max_events=self.max_events,
            timeout_seconds=self.timeout_seconds,
        )
        self.provider_evidence_policy = validate_provider_evidence_policy(
            self.provider_evidence_policy
        )
        if self.source_mode == "safeclaw_derived":
            required = {
                "safeclaw_task_set_path": self.safeclaw_task_set_path,
                "upstream_dir": self.upstream_dir,
                "safety_patch_path": self.safety_patch_path,
                "construction_bridge_path": self.construction_bridge_path,
                "victim_model_env": self.victim_model_env,
                "victim_base_url_env": self.victim_base_url_env,
                "victim_api_key_env": self.victim_api_key_env,
                "victim_model_hash": self.victim_model_hash,
                "embedding_provider": self.embedding_provider,
                "embedding_model_env": self.embedding_model_env,
                "embedding_base_url_env": self.embedding_base_url_env,
                "embedding_api_key_env": self.embedding_api_key_env,
            }
            missing = [key for key, value in required.items() if value is None]
            if missing:
                raise ValueError("benign_live_configuration_missing:" + ",".join(missing))
            if set(self.provider_allowed_tools or []) != SAFECLAW_CONSTRUCTION_TOOLS:
                raise ValueError("benign_live_tool_scope_mismatch")
            required_safety = {
                "synthetic_canary_only",
                "no_external_network",
                "no_host_files",
                "no_real_credentials",
                "isolated_container",
            }
            if not required_safety <= set(self.safety_constraint_ids):
                raise ValueError("benign_live_safety_constraints_missing")
            expected_target_hash = stable_hash(
                {
                    "environment_version": self.environment_version,
                    "victim_model_hash": self.victim_model_hash,
                    "allowed_victim_models": self.allowed_victim_models,
                    "embedding_provider": self.embedding_provider,
                    "image_tag": self.image_tag,
                    "provider_allowed_tools": self.provider_allowed_tools,
                    "provider_evidence_policy": self.provider_evidence_policy,
                }
            )
            if self.target_agent_config_hash != expected_target_hash:
                raise ValueError("benign_live_target_agent_config_hash_mismatch")
        return self


class BenignSourceModeManifest(StrictModel):
    schema_version: Literal["1.0"] = "1.0"
    study_id: str
    collection_id: str
    source_mode: Literal["benign_interaction"] = "benign_interaction"
    fixture_or_runtime_mode: Literal["synthetic_fixture", "safeclaw_derived"]
    config_hash: str
    scenario_set_hash: str
    scenario_ids: list[str]
    scenario_mapping_hashes: dict[str, str]
    interaction_policy_id: str
    prompt_hash: str
    profile_hash: str
    registry_hash: str
    collection_manifest_hash: str
    trajectory_hashes: dict[str, str]
    processing_source_hashes: dict[str, str]
    security_evaluator_used: Literal[False] = False
    attack_objective_exposed_to_policy: Literal[False] = False
    real_model_requests: bool = False
    real_model_request_status: Literal["not_performed", "observed", "unknown"] = "not_performed"
    manifest_hash: str

    @model_validator(mode="after")
    def validate_hash(self) -> BenignSourceModeManifest:
        payload = self.model_dump(mode="json", exclude={"manifest_hash"})
        if stable_hash(payload) != self.manifest_hash:
            raise ValueError("benign_source_mode_manifest_hash_mismatch")
        return self


class BenignPreparationManifest(StrictModel):
    schema_version: Literal["1.0"] = "1.0"
    preparation_id: str
    config_hash: str
    scenario_set_hash: str
    prompt_hash: str
    execution_enabled: Literal[False]
    network_requests_performed: Literal[False] = False
    manifest_hash: str

    @model_validator(mode="after")
    def validate_hash(self) -> BenignPreparationManifest:
        payload = self.model_dump(mode="json", exclude={"manifest_hash"})
        if stable_hash(payload) != self.manifest_hash:
            raise ValueError("benign_preparation_manifest_hash_mismatch")
        return self


class BenignTraceAssessment(StrictModel):
    schema_version: Literal["1.0"] = "1.0"
    trajectory_id: str
    observation_valid: GateStatus
    normal_task_completion: GateStatus
    planning_reference_eligible: GateStatus
    verified_dependency_claim_count: int = Field(ge=0)
    unknown_dependency_claim_count: int = Field(ge=0)
    cross_session_capability: GateStatus
    reason_codes: list[str]
    security_outcome: Literal["not_evaluated"] = "not_evaluated"


def _assess_benign_analysis(
    analysis_root: Path, completion_by_trajectory: Mapping[str, GateStatus] | None = None
) -> list[BenignTraceAssessment]:
    assessments: list[BenignTraceAssessment] = []
    for graph_path in sorted((analysis_root / "graphs").glob("*.json")):
        stem = graph_path.name.removesuffix(".effect_graph.json")
        graph = EffectGraph.model_validate_json(graph_path.read_text(encoding="utf-8"))
        admission = LayeredAdmission.model_validate_json(
            (analysis_root / "admission" / f"{stem}.json").read_text(encoding="utf-8")
        )
        descriptive = admission.profiles[0]
        observed_effects = [
            item
            for item in graph.effects
            if item.execution_status.value in {"observed", "committed"}
        ]
        observation_valid = descriptive.status
        reasons = list(descriptive.reason_codes)
        completion = (completion_by_trajectory or {}).get(
            graph.source_graph_id.removeprefix("graph-"), GateStatus.unknown
        )
        planning_status = GateStatus.unknown
        if (
            observation_valid == GateStatus.passed
            and observed_effects
            and completion == GateStatus.passed
        ):
            planning_status = GateStatus.passed
            reasons.append("benign_observed_effects_available_as_planning_reference")
        elif not observed_effects:
            reasons.append("benign_observed_effects_missing")
        elif completion != GateStatus.passed:
            reasons.append("benign_normal_task_completion_not_verified")
        verified_claims = [
            item for item in graph.claims if item.dependency_verdict == ClaimVerdict.verified
        ]
        unknown_claims = [
            item for item in graph.claims if item.dependency_verdict == ClaimVerdict.unknown
        ]
        sessions = {
            item.actual_session_id for item in graph.domains if item.actual_session_id is not None
        }
        read_from = [
            item for item in verified_claims if item.relation == DependencyRelation.read_from
        ]
        cross_status = GateStatus.not_applicable
        if len(sessions) > 1:
            cross_status = GateStatus.passed if read_from else GateStatus.unknown
            if not read_from:
                reasons.append("benign_cross_session_read_from_not_verified")
        assessments.append(
            BenignTraceAssessment(
                trajectory_id=graph.source_graph_id,
                observation_valid=observation_valid,
                normal_task_completion=completion,
                planning_reference_eligible=planning_status,
                verified_dependency_claim_count=len(verified_claims),
                unknown_dependency_claim_count=len(unknown_claims),
                cross_session_capability=cross_status,
                reason_codes=sorted(set(reasons)),
            )
        )
    return assessments


def _atomic_json(path: Path, value: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    os.chmod(temporary, 0o600)
    temporary.replace(path)


def load_benign_collection_config(path: Path) -> BenignCollectionConfig:
    return BenignCollectionConfig.model_validate_json(path.read_text(encoding="utf-8"))


def validate_benign_collection_config(
    project_root: Path, config_path: Path
) -> tuple[BenignCollectionConfig, BenignScenarioSet]:
    config = load_benign_collection_config(config_path)
    allowed_output = (project_root / "experiments" / "runs").resolve()
    output = (project_root / config.output_root).resolve()
    if output != allowed_output and allowed_output not in output.parents:
        raise ValueError("benign_collection_output_outside_allowed_directory")
    scenario_path = project_root / config.scenario_set_path
    scenarios = BenignScenarioSet.model_validate_json(scenario_path.read_text(encoding="utf-8"))
    selected = [item for item in scenarios.scenarios if item.scenario_id in config.scenario_ids]
    if {item.scenario_id for item in selected} != set(config.scenario_ids):
        raise ValueError("benign_collection_scenario_missing")
    if any(item.environment_version != config.environment_version for item in selected):
        raise ValueError("benign_collection_environment_version_mismatch")
    expected_source = (
        "independent_synthetic" if config.source_mode == "synthetic_fixture" else "safeclaw_derived"
    )
    if any(item.source_task_mapping.source_kind != expected_source for item in selected):
        raise ValueError("benign_collection_source_mode_mapping_mismatch")
    prompt = project_root / config.prompt_path
    if not prompt.is_file():
        raise ValueError("benign_collection_policy_prompt_missing")
    for path in (project_root / config.profile_path, project_root / config.registry_path):
        if not path.is_file():
            raise ValueError("benign_collection_v3_contract_missing")
    if config.source_mode == "safeclaw_derived":
        required_paths = (
            config.safeclaw_task_set_path,
            config.upstream_dir,
            config.safety_patch_path,
            config.construction_bridge_path,
        )
        if any(value is None or not (project_root / value).exists() for value in required_paths):
            raise ValueError("benign_live_required_path_missing")
        task_set_path = project_root / str(config.safeclaw_task_set_path)
        task_set = SafeClawConstructionTaskSet.model_validate_json(
            task_set_path.read_text(encoding="utf-8")
        )
        tasks = {item.source_task_id: item for item in task_set.tasks}
        for scenario in selected:
            mapping = scenario.source_task_mapping
            if mapping.runtime_task_id not in tasks:
                raise ValueError("benign_live_runtime_task_missing")
            task = tasks[str(mapping.runtime_task_id)]
            template = project_root / task.template_path
            if not template.is_file() or file_hash(template) != task.template_hash:
                raise ValueError("benign_live_runtime_task_hash_mismatch")
            if task.template_hash != mapping.sanitized_task_hash:
                raise ValueError("benign_live_sanitized_mapping_hash_mismatch")
    return config, scenarios


def _build_live_driver(
    project_root: Path,
    config: BenignCollectionConfig,
    environment: Mapping[str, str],
    *,
    batch_id: str,
) -> SafeClawSubprocessVictimDriver:
    env_names = (
        config.victim_model_env,
        config.victim_base_url_env,
        config.victim_api_key_env,
        config.embedding_model_env,
        config.embedding_base_url_env,
        config.embedding_api_key_env,
    )
    if any(item is None for item in env_names) or config.embedding_provider is None:
        raise ValueError("benign_live_environment_contract_incomplete")
    victim_model = environment.get(str(config.victim_model_env))
    victim_base_url = environment.get(str(config.victim_base_url_env))
    embedding_model = environment.get(str(config.embedding_model_env))
    embedding_base_url = environment.get(str(config.embedding_base_url_env))
    if not all(
        (
            victim_model,
            victim_base_url,
            environment.get(str(config.victim_api_key_env)),
            embedding_model,
            embedding_base_url,
            environment.get(str(config.embedding_api_key_env)),
        )
    ):
        raise ValueError("benign_live_environment_missing")
    if config.allowed_victim_models and victim_model not in config.allowed_victim_models:
        raise ValueError("benign_live_victim_model_not_allowed")
    return SafeClawSubprocessVictimDriver(
        project_root=project_root,
        upstream_root=project_root / str(config.upstream_dir),
        safety_patch=project_root / str(config.safety_patch_path),
        bridge_path=project_root / str(config.construction_bridge_path),
        target_model_id=str(victim_model),
        target_base_url=str(victim_base_url),
        target_api_key_env=str(config.victim_api_key_env),
        embedding=SafeClawEmbeddingRuntime(
            provider=config.embedding_provider,
            model_id=str(embedding_model),
            base_url=str(embedding_base_url),
            api_key_env=str(config.embedding_api_key_env),
        ),
        model_hash=str(config.victim_model_hash),
        provider_request_budget=config.provider_request_budget,
        provider_timeout_seconds=config.provider_timeout_seconds,
        provider_allowed_tools=config.provider_allowed_tools,
        embedding_request_budget=config.embedding_request_budget,
        provider_evidence_policy=config.provider_evidence_policy,
        environment=environment,
        batch_id=batch_id,
    )


def prepare_benign_collection(
    project_root: Path, config_path: Path, run_id: str | None = None
) -> Path:
    config, _ = validate_benign_collection_config(project_root, config_path)
    if config.execution_enabled:
        raise ValueError("benign_prepare_requires_disabled_config")
    preparation_id = run_id or datetime.now(UTC).strftime("benign-prepare-%Y%m%dT%H%M%S-%fZ")
    if preparation_id in {".", ".."} or not _SAFE_ID.fullmatch(preparation_id):
        raise ValueError("benign_preparation_id_invalid")
    root = project_root / config.output_root / preparation_id
    root.mkdir(parents=True, exist_ok=False, mode=0o700)
    payload: dict[str, Any] = {
        "schema_version": "1.0",
        "preparation_id": preparation_id,
        "config_hash": stable_hash(config.model_dump(mode="json")),
        "scenario_set_hash": file_hash(project_root / config.scenario_set_path),
        "prompt_hash": file_hash(project_root / config.prompt_path),
        "execution_enabled": False,
        "network_requests_performed": False,
    }
    payload["manifest_hash"] = stable_hash(payload)
    manifest = BenignPreparationManifest.model_validate(payload)
    _atomic_json(root / "benign_config.snapshot.json", config.model_dump(mode="json"))
    _atomic_json(root / "preparation_manifest.json", manifest.model_dump(mode="json"))
    return root


def collect_benign_fixture(project_root: Path, config_path: Path) -> tuple[Path, Path]:
    config, scenarios = validate_benign_collection_config(project_root, config_path)
    if config.source_mode != "synthetic_fixture":
        raise ValueError("benign_fixture_command_requires_synthetic_source")
    if config.execution_enabled:
        raise ValueError("benign_fixture_command_rejects_enabled_execution")
    adapter = BenignScenarioAdapter(project_root / config.scenario_set_path)
    collection_root = (
        project_root
        / config.output_root
        / datetime.now(UTC).strftime("benign-offline-%Y%m%dT%H%M%S-%fZ")
        / "collection"
    )
    summary = collect_interactions(
        InteractionCollectionPlan(
            collection_id=config.collection_id,
            collection_mode="benign_interaction",
            source_task_ids=config.scenario_ids,
            allowed_source_splits=["synthetic"],
            seed=config.seed,
            budget=CollectionBudget(
                max_sessions=config.max_sessions,
                max_turns=config.max_turns,
                max_actions=config.max_actions,
                max_tool_calls=config.max_tool_calls,
                max_tokens=config.max_tokens,
                max_wall_time_seconds=config.wall_clock_seconds,
                max_events=config.max_events,
                timeout_seconds=config.timeout_seconds,
            ),
        ),
        adapter,
        collection_root,
    ).collection_root
    return _finalize_benign_collection(
        project_root, config, scenarios, summary, real_model_requests=False
    )


def collect_benign_live(
    project_root: Path,
    config_path: Path,
    *,
    authorized: bool,
    run_id: str,
    environment: Mapping[str, str] | None = None,
    driver: ConstructionVictimDriver | None = None,
) -> tuple[Path, Path]:
    config, scenarios = validate_benign_collection_config(project_root, config_path)
    if config.source_mode != "safeclaw_derived":
        raise ValueError("benign_live_command_requires_safeclaw_source")
    if not config.execution_enabled:
        raise ValueError("benign_live_execution_disabled")
    if not authorized:
        raise ValueError("benign_live_authorization_required")
    if run_id in {".", ".."} or not _SAFE_ID.fullmatch(run_id):
        raise ValueError("benign_live_run_id_invalid")
    if config.safeclaw_task_set_path is None:
        raise ValueError("benign_live_task_set_missing")
    run_root = project_root / config.output_root / run_id
    run_root.mkdir(parents=True, exist_ok=True, mode=0o700)
    prepared_path = run_root / "benign_config.snapshot.json"
    preparation_manifest = run_root / "preparation_manifest.json"
    if not prepared_path.is_file() or not preparation_manifest.is_file():
        raise ValueError("benign_live_prepare_snapshot_missing")
    prepared = json.loads(prepared_path.read_text(encoding="utf-8"))
    current = config.model_dump(mode="json")
    current["execution_enabled"] = False
    if prepared != current:
        raise ValueError("benign_live_config_changed_beyond_enablement")
    runtime_environment = environment if environment is not None else os.environ
    if driver is None:
        from stac_attack_lab.execution.readiness import diagnose_workflow

        preflight = diagnose_workflow(
            project_root,
            config_path,
            workflow_kind="benign_collection",
            run_root=run_root,
            environment=runtime_environment,
        )
        _atomic_json(run_root / "benign_live_preflight.json", preflight.model_dump(mode="json"))
        if not (
            preflight.config_valid
            and preflight.implementation_ready
            and preflight.environment_ready is True
        ):
            raise RuntimeError("benign_live_preflight_failed")
    runtime_driver = driver or _build_live_driver(
        project_root, config, runtime_environment, batch_id=run_root.name
    )
    adapter = SafeClawBenignInteractionAdapter(
        project_root=project_root,
        scenario_set_path=project_root / config.scenario_set_path,
        task_set_path=project_root / config.safeclaw_task_set_path,
        driver=runtime_driver,
    )
    marker = run_root / "launch.marker"
    descriptor = os.open(marker, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        os.write(descriptor, b"benign live launch reserved\n")
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    summary = collect_interactions(
        InteractionCollectionPlan(
            collection_id=config.collection_id,
            collection_mode="benign_interaction",
            source_task_ids=config.scenario_ids,
            allowed_source_splits=["synthetic", "dev"],
            seed=config.seed,
            budget=CollectionBudget(
                max_sessions=config.max_sessions,
                max_turns=config.max_turns,
                max_actions=config.max_actions,
                max_tool_calls=config.max_tool_calls,
                max_tokens=config.max_tokens,
                max_wall_time_seconds=config.wall_clock_seconds,
                max_events=config.max_events,
                timeout_seconds=config.timeout_seconds,
            ),
        ),
        adapter,
        run_root / "collection",
    ).collection_root
    return _finalize_benign_collection(
        project_root,
        config,
        scenarios,
        summary,
        real_model_requests=None if driver is None else False,
    )


def _finalize_benign_collection(
    project_root: Path,
    config: BenignCollectionConfig,
    scenarios: BenignScenarioSet,
    summary: Path,
    *,
    real_model_requests: bool | None,
) -> tuple[Path, Path]:
    collection_manifest = summary / "collection_manifest.json"
    completion_by_trajectory: dict[str, GateStatus] = {}
    for path in sorted(summary.glob("trajectories/*/raw_trajectory.json")):
        trajectory = json.loads(path.read_text(encoding="utf-8"))
        status = trajectory.get("provenance", {}).get("normal_task_completion")
        if status is None and config.source_mode == "synthetic_fixture":
            status = "passed"
        completion_by_trajectory[str(trajectory.get("trajectory_id"))] = (
            GateStatus(status)
            if status in {item.value for item in GateStatus}
            else GateStatus.unknown
        )
    if real_model_requests is None:
        observed_counts: list[int] = []
        missing_count = False
        for path in sorted(summary.glob("trajectories/*/raw_trajectory.json")):
            trajectory = json.loads(path.read_text(encoding="utf-8"))
            raw_count = trajectory.get("provenance", {}).get("victim_provider_http_request_count")
            if isinstance(raw_count, str) and raw_count.isdigit():
                observed_counts.append(int(raw_count))
            else:
                missing_count = True
        request_status: Literal["not_performed", "observed", "unknown"] = (
            "observed"
            if any(count > 0 for count in observed_counts)
            else ("unknown" if missing_count else "not_performed")
        )
        real_model_requests = request_status == "observed"
    else:
        request_status = "observed" if real_model_requests else "not_performed"
    selected = {
        item.scenario_id: item
        for item in scenarios.scenarios
        if item.scenario_id in config.scenario_ids
    }
    manifest_payload: dict[str, Any] = {
        "schema_version": "1.0",
        "study_id": config.study_id,
        "collection_id": config.collection_id,
        "source_mode": "benign_interaction",
        "fixture_or_runtime_mode": config.source_mode,
        "config_hash": stable_hash(config.model_dump(mode="json")),
        "scenario_set_hash": file_hash(project_root / config.scenario_set_path),
        "scenario_ids": sorted(config.scenario_ids),
        "scenario_mapping_hashes": {
            scenario_id: stable_hash(item.source_task_mapping.model_dump(mode="json"))
            for scenario_id, item in sorted(selected.items())
        },
        "interaction_policy_id": config.interaction_policy_id,
        "prompt_hash": file_hash(project_root / config.prompt_path),
        "profile_hash": file_hash(project_root / config.profile_path),
        "registry_hash": file_hash(project_root / config.registry_path),
        "collection_manifest_hash": file_hash(collection_manifest),
        "trajectory_hashes": {
            path.parent.name: file_hash(path)
            for path in sorted(summary.glob("trajectories/*/raw_trajectory.json"))
        },
        "processing_source_hashes": {
            "src/stac_attack_lab/execution/benign_collection.py": file_hash(Path(__file__)),
            "src/stac_attack_lab/interactions/benign.py": file_hash(
                Path(BenignScenarioAdapter.__init__.__code__.co_filename)
            ),
            "src/stac_attack_lab/interactions/collector.py": file_hash(
                Path(collect_interactions.__code__.co_filename)
            ),
        },
        "security_evaluator_used": False,
        "attack_objective_exposed_to_policy": False,
        "real_model_requests": real_model_requests,
        "real_model_request_status": request_status,
    }
    manifest_payload["manifest_hash"] = stable_hash(manifest_payload)
    source_manifest = BenignSourceModeManifest.model_validate(manifest_payload)
    _atomic_json(
        summary / "benign_source_mode_manifest.json",
        source_manifest.model_dump(mode="json"),
    )
    analysis_root = reanalyze_flow_v3(
        project_root,
        input_path=summary,
        output_root=summary.parent / "analysis",
        profile_path=project_root / config.profile_path,
        registry_path=project_root / config.registry_path,
        terminal_outputs=True,
        budget=SliceBudget(),
    )
    assessment_path = analysis_root / "benign_trace_assessments.json"
    _atomic_json(
        assessment_path,
        [
            item.model_dump(mode="json")
            for item in _assess_benign_analysis(analysis_root, completion_by_trajectory)
        ],
    )
    manifest_path = analysis_root / "analysis_manifest.json"
    manifest = AnalysisManifest.model_validate_json(manifest_path.read_text(encoding="utf-8"))
    updated = manifest.model_dump(mode="json", exclude={"manifest_hash"})
    updated["output_refs"] = [
        *updated["output_refs"],
        AnalysisOutputRef(
            relative_path=assessment_path.name,
            content_hash=file_hash(assessment_path),
            kind="benign_trace_assessments",
        ).model_dump(mode="json"),
    ]
    updated["manifest_hash"] = stable_hash(updated)
    resealed = AnalysisManifest.model_validate(updated)
    _atomic_json(manifest_path, resealed.model_dump(mode="json"))
    return summary, analysis_root
