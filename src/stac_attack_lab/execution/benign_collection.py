from __future__ import annotations

import json
import os
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Literal

from pydantic import Field, PositiveInt, model_validator

from stac_attack_lab.contracts import StrictModel
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
from stac_attack_lab.interactions.benign import BenignScenarioAdapter, BenignScenarioSet
from stac_attack_lab.interactions.collector import InteractionCollectionPlan, collect_interactions


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
    allowed_source_splits: list[Literal["synthetic", "development", "validation"]] = ["synthetic"]

    @model_validator(mode="after")
    def validate_config(self) -> BenignCollectionConfig:
        if not self.scenario_ids or len(self.scenario_ids) != len(set(self.scenario_ids)):
            raise ValueError("benign_collection_scenario_ids_invalid")
        if set(self.request_caps_by_role) != {"target_agent", "interaction_policy"}:
            raise ValueError("benign_collection_request_roles_invalid")
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
            max_tokens=8192,
            max_wall_time_seconds=self.wall_clock_seconds,
            max_events=self.max_events,
            timeout_seconds=self.timeout_seconds,
        )
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
    real_model_requests: Literal[False] = False
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
    planning_reference_eligible: GateStatus
    verified_dependency_claim_count: int = Field(ge=0)
    unknown_dependency_claim_count: int = Field(ge=0)
    cross_session_capability: GateStatus
    reason_codes: list[str]
    security_outcome: Literal["not_evaluated"] = "not_evaluated"


def _assess_benign_analysis(analysis_root: Path) -> list[BenignTraceAssessment]:
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
        planning_status = GateStatus.unknown
        if observation_valid == GateStatus.passed and observed_effects:
            planning_status = GateStatus.passed
            reasons.append("benign_observed_effects_available_as_planning_reference")
        elif not observed_effects:
            reasons.append("benign_observed_effects_missing")
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
    scenario_path = project_root / config.scenario_set_path
    scenarios = BenignScenarioSet.model_validate_json(scenario_path.read_text(encoding="utf-8"))
    selected = [item for item in scenarios.scenarios if item.scenario_id in config.scenario_ids]
    if {item.scenario_id for item in selected} != set(config.scenario_ids):
        raise ValueError("benign_collection_scenario_missing")
    if any(item.environment_version != config.environment_version for item in selected):
        raise ValueError("benign_collection_environment_version_mismatch")
    prompt = project_root / config.prompt_path
    if not prompt.is_file():
        raise ValueError("benign_collection_policy_prompt_missing")
    for path in (project_root / config.profile_path, project_root / config.registry_path):
        if not path.is_file():
            raise ValueError("benign_collection_v3_contract_missing")
    return config, scenarios


def prepare_benign_collection(project_root: Path, config_path: Path) -> Path:
    config, _ = validate_benign_collection_config(project_root, config_path)
    if config.execution_enabled:
        raise ValueError("benign_prepare_requires_disabled_config")
    preparation_id = datetime.now(UTC).strftime("benign-prepare-%Y%m%dT%H%M%S-%fZ")
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
                max_tokens=8192,
                max_wall_time_seconds=config.wall_clock_seconds,
                max_events=config.max_events,
                timeout_seconds=config.timeout_seconds,
            ),
        ),
        adapter,
        collection_root,
    ).collection_root
    collection_manifest = summary / "collection_manifest.json"
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
        "real_model_requests": False,
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
        [item.model_dump(mode="json") for item in _assess_benign_analysis(analysis_root)],
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
