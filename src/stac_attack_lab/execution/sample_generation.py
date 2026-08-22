from __future__ import annotations

import json
import os
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any, Literal

from pydantic import Field, PositiveInt, model_validator

from stac_attack_lab.config import RoleModelConfig, load_simple_yaml
from stac_attack_lab.contracts import StrictModel
from stac_attack_lab.datasets.library import build_primitive_chain_library
from stac_attack_lab.extraction.chains import construct_chain_candidates
from stac_attack_lab.extraction.filtering import (
    ChainFilteringPolicy,
    filter_chain_candidates,
)
from stac_attack_lab.extraction.occurrences import extract_primitive_occurrences
from stac_attack_lab.hashing import stable_hash
from stac_attack_lab.interactions.base import CollectionBudget, InteractionSourceAdapter
from stac_attack_lab.interactions.collector import (
    InteractionCollectionPlan,
    collect_interactions,
)
from stac_attack_lab.interactions.construction import (
    ConstructionAttacker,
    DeterministicConstructionAttacker,
    ModelConstructionAttacker,
)
from stac_attack_lab.interactions.fixture_adapter import JsonlFixtureInteractionAdapter
from stac_attack_lab.interactions.models import (
    InteractionGraph,
    PrimitiveOccurrence,
    RawInteractionTrajectory,
)
from stac_attack_lab.interactions.normalizer import normalize_trajectory
from stac_attack_lab.interactions.safeclaw_collection import (
    SafeClawConstructionInteractionAdapter,
    SafeClawSubprocessVictimDriver,
)
from stac_attack_lab.models.factory import build_model_client
from stac_attack_lab.primitives.formal_registry import load_formal_registry


class SampleGenerationConfig(StrictModel):
    schema_version: Literal["2.1"] = "2.1"
    pipeline_id: str
    library_id: str
    library_version: str
    registry_path: str
    source_adapter: Literal["jsonl_authorized_fixture", "safeclaw_adaptive_construction"]
    source_fixture_path: str | None = None
    construction_task_set_path: str | None = None
    upstream_dir: str | None = None
    safety_patch_path: str | None = None
    construction_bridge_path: str | None = None
    construction_attacker_model_config_path: str | None = None
    construction_attacker_prompt_path: str | None = None
    victim_model_env: str | None = None
    allowed_victim_models: list[str] = Field(default_factory=list)
    victim_base_url_env: str | None = None
    victim_api_key_env: str | None = None
    victim_model_hash: str | None = None
    execution_enabled: bool = False
    image_tag: str = "openclaw-env:2026.3.12"
    source_task_ids: list[str]
    acquisition_mode: Literal["adversarial_trace"] = "adversarial_trace"
    construction_objective_id: str
    public_attack_goal: str
    allowed_delivery_surfaces: list[str]
    required_trust_boundary_crossings: list[str]
    public_terminal_predicate_ids: list[str]
    safety_constraint_ids: list[str]
    construction_attacker_model_hash: str
    construction_prompt_hash: str
    attacker_stage_implemented: bool = False
    allowed_source_splits: list[str] = Field(default_factory=lambda: ["train", "dev", "synthetic"])
    formal_excluded_task_ids: list[str]
    seed: int
    available_capabilities: list[str]
    max_sessions: PositiveInt = 4
    max_events: PositiveInt = 200
    timeout_seconds: PositiveInt = 1200
    minimum_free_disk_gb: PositiveInt = 20
    output_root: str = "data/primitive_libraries/generated"

    @model_validator(mode="after")
    def validate_adapter_configuration(self) -> SampleGenerationConfig:
        if self.source_adapter == "jsonl_authorized_fixture":
            if self.source_fixture_path is None:
                raise ValueError("fixture_adapter_requires_source_fixture_path")
            return self
        required = {
            "construction_task_set_path": self.construction_task_set_path,
            "upstream_dir": self.upstream_dir,
            "safety_patch_path": self.safety_patch_path,
            "construction_bridge_path": self.construction_bridge_path,
            "construction_attacker_model_config_path": (
                self.construction_attacker_model_config_path
            ),
            "construction_attacker_prompt_path": self.construction_attacker_prompt_path,
            "victim_model_env": self.victim_model_env,
            "victim_base_url_env": self.victim_base_url_env,
            "victim_api_key_env": self.victim_api_key_env,
            "victim_model_hash": self.victim_model_hash,
        }
        missing = [key for key, value in required.items() if value is None]
        if missing:
            raise ValueError("safeclaw_collection_configuration_missing:" + ",".join(missing))
        if not self.attacker_stage_implemented:
            raise ValueError("safeclaw_collection_requires_construction_attacker")
        return self


def load_sample_generation_config(path: Path) -> SampleGenerationConfig:
    value = json.loads(path.read_text(encoding="utf-8"))
    return SampleGenerationConfig.model_validate(value)


def _atomic_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(json.dumps(value, indent=2, sort_keys=True), encoding="utf-8")
    temporary.replace(path)


def _atomic_jsonl(path: Path, values: Sequence[StrictModel]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(
        "".join(item.model_dump_json() + "\n" for item in values), encoding="utf-8"
    )
    temporary.replace(path)


def _collection_components(
    project_root: Path,
    config: SampleGenerationConfig,
    environment: Mapping[str, str] | None = None,
) -> tuple[InteractionSourceAdapter, ConstructionAttacker]:
    if config.source_adapter == "jsonl_authorized_fixture":
        if config.source_fixture_path is None:
            raise ValueError("fixture_adapter_requires_source_fixture_path")
        adapter: InteractionSourceAdapter = JsonlFixtureInteractionAdapter(
            project_root / config.source_fixture_path
        )
        attacker: ConstructionAttacker = DeterministicConstructionAttacker(
            objective_id=config.construction_objective_id,
            public_attack_goal=config.public_attack_goal,
            allowed_delivery_surfaces=config.allowed_delivery_surfaces,
            required_trust_boundary_crossings=config.required_trust_boundary_crossings,
            public_terminal_predicate_ids=config.public_terminal_predicate_ids,
            safety_constraint_ids=config.safety_constraint_ids,
            model_hash=config.construction_attacker_model_hash,
            prompt_hash=config.construction_prompt_hash,
        )
        return adapter, attacker
    if not config.execution_enabled:
        raise ValueError("sample_collection_execution_disabled_by_config")
    required_paths = (
        config.construction_task_set_path,
        config.upstream_dir,
        config.safety_patch_path,
        config.construction_bridge_path,
        config.construction_attacker_model_config_path,
        config.construction_attacker_prompt_path,
    )
    required_env = (
        config.victim_model_env,
        config.victim_base_url_env,
        config.victim_api_key_env,
    )
    if any(item is None for item in (*required_paths, *required_env, config.victim_model_hash)):
        raise ValueError("safeclaw_collection_configuration_incomplete")
    env = environment if environment is not None else os.environ
    victim_model_env, victim_base_url_env, victim_api_key_env = required_env
    if victim_model_env is None or victim_base_url_env is None or victim_api_key_env is None:
        raise ValueError("safeclaw_collection_victim_environment_incomplete")
    victim_model = env.get(victim_model_env)
    victim_base_url = env.get(victim_base_url_env)
    if not victim_model or not victim_base_url or not env.get(victim_api_key_env):
        raise ValueError("safeclaw_collection_victim_environment_missing")
    if config.allowed_victim_models and victim_model not in config.allowed_victim_models:
        raise ValueError("safeclaw_collection_victim_model_not_allowed")
    model_config_path = config.construction_attacker_model_config_path
    prompt_path = config.construction_attacker_prompt_path
    if model_config_path is None or prompt_path is None:
        raise ValueError("safeclaw_collection_attacker_configuration_incomplete")
    attacker_model_config = RoleModelConfig.model_validate(
        load_simple_yaml(project_root / model_config_path)
    )
    live_attacker = ModelConstructionAttacker(
        client=build_model_client(attacker_model_config),
        prompt_path=project_root / prompt_path,
        objective_id=config.construction_objective_id,
        public_attack_goal=config.public_attack_goal,
        allowed_delivery_surfaces=config.allowed_delivery_surfaces,
        required_trust_boundary_crossings=config.required_trust_boundary_crossings,
        public_terminal_predicate_ids=config.public_terminal_predicate_ids,
        safety_constraint_ids=config.safety_constraint_ids,
        model_hash=stable_hash(attacker_model_config.model_dump(mode="json")),
    )
    task_set_path, upstream_dir, safety_patch_path, bridge_path = required_paths[:4]
    if None in (task_set_path, upstream_dir, safety_patch_path, bridge_path):
        raise ValueError("safeclaw_collection_path_configuration_incomplete")
    driver = SafeClawSubprocessVictimDriver(
        project_root=project_root,
        upstream_root=project_root / str(upstream_dir),
        safety_patch=project_root / str(safety_patch_path),
        bridge_path=project_root / str(bridge_path),
        target_model_id=victim_model,
        target_base_url=victim_base_url,
        target_api_key_env=victim_api_key_env,
        model_hash=str(config.victim_model_hash),
        environment=env,
    )
    live_adapter = SafeClawConstructionInteractionAdapter(
        project_root=project_root,
        task_set_path=project_root / str(task_set_path),
        driver=driver,
    )
    return live_adapter, live_attacker


def collect_sample_interactions(
    project_root: Path,
    config: SampleGenerationConfig,
    *,
    environment: Mapping[str, str] | None = None,
) -> Path:
    adapter, attacker = _collection_components(project_root, config, environment)
    build_root = project_root / config.output_root / config.library_version
    plan = InteractionCollectionPlan(
        collection_id=config.pipeline_id,
        source_task_ids=config.source_task_ids,
        allowed_source_splits=config.allowed_source_splits,
        formal_excluded_task_ids=config.formal_excluded_task_ids,
        seed=config.seed,
        budget=CollectionBudget(
            max_sessions=config.max_sessions,
            max_events=config.max_events,
            timeout_seconds=config.timeout_seconds,
        ),
    )
    summary = collect_interactions(
        plan,
        adapter,
        build_root / "interactions/raw",
        construction_attacker=attacker,
    )
    return summary.collection_root


def build_sample_library(project_root: Path, config: SampleGenerationConfig) -> Path:
    build_root = project_root / config.output_root / config.library_version
    raw_root = build_root / "interactions/raw"
    normalized_root = build_root / "interactions/normalized"
    extraction_root = build_root / "extraction"
    library_root = build_root / "library"
    registry = load_formal_registry(project_root / config.registry_path)
    adapter, construction_attacker = _collection_components(project_root, config)
    collection_plan = InteractionCollectionPlan(
        collection_id=config.pipeline_id,
        source_task_ids=config.source_task_ids,
        allowed_source_splits=config.allowed_source_splits,
        formal_excluded_task_ids=config.formal_excluded_task_ids,
        seed=config.seed,
        budget=CollectionBudget(
            max_sessions=config.max_sessions,
            max_events=config.max_events,
            timeout_seconds=config.timeout_seconds,
        ),
    )
    collection = collect_interactions(
        collection_plan,
        adapter,
        raw_root,
        construction_attacker=construction_attacker,
    )
    graphs: list[InteractionGraph] = []
    occurrences_by_graph: dict[str, list[PrimitiveOccurrence]] = {}
    candidates = []
    attempt_outcome_counts: dict[str, int] = {}
    for trajectory_path in collection.trajectory_paths:
        graph_path, _ = normalize_trajectory(
            trajectory_path,
            collection_root=collection.collection_root,
            output_root=normalized_root,
        )
        graph = InteractionGraph.model_validate_json(graph_path.read_text(encoding="utf-8"))
        graphs.append(graph)
        extraction = extract_primitive_occurrences(graph, registry)
        occurrences_by_graph[graph.graph_id] = extraction.occurrences
        _atomic_jsonl(
            extraction_root / f"{graph.graph_id}-occurrences.jsonl",
            extraction.occurrences,
        )
        _atomic_json(
            extraction_root / f"{graph.graph_id}-decisions.json",
            extraction.model_dump(mode="json"),
        )
        raw_trajectory = RawInteractionTrajectory.model_validate_json(
            trajectory_path.read_text(encoding="utf-8")
        )
        if raw_trajectory.construction_manifest is None:
            raise ValueError("adversarial_collection_missing_construction_manifest")
        outcome = raw_trajectory.construction_manifest.attempt_outcome
        attempt_outcome_counts[outcome] = attempt_outcome_counts.get(outcome, 0) + 1
        candidates.extend(
            construct_chain_candidates(
                graph,
                extraction.occurrences,
                registry,
                construction_manifest=raw_trajectory.construction_manifest,
                source_split=raw_trajectory.source_split,
                source_task_id=raw_trajectory.source_task_id,
            )
        )
    graph_by_id = {graph.graph_id: graph for graph in graphs}
    filtering = filter_chain_candidates(
        candidates,
        graph_by_id,
        occurrences_by_graph,
        registry,
        ChainFilteringPolicy(
            allowed_source_splits=config.allowed_source_splits,
            formal_excluded_task_ids=config.formal_excluded_task_ids,
            available_capabilities=config.available_capabilities,
        ),
    )
    build_primitive_chain_library(
        library_root,
        accepted_candidates=filtering.accepted,
        negative_candidates=filtering.negative,
        filter_records=filtering.records,
        occurrences_by_graph_id=occurrences_by_graph,
        registry=registry,
        library_id=config.library_id,
        library_version=config.library_version,
        formal_exclusion_hash=stable_hash(sorted(config.formal_excluded_task_ids)),
        attempt_outcome_counts=attempt_outcome_counts,
        attacker_stage_implemented=config.attacker_stage_implemented,
    )
    _atomic_json(
        build_root / "sample_generation_manifest.json",
        {
            "schema_version": "2.1",
            "pipeline_id": config.pipeline_id,
            "config_hash": stable_hash(config.model_dump(mode="json")),
            "registry_hash": registry.registry_hash,
            "collection_manifest": str(collection.collection_root / "collection_manifest.json"),
            "library_root": str(library_root),
            "candidate_count": len(candidates),
            "accepted_count": len(filtering.accepted),
            "negative_count": len(filtering.negative),
            "attempt_outcome_counts": attempt_outcome_counts,
            "attacker_stage": {"implemented": config.attacker_stage_implemented},
        },
    )
    return library_root
