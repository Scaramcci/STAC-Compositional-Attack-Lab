from __future__ import annotations

import json
import os
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any, Literal

from pydantic import Field, PositiveInt, model_validator

from stac_attack_lab.config import RoleModelConfig, load_simple_yaml
from stac_attack_lab.contracts import StrictModel
from stac_attack_lab.datasets.library import (
    audit_primitive_library,
    build_primitive_chain_library,
    freeze_primitive_library,
)
from stac_attack_lab.datasets.primitive_chain import SampleLibraryManifest
from stac_attack_lab.environments.safeclaw.model_config import SafeClawEmbeddingRuntime
from stac_attack_lab.extraction.chains import construct_chain_candidates
from stac_attack_lab.extraction.filtering import (
    ChainFilteringPolicy,
    filter_chain_candidates,
)
from stac_attack_lab.extraction.occurrences import extract_primitive_occurrences
from stac_attack_lab.hashing import file_hash, stable_hash
from stac_attack_lab.interactions.base import CollectionBudget, InteractionSourceAdapter
from stac_attack_lab.interactions.collector import (
    CollectionSummary,
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
    embedding_provider: Literal["openai"] | None = None
    embedding_model_env: str | None = None
    embedding_base_url_env: str | None = None
    embedding_api_key_env: str | None = None
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
    seed: int | None = None
    seeds: list[int] = Field(default_factory=list)
    available_capabilities: list[str]
    max_sessions: PositiveInt = 4
    max_turns: PositiveInt = 8
    max_actions: PositiveInt = 12
    max_tool_calls: PositiveInt = 16
    max_tokens: PositiveInt = 8192
    max_wall_time_seconds: PositiveInt = 1200
    max_collection_trajectories: PositiveInt = 120
    target_accepted_samples: PositiveInt = 1
    max_events: PositiveInt = 200
    timeout_seconds: PositiveInt = 1200
    minimum_free_disk_gb: PositiveInt = 20
    output_root: str = "data/primitive_libraries/generated"

    @model_validator(mode="after")
    def validate_adapter_configuration(self) -> SampleGenerationConfig:
        CollectionBudget(
            max_sessions=self.max_sessions,
            max_turns=self.max_turns,
            max_actions=self.max_actions,
            max_tool_calls=self.max_tool_calls,
            max_tokens=self.max_tokens,
            max_wall_time_seconds=self.max_wall_time_seconds,
            max_events=self.max_events,
            timeout_seconds=self.timeout_seconds,
        )
        if self.seed is not None and self.seeds:
            raise ValueError("sample_seed_and_seeds_are_mutually_exclusive")
        if self.seed is None and not self.seeds:
            raise ValueError("sample_generation_requires_seed_or_seeds")
        if len(self.seeds) != len(set(self.seeds)):
            raise ValueError("duplicate_sample_generation_seed")
        matrix_size = len(self.source_task_ids) * len(self.effective_seeds)
        if matrix_size > self.max_collection_trajectories:
            raise ValueError("sample_collection_matrix_exceeds_trajectory_cap")
        if self.target_accepted_samples > self.max_collection_trajectories:
            raise ValueError("sample_target_exceeds_trajectory_cap")
        if len(self.source_task_ids) != len(set(self.source_task_ids)):
            raise ValueError("duplicate_sample_source_task_id")
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

    @property
    def effective_seeds(self) -> list[int]:
        if self.seeds:
            return list(self.seeds)
        if self.seed is None:
            raise ValueError("sample_generation_requires_seed_or_seeds")
        return [self.seed]


class SampleCollectionStageManifest(StrictModel):
    schema_version: Literal["1.0"] = "1.0"
    stage: Literal["collection"] = "collection"
    pipeline_id: str
    config: SampleGenerationConfig
    config_hash: str
    registry_hash: str
    collection_manifest_hash: str
    collection_content_hashes: dict[str, str]
    collection_tree_hash: str


class SampleMiningStageManifest(StrictModel):
    schema_version: Literal["1.0"] = "1.0"
    stage: Literal["mining"] = "mining"
    pipeline_id: str
    config_hash: str
    registry_hash: str
    collection_tree_hash: str
    library_tree_hash: str
    candidate_count: int
    accepted_count: int
    target_accepted_samples: PositiveInt
    negative_count: int
    attempt_outcome_counts: dict[str, int]
    output_content_hashes: dict[str, str]
    output_tree_hash: str


class SampleLibraryAuditReport(StrictModel):
    schema_version: Literal["1.0"] = "1.0"
    stage: Literal["audit"] = "audit"
    library_tree_hash: str | None
    mining_manifest_hash: str | None
    passed: bool
    error_codes: list[str] = Field(default_factory=list)


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


COLLECTION_STAGE_MANIFEST = "collection_stage_manifest.json"
MINING_STAGE_MANIFEST = "mining_stage_manifest.json"
LIBRARY_AUDIT_REPORT = "library_audit.json"


def _tree_content_hashes(root: Path, *, excluded_names: set[str] | None = None) -> dict[str, str]:
    excluded = excluded_names or set()
    return {
        path.relative_to(root).as_posix(): file_hash(path)
        for path in sorted(root.rglob("*"))
        if path.is_file() and path.name not in excluded
    }


def _write_immutable_json(path: Path, value: dict[str, Any], reason_code: str) -> None:
    if path.exists():
        try:
            existing = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise ValueError(reason_code) from exc
        if existing != value:
            raise ValueError(reason_code)
        return
    _atomic_json(path, value)


def _validate_collection_stage(
    collection_root: Path,
    *,
    expected_config: SampleGenerationConfig | None = None,
) -> SampleCollectionStageManifest:
    stage_path = collection_root / COLLECTION_STAGE_MANIFEST
    if not stage_path.is_file():
        raise ValueError("sample_collection_stage_manifest_missing")
    try:
        stage = SampleCollectionStageManifest.model_validate_json(
            stage_path.read_text(encoding="utf-8")
        )
    except Exception as exc:
        raise ValueError("sample_collection_stage_manifest_invalid") from exc
    if stable_hash(stage.config.model_dump(mode="json")) != stage.config_hash:
        raise ValueError("sample_collection_stage_config_hash_mismatch")
    if expected_config is not None and stage.config_hash != stable_hash(
        expected_config.model_dump(mode="json")
    ):
        raise ValueError("sample_collection_resume_config_mismatch")
    content_hashes = _tree_content_hashes(
        collection_root, excluded_names={COLLECTION_STAGE_MANIFEST}
    )
    if content_hashes != stage.collection_content_hashes:
        raise ValueError("sample_collection_content_hash_mismatch")
    if stable_hash(content_hashes) != stage.collection_tree_hash:
        raise ValueError("sample_collection_tree_hash_mismatch")
    collection_manifest_path = collection_root / "collection_manifest.json"
    if (
        not collection_manifest_path.is_file()
        or file_hash(collection_manifest_path) != stage.collection_manifest_hash
    ):
        raise ValueError("sample_collection_manifest_hash_mismatch")
    try:
        collection_manifest = json.loads(collection_manifest_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ValueError("sample_collection_manifest_invalid") from exc
    if collection_manifest.get("collection_id") != stage.pipeline_id:
        raise ValueError("sample_collection_identity_mismatch")
    trajectory_hashes = collection_manifest.get("trajectory_hashes")
    if not isinstance(trajectory_hashes, dict):
        raise ValueError("sample_collection_trajectory_hashes_invalid")
    raw_paths = sorted(collection_root.glob("trajectories/*/raw_trajectory.json"))
    raw_by_id = {path.parent.name: path for path in raw_paths}
    if set(raw_by_id) != set(trajectory_hashes):
        raise ValueError("sample_collection_trajectory_set_mismatch")
    for trajectory_id, path in raw_by_id.items():
        if file_hash(path) != trajectory_hashes[trajectory_id]:
            raise ValueError("sample_collection_trajectory_hash_mismatch")
        trajectory = RawInteractionTrajectory.model_validate_json(path.read_text(encoding="utf-8"))
        if trajectory.trajectory_id != trajectory_id:
            raise ValueError("sample_collection_trajectory_identity_mismatch")
        for reference in [*trajectory.event_refs, *trajectory.checkpoint_refs]:
            if reference.relative_path is None:
                raise ValueError("sample_collection_reference_path_missing")
            referenced = (collection_root / reference.relative_path).resolve()
            root = collection_root.resolve()
            if referenced != root and root not in referenced.parents:
                raise ValueError("sample_collection_reference_path_escape")
            if not referenced.is_file() or file_hash(referenced) != reference.content_hash:
                raise ValueError("sample_collection_reference_hash_mismatch")
    if collection_manifest.get("trajectory_count") != len(raw_paths):
        raise ValueError("sample_collection_trajectory_count_mismatch")
    return stage


def _record_collection_stage(
    collection_root: Path,
    config: SampleGenerationConfig,
    registry_hash: str,
) -> SampleCollectionStageManifest:
    collection_manifest_path = collection_root / "collection_manifest.json"
    content_hashes = _tree_content_hashes(
        collection_root, excluded_names={COLLECTION_STAGE_MANIFEST}
    )
    stage = SampleCollectionStageManifest(
        pipeline_id=config.pipeline_id,
        config=config,
        config_hash=stable_hash(config.model_dump(mode="json")),
        registry_hash=registry_hash,
        collection_manifest_hash=file_hash(collection_manifest_path),
        collection_content_hashes=content_hashes,
        collection_tree_hash=stable_hash(content_hashes),
    )
    _write_immutable_json(
        collection_root / COLLECTION_STAGE_MANIFEST,
        stage.model_dump(mode="json"),
        "sample_collection_stage_immutable",
    )
    return _validate_collection_stage(collection_root, expected_config=config)


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
        config.embedding_model_env,
        config.embedding_base_url_env,
        config.embedding_api_key_env,
    )
    if any(item is None for item in (*required_paths, *required_env, config.victim_model_hash)):
        raise ValueError("safeclaw_collection_configuration_incomplete")
    env = environment if environment is not None else os.environ
    (
        victim_model_env,
        victim_base_url_env,
        victim_api_key_env,
        embedding_model_env,
        embedding_base_url_env,
        embedding_api_key_env,
    ) = required_env
    if any(item is None for item in required_env) or config.embedding_provider is None:
        raise ValueError("safeclaw_collection_victim_environment_incomplete")
    victim_model = env.get(str(victim_model_env))
    victim_base_url = env.get(str(victim_base_url_env))
    embedding_model = env.get(str(embedding_model_env))
    embedding_base_url = env.get(str(embedding_base_url_env))
    if (
        not victim_model
        or not victim_base_url
        or not env.get(str(victim_api_key_env))
        or not embedding_model
        or not embedding_base_url
        or not env.get(str(embedding_api_key_env))
    ):
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
        target_api_key_env=str(victim_api_key_env),
        embedding=SafeClawEmbeddingRuntime(
            provider=config.embedding_provider,
            model_id=embedding_model,
            base_url=embedding_base_url,
            api_key_env=str(embedding_api_key_env),
        ),
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
    build_root = project_root / config.output_root / config.library_version
    expected_collection_root = build_root / "interactions/raw" / config.pipeline_id
    if (expected_collection_root / COLLECTION_STAGE_MANIFEST).is_file():
        _validate_collection_stage(expected_collection_root, expected_config=config)
        return expected_collection_root
    registry = load_formal_registry(project_root / config.registry_path)
    adapter, attacker = _collection_components(project_root, config, environment)
    plan = InteractionCollectionPlan(
        collection_id=config.pipeline_id,
        source_task_ids=config.source_task_ids,
        allowed_source_splits=config.allowed_source_splits,
        formal_excluded_task_ids=config.formal_excluded_task_ids,
        seed=config.seed,
        seeds=config.seeds,
        budget=CollectionBudget(
            max_sessions=config.max_sessions,
            max_turns=config.max_turns,
            max_actions=config.max_actions,
            max_tool_calls=config.max_tool_calls,
            max_tokens=config.max_tokens,
            max_wall_time_seconds=config.max_wall_time_seconds,
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
    _record_collection_stage(summary.collection_root, config, registry.registry_hash)
    return summary.collection_root


def _mining_output_content_hashes(build_root: Path) -> dict[str, str]:
    paths: list[Path] = []
    for relative_root in ("interactions/normalized", "extraction", "library"):
        root = build_root / relative_root
        if root.exists():
            paths.extend(path for path in root.rglob("*") if path.is_file())
    generation_manifest = build_root / "sample_generation_manifest.json"
    if generation_manifest.is_file():
        paths.append(generation_manifest)
    return {path.relative_to(build_root).as_posix(): file_hash(path) for path in sorted(set(paths))}


def _validate_mining_stage(
    build_root: Path,
    *,
    expected_collection_tree_hash: str | None = None,
) -> SampleMiningStageManifest:
    path = build_root / MINING_STAGE_MANIFEST
    if not path.is_file():
        raise ValueError("sample_mining_stage_manifest_missing")
    try:
        stage = SampleMiningStageManifest.model_validate_json(path.read_text(encoding="utf-8"))
    except Exception as exc:
        raise ValueError("sample_mining_stage_manifest_invalid") from exc
    if (
        expected_collection_tree_hash is not None
        and stage.collection_tree_hash != expected_collection_tree_hash
    ):
        raise ValueError("sample_mining_collection_hash_mismatch")
    output_hashes = _mining_output_content_hashes(build_root)
    if output_hashes != stage.output_content_hashes:
        raise ValueError("sample_mining_output_hash_mismatch")
    if stable_hash(output_hashes) != stage.output_tree_hash:
        raise ValueError("sample_mining_output_tree_hash_mismatch")
    library_root = build_root / "library"
    errors = audit_primitive_library(library_root)
    if errors:
        raise ValueError("sample_mining_library_audit_failed:" + ",".join(errors))
    library_manifest = SampleLibraryManifest.model_validate_json(
        (library_root / "library_manifest.json").read_text(encoding="utf-8")
    )
    if library_manifest.tree_hash != stage.library_tree_hash:
        raise ValueError("sample_mining_library_tree_hash_mismatch")
    return stage


def mine_sample_collection(project_root: Path, collection_root: Path) -> Path:
    collection_root = collection_root.resolve()
    collection_stage = _validate_collection_stage(collection_root)
    config = collection_stage.config
    build_root = collection_root.parents[2]
    mining_stage_path = build_root / MINING_STAGE_MANIFEST
    if mining_stage_path.is_file():
        _validate_mining_stage(
            build_root,
            expected_collection_tree_hash=collection_stage.collection_tree_hash,
        )
        return build_root / "library"
    normalized_root = build_root / "interactions/normalized"
    extraction_root = build_root / "extraction"
    library_root = build_root / "library"
    registry = load_formal_registry(project_root / config.registry_path)
    if registry.registry_hash != collection_stage.registry_hash:
        raise ValueError("sample_mining_registry_hash_mismatch")
    trajectory_paths = tuple(sorted(collection_root.glob("trajectories/*/raw_trajectory.json")))
    collection = CollectionSummary(
        collection_root=collection_root,
        trajectory_paths=trajectory_paths,
        skipped_trajectory_ids=(),
        failure_count=0,
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
    library_manifest = SampleLibraryManifest.model_validate_json(
        (library_root / "library_manifest.json").read_text(encoding="utf-8")
    )
    output_hashes = _mining_output_content_hashes(build_root)
    mining_stage = SampleMiningStageManifest(
        pipeline_id=config.pipeline_id,
        config_hash=collection_stage.config_hash,
        registry_hash=registry.registry_hash,
        collection_tree_hash=collection_stage.collection_tree_hash,
        library_tree_hash=library_manifest.tree_hash,
        candidate_count=len(candidates),
        accepted_count=len(filtering.accepted),
        target_accepted_samples=config.target_accepted_samples,
        negative_count=len(filtering.negative),
        attempt_outcome_counts=attempt_outcome_counts,
        output_content_hashes=output_hashes,
        output_tree_hash=stable_hash(output_hashes),
    )
    _write_immutable_json(
        mining_stage_path,
        mining_stage.model_dump(mode="json"),
        "sample_mining_stage_immutable",
    )
    _validate_mining_stage(
        build_root,
        expected_collection_tree_hash=collection_stage.collection_tree_hash,
    )
    return library_root


def build_sample_library(project_root: Path, config: SampleGenerationConfig) -> Path:
    if config.source_adapter != "jsonl_authorized_fixture":
        raise ValueError("sample_build_fixture_only_use_collect_then_mine")
    collection_root = collect_sample_interactions(project_root, config)
    return mine_sample_collection(project_root, collection_root)


def _current_library_audit_report(library_root: Path) -> SampleLibraryAuditReport:
    library_root = library_root.resolve()
    build_root = library_root.parent
    errors = list(audit_primitive_library(library_root))
    mining_manifest_path = build_root / MINING_STAGE_MANIFEST
    mining_manifest_hash = (
        file_hash(mining_manifest_path) if mining_manifest_path.is_file() else None
    )
    try:
        mining_stage = _validate_mining_stage(build_root)
    except ValueError as exc:
        errors.append(str(exc))
    else:
        if mining_stage.accepted_count < mining_stage.target_accepted_samples:
            errors.append(
                "accepted_sample_target_not_met:"
                f"{mining_stage.accepted_count}:{mining_stage.target_accepted_samples}"
            )
    library_tree_hash: str | None = None
    try:
        library_manifest = SampleLibraryManifest.model_validate_json(
            (library_root / "library_manifest.json").read_text(encoding="utf-8")
        )
        library_tree_hash = library_manifest.tree_hash
    except Exception:
        errors.append("sample_library_manifest_unreadable")
    error_codes = list(dict.fromkeys(errors))
    return SampleLibraryAuditReport(
        library_tree_hash=library_tree_hash,
        mining_manifest_hash=mining_manifest_hash,
        passed=not error_codes,
        error_codes=error_codes,
    )


def audit_sample_library_stage(library_root: Path) -> SampleLibraryAuditReport:
    report = _current_library_audit_report(library_root)
    _atomic_json(
        library_root.resolve().parent / LIBRARY_AUDIT_REPORT,
        report.model_dump(mode="json"),
    )
    return report


def freeze_audited_sample_library(
    generated_library: Path,
    version: str,
    project_root: Path,
) -> Path:
    generated_library = generated_library.resolve()
    report_path = generated_library.parent / LIBRARY_AUDIT_REPORT
    if not report_path.is_file():
        raise ValueError("sample_library_audit_report_missing")
    try:
        recorded = SampleLibraryAuditReport.model_validate_json(
            report_path.read_text(encoding="utf-8")
        )
    except Exception as exc:
        raise ValueError("sample_library_audit_report_invalid") from exc
    current = _current_library_audit_report(generated_library)
    if recorded != current:
        raise ValueError("sample_library_audit_report_stale")
    if not current.passed:
        raise ValueError("sample_library_audit_failed:" + ",".join(current.error_codes))
    return freeze_primitive_library(generated_library, version, project_root)
