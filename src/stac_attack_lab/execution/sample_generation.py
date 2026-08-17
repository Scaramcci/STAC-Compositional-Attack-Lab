from __future__ import annotations

import json
from collections.abc import Sequence
from pathlib import Path
from typing import Any, Literal

from pydantic import Field

from stac_attack_lab.contracts import StrictModel
from stac_attack_lab.datasets.library import build_primitive_chain_library
from stac_attack_lab.extraction.chains import construct_chain_candidates
from stac_attack_lab.extraction.filtering import (
    ChainFilteringPolicy,
    filter_chain_candidates,
)
from stac_attack_lab.extraction.occurrences import extract_primitive_occurrences
from stac_attack_lab.hashing import stable_hash
from stac_attack_lab.interactions.collector import (
    InteractionCollectionPlan,
    collect_interactions,
)
from stac_attack_lab.interactions.fixture_adapter import JsonlFixtureInteractionAdapter
from stac_attack_lab.interactions.models import (
    InteractionGraph,
    PrimitiveOccurrence,
    RawInteractionTrajectory,
)
from stac_attack_lab.interactions.normalizer import normalize_trajectory
from stac_attack_lab.primitives.formal_registry import load_formal_registry


class SampleGenerationConfig(StrictModel):
    schema_version: Literal["2.0"] = "2.0"
    pipeline_id: str
    library_id: str
    library_version: str
    registry_path: str
    source_adapter: Literal["jsonl_authorized_fixture"]
    source_fixture_path: str
    source_task_ids: list[str]
    allowed_source_splits: list[str] = Field(default_factory=lambda: ["train", "dev", "synthetic"])
    formal_excluded_task_ids: list[str]
    seed: int
    available_capabilities: list[str]
    output_root: str = "data/primitive_libraries/generated"


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


def build_sample_library(project_root: Path, config: SampleGenerationConfig) -> Path:
    build_root = project_root / config.output_root / config.library_version
    raw_root = build_root / "interactions/raw"
    normalized_root = build_root / "interactions/normalized"
    extraction_root = build_root / "extraction"
    library_root = build_root / "library"
    registry = load_formal_registry(project_root / config.registry_path)
    adapter = JsonlFixtureInteractionAdapter(project_root / config.source_fixture_path)
    collection_plan = InteractionCollectionPlan(
        collection_id=config.pipeline_id,
        source_task_ids=config.source_task_ids,
        allowed_source_splits=config.allowed_source_splits,
        formal_excluded_task_ids=config.formal_excluded_task_ids,
        seed=config.seed,
    )
    collection = collect_interactions(collection_plan, adapter, raw_root)
    graphs: list[InteractionGraph] = []
    occurrences_by_graph: dict[str, list[PrimitiveOccurrence]] = {}
    candidates = []
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
        candidates.extend(
            construct_chain_candidates(
                graph,
                extraction.occurrences,
                registry,
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
    )
    _atomic_json(
        build_root / "sample_generation_manifest.json",
        {
            "schema_version": "2.0",
            "pipeline_id": config.pipeline_id,
            "config_hash": stable_hash(config.model_dump(mode="json")),
            "registry_hash": registry.registry_hash,
            "collection_manifest": str(collection.collection_root / "collection_manifest.json"),
            "library_root": str(library_root),
            "candidate_count": len(candidates),
            "accepted_count": len(filtering.accepted),
            "negative_count": len(filtering.negative),
        },
    )
    return library_root
