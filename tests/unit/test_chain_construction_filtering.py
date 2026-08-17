from __future__ import annotations

from pathlib import Path

from stac_attack_lab.datasets.primitive_chain import FilterGate
from stac_attack_lab.extraction.chains import construct_chain_candidates
from stac_attack_lab.extraction.filtering import (
    ChainFilteringPolicy,
    filter_chain_candidates,
)
from stac_attack_lab.extraction.occurrences import extract_primitive_occurrences
from stac_attack_lab.interactions.collector import (
    InteractionCollectionPlan,
    collect_interactions,
)
from stac_attack_lab.interactions.fixture_adapter import JsonlFixtureInteractionAdapter
from stac_attack_lab.interactions.models import InteractionGraph
from stac_attack_lab.interactions.normalizer import normalize_trajectory
from stac_attack_lab.primitives.formal_registry import load_formal_registry

ROOT = Path(__file__).resolve().parents[2]
FIXTURE = ROOT / "tests/fixtures/interactions/authorized_synthetic.jsonl"
CAPABILITIES = [
    "read_untrusted_source",
    "persistent_state_write",
    "lifecycle_boundary",
    "persistent_state_read",
    "effectful_sandbox_action",
]


def _inputs(tmp_path: Path) -> tuple[InteractionGraph, object, object]:
    adapter = JsonlFixtureInteractionAdapter(FIXTURE)
    plan = InteractionCollectionPlan(
        collection_id="chain-test",
        source_task_ids=["construction-synthetic-001"],
        seed=23,
    )
    summary = collect_interactions(plan, adapter, tmp_path / "raw")
    graph_path, _ = normalize_trajectory(
        summary.trajectory_paths[0],
        collection_root=summary.collection_root,
        output_root=tmp_path / "normalized",
    )
    graph = InteractionGraph.model_validate_json(graph_path.read_text(encoding="utf-8"))
    registry = load_formal_registry(ROOT / "configs/primitives/formal_v1.yaml")
    extraction = extract_primitive_occurrences(graph, registry)
    return graph, registry, extraction


def test_canonical_chain_passes_all_g0_g8_filters(tmp_path: Path) -> None:
    graph, registry, extraction = _inputs(tmp_path)
    candidates = construct_chain_candidates(
        graph,
        extraction.occurrences,
        registry,
        source_split="synthetic",
        source_task_id="construction-synthetic-001",
    )
    result = filter_chain_candidates(
        candidates,
        {graph.graph_id: graph},
        {graph.graph_id: extraction.occurrences},
        registry,
        ChainFilteringPolicy(available_capabilities=CAPABILITIES),
    )

    assert len(candidates) == 1
    assert len(candidates[0].nodes) == 4
    assert len(result.accepted) == 1
    assert result.negative == []
    assert [decision.gate for decision in result.records[0].decisions] == list(FilterGate)
    assert all(decision.passed for decision in result.records[0].decisions)


def test_temporal_order_without_typed_edge_is_rejected(tmp_path: Path) -> None:
    graph, registry, extraction = _inputs(tmp_path)
    graph = graph.model_copy(
        update={
            "edges": [
                edge
                for edge in graph.edges
                if not (edge.source_event_id == "e1" and edge.target_event_id == "e2")
            ]
        }
    )
    candidates = construct_chain_candidates(
        graph,
        extraction.occurrences,
        registry,
        source_split="synthetic",
        source_task_id="construction-synthetic-001",
    )
    result = filter_chain_candidates(
        candidates,
        {graph.graph_id: graph},
        {graph.graph_id: extraction.occurrences},
        registry,
        ChainFilteringPolicy(available_capabilities=CAPABILITIES),
    )
    causal = next(
        decision
        for decision in result.records[0].decisions
        if decision.gate == FilterGate.causal_edge
    )

    assert causal.passed is False
    assert any("missing_typed_causal_edge" in reason for reason in causal.reason_codes)
    assert len(result.negative) == 1


def test_duplicate_candidate_enters_negative_pool(tmp_path: Path) -> None:
    graph, registry, extraction = _inputs(tmp_path)
    candidate = construct_chain_candidates(
        graph,
        extraction.occurrences,
        registry,
        source_split="synthetic",
        source_task_id="construction-synthetic-001",
    )[0]
    result = filter_chain_candidates(
        [candidate, candidate],
        {graph.graph_id: graph},
        {graph.graph_id: extraction.occurrences},
        registry,
        ChainFilteringPolicy(available_capabilities=CAPABILITIES),
    )

    assert len(result.accepted) == 1
    assert len(result.negative) == 1
    portability = next(
        decision
        for decision in result.records[1].decisions
        if decision.gate == FilterGate.portability_dedup
    )
    assert portability.reason_codes == ["duplicate_candidate_hash"]
