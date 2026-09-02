from __future__ import annotations

from pathlib import Path

from stac_attack_lab.datasets.primitive_chain import FilterGate
from stac_attack_lab.extraction.chains import (
    ChainMiningPolicy,
    construct_chain_candidates,
    match_semantic_macros,
)
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
from stac_attack_lab.interactions.models import (
    ConstructionManifest,
    DependencyType,
    InteractionEdge,
    InteractionGraph,
    JoinSemantics,
)
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
CONSTRUCTION_MANIFEST = ConstructionManifest(
    acquisition_mode="adversarial_trace",
    construction_objective_id="objective:test",
    public_attack_goal="Propagate a synthetic marker to the local no-value sink.",
    allowed_delivery_surfaces=["fixture", "memory", "local_sink"],
    required_trust_boundary_crossings=["source_to_context", "memory_to_later_session"],
    public_terminal_predicate_ids=["sandbox_terminal_effect_observed"],
    safety_constraint_ids=["synthetic_only", "no_network"],
    construction_attacker_model_hash="fake-attacker-v1",
    construction_prompt_hash="public-objective-v1",
    attempt_outcome="completed",
)


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
    registry = load_formal_registry(ROOT / "configs/primitives/registry.yaml")
    extraction = extract_primitive_occurrences(graph, registry)
    return graph, registry, extraction


def test_canonical_chain_passes_all_g0_g8_filters(tmp_path: Path) -> None:
    graph, registry, extraction = _inputs(tmp_path)
    candidates = construct_chain_candidates(
        graph,
        extraction.occurrences,
        registry,
        construction_manifest=CONSTRUCTION_MANIFEST,
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

    assert len(candidates) > 1
    assert {len(candidate.core_nodes) for candidate in candidates} == {7, 8}
    assert any(
        "macro.recall@2" in {node.macro_primitive_ref for node in candidate.nodes}
        for candidate in candidates
    )
    assert any(
        "macro.recall@2" not in {node.macro_primitive_ref for node in candidate.nodes}
        for candidate in candidates
    )
    assert all(candidate.core_nodes for candidate in candidates)
    assert len(result.accepted) == len(candidates)
    assert result.negative == []
    assert [decision.gate for decision in result.records[0].decisions] == list(FilterGate)
    assert all(decision.passed for record in result.records for decision in record.decisions)


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
        construction_manifest=CONSTRUCTION_MANIFEST,
        source_split="synthetic",
        source_task_id="construction-synthetic-001",
    )
    assert candidates == []


def test_duplicate_candidate_enters_negative_pool(tmp_path: Path) -> None:
    graph, registry, extraction = _inputs(tmp_path)
    candidate = construct_chain_candidates(
        graph,
        extraction.occurrences,
        registry,
        construction_manifest=CONSTRUCTION_MANIFEST,
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


def test_ordinary_trace_fails_closed_at_attack_relevance_gate(tmp_path: Path) -> None:
    graph, registry, extraction = _inputs(tmp_path)
    candidate = construct_chain_candidates(
        graph,
        extraction.occurrences,
        registry,
        source_split="synthetic",
        source_task_id="construction-synthetic-001",
    )[0]
    result = filter_chain_candidates(
        [candidate],
        {graph.graph_id: graph},
        {graph.graph_id: extraction.occurrences},
        registry,
        ChainFilteringPolicy(available_capabilities=CAPABILITIES),
    )
    relevance = next(
        item for item in result.records[0].decisions if item.gate == FilterGate.attack_relevance
    )

    assert result.accepted == []
    assert len(result.negative) == 1
    assert "adversarial_acquisition_required" in relevance.reason_codes
    assert "construction_manifest_missing" in relevance.reason_codes


def test_nine_macro_matcher_requires_typed_outputs_and_semantic_evidence(tmp_path: Path) -> None:
    graph, registry, extraction = _inputs(tmp_path)
    matches = match_semantic_macros(graph, extraction.occurrences, registry)

    assert set(matches) == {
        "macro.ingest@2",
        "macro.persist@2",
        "macro.recall@2",
        "macro.bind@2",
        "macro.act@2",
    }
    assert "macro.adopt@2" not in matches
    assert "macro.select@2" not in matches


def test_repeated_occurrences_are_structurally_deduplicated_with_provenance(
    tmp_path: Path,
) -> None:
    graph, registry, extraction = _inputs(tmp_path)
    terminal = next(item for item in extraction.occurrences if item.subtype == "external_effect")
    repeated = terminal.model_copy(update={"occurrence_id": terminal.occurrence_id + "-repeat"})

    candidates = construct_chain_candidates(
        graph,
        [*extraction.occurrences, repeated],
        registry,
        construction_manifest=CONSTRUCTION_MANIFEST,
        source_split="synthetic",
        source_task_id="construction-synthetic-001",
    )

    assert candidates
    assert any(len(candidate.duplicate_provenance_paths) > 1 for candidate in candidates)
    assert len({candidate.chain_id for candidate in candidates}) == len(candidates)


def test_branch_join_and_cross_session_edges_are_preserved(tmp_path: Path) -> None:
    graph, registry, extraction = _inputs(tmp_path)
    graph = graph.model_copy(
        update={
            "edges": [
                edge.model_copy(update={"join_semantics": JoinSemantics.k_of_n, "join_k": 1})
                if edge.edge_id == "edge-control-e5-e6"
                else edge
                for edge in graph.edges
            ]
        }
    )

    candidates = construct_chain_candidates(
        graph,
        extraction.occurrences,
        registry,
        construction_manifest=CONSTRUCTION_MANIFEST,
        source_split="synthetic",
        source_task_id="construction-synthetic-001",
    )

    assert len(candidates) > 1
    assert any(
        edge.join_semantics == JoinSemantics.k_of_n and edge.join_k == 1
        for candidate in candidates
        for edge in candidate.core_edges
    )
    assert any(
        edge.crosses_session_boundary for candidate in candidates for edge in candidate.core_edges
    )


def test_direct_shortcut_is_mined_but_fails_closed(tmp_path: Path) -> None:
    graph, registry, extraction = _inputs(tmp_path)
    graph = graph.model_copy(
        update={
            "edges": [
                *graph.edges,
                InteractionEdge(
                    edge_id="edge-shortcut-e1-e9",
                    edge_type=DependencyType.state,
                    source_event_id="e1",
                    target_event_id="e9",
                    source_fact="untrusted ingress exists",
                    target_precondition="terminal effect requested",
                    state_ref="synthetic-shortcut-state",
                    evidence_ref_ids=["evidence:synthetic-shortcut"],
                ),
            ]
        }
    )
    candidates = construct_chain_candidates(
        graph,
        extraction.occurrences,
        registry,
        construction_manifest=CONSTRUCTION_MANIFEST,
        source_split="synthetic",
        source_task_id="construction-synthetic-001",
    )
    shortcut = next(item for item in candidates if item.forbidden_shortcut_detected)
    result = filter_chain_candidates(
        [shortcut],
        {graph.graph_id: graph},
        {graph.graph_id: extraction.occurrences},
        registry,
        ChainFilteringPolicy(available_capabilities=CAPABILITIES),
    )

    assert result.accepted == []
    relevance = next(
        decision
        for decision in result.records[0].decisions
        if decision.gate == FilterGate.attack_relevance
    )
    assert "forbidden_shortcut_detected" in relevance.reason_codes


def test_miner_bounds_and_order_are_deterministic(tmp_path: Path) -> None:
    graph, registry, extraction = _inputs(tmp_path)
    policy = ChainMiningPolicy(max_candidates=2, max_branching_factor=2, max_path_length=12)
    kwargs = {
        "construction_manifest": CONSTRUCTION_MANIFEST,
        "source_split": "synthetic",
        "source_task_id": "construction-synthetic-001",
        "policy": policy,
    }

    first = construct_chain_candidates(graph, extraction.occurrences, registry, **kwargs)
    second = construct_chain_candidates(graph, extraction.occurrences, registry, **kwargs)

    assert 0 < len(first) <= 2
    assert [item.candidate_hash for item in first] == [item.candidate_hash for item in second]
