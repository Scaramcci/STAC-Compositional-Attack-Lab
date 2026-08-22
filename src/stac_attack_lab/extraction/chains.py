from __future__ import annotations

from collections import defaultdict, deque

from stac_attack_lab.datasets.primitive_chain import (
    CandidateAcquisitionMode,
    ChainEdge,
    ChainNode,
    PrimitiveChainCandidate,
)
from stac_attack_lab.hashing import stable_hash
from stac_attack_lab.interactions.models import (
    ConstructionManifest,
    DependencyType,
    InteractionEdge,
    InteractionGraph,
    PrimitiveOccurrence,
)
from stac_attack_lab.primitives.core import EvidenceGrade, PrimitiveOutcome
from stac_attack_lab.primitives.formal_registry import FormalPrimitiveRegistry

CANONICAL_MACRO_ORDER = (
    "macro.ingest@2",
    "macro.persist@2",
    "macro.recall@2",
    "macro.bind@2",
    "macro.act@2",
)

CANONICAL_REQUIRED_CORE_EDGES = (
    ("core.transfer.external_ingress@1", "core.transform.extract@1", DependencyType.data),
    ("core.transform.extract@1", "core.mutate.memory_write@1", DependencyType.data),
    ("core.mutate.memory_write@1", "core.transfer.retrieve@1", DependencyType.state),
    ("core.control.restart@1", "core.transfer.retrieve@1", DependencyType.control),
    ("core.transfer.retrieve@1", "core.transform.parameterize@1", DependencyType.data),
    ("core.transform.parameterize@1", "core.transfer.request@1", DependencyType.data),
    ("core.transfer.request@1", "core.mutate.external_effect@1", DependencyType.state),
)


def _first_by_primitive(
    graph: InteractionGraph, occurrences: list[PrimitiveOccurrence]
) -> dict[str, PrimitiveOccurrence]:
    logical_time = {event.event_id: event.logical_time for event in graph.events}
    grouped: dict[str, list[PrimitiveOccurrence]] = defaultdict(list)
    for occurrence in occurrences:
        grouped[occurrence.primitive_ref].append(occurrence)
    return {
        primitive_ref: min(
            items,
            key=lambda item: min(logical_time[event_id] for event_id in item.source_event_ids),
        )
        for primitive_ref, items in grouped.items()
    }


def _has_path(graph: InteractionGraph, source_event_id: str, target_event_id: str) -> bool:
    adjacency: dict[str, list[str]] = defaultdict(list)
    for edge in graph.edges:
        if edge.observable:
            adjacency[edge.source_event_id].append(edge.target_event_id)
    frontier = deque([source_event_id])
    visited = {source_event_id}
    while frontier:
        current = frontier.popleft()
        if current == target_event_id:
            return True
        for target in adjacency[current]:
            if target not in visited:
                visited.add(target)
                frontier.append(target)
    return False


def _matching_graph_edge(
    graph: InteractionGraph,
    source: PrimitiveOccurrence | None,
    target: PrimitiveOccurrence | None,
    edge_type: DependencyType,
) -> InteractionEdge | None:
    if source is None or target is None:
        return None
    source_events = set(source.source_event_ids)
    target_events = set(target.source_event_ids)
    return next(
        (
            edge
            for edge in graph.edges
            if edge.edge_type == edge_type
            and edge.source_event_id in source_events
            and edge.target_event_id in target_events
            and edge.observable
        ),
        None,
    )


def match_semantic_macros(
    graph: InteractionGraph,
    occurrences: list[PrimitiveOccurrence],
    registry: FormalPrimitiveRegistry,
) -> dict[str, list[str]]:
    selected = _first_by_primitive(graph, occurrences)
    artifacts = {item.artifact_id: item for item in graph.artifacts}
    matches: dict[str, list[str]] = {}
    for macro in registry.attack_macros:
        matched_occurrence_ids: list[str] = []
        macro_matches = True
        for pattern_node in macro.core_nodes:
            occurrence = selected.get(pattern_node.primitive_ref)
            if occurrence is None:
                if pattern_node.required:
                    macro_matches = False
                continue
            output_types = {
                artifacts[artifact_id].artifact_type
                for artifact_id in occurrence.output_artifact_ids
                if artifact_id in artifacts
            }
            if pattern_node.required_output_types and not (
                output_types & set(pattern_node.required_output_types)
            ):
                if pattern_node.required:
                    macro_matches = False
                continue
            semantic_values = {
                *occurrence.semantic_labels,
                *occurrence.semantic_labels.values(),
            }
            if (
                pattern_node.required_semantic_labels
                and not set(pattern_node.required_semantic_labels) <= semantic_values
            ):
                if pattern_node.required:
                    macro_matches = False
                continue
            matched_occurrence_ids.append(occurrence.occurrence_id)
        if macro_matches:
            matches[macro.macro_id] = matched_occurrence_ids
    return matches


def construct_chain_candidates(
    graph: InteractionGraph,
    occurrences: list[PrimitiveOccurrence],
    registry: FormalPrimitiveRegistry,
    *,
    acquisition_mode: CandidateAcquisitionMode | None = None,
    construction_manifest: ConstructionManifest | None = None,
    source_split: str,
    source_task_id: str,
) -> list[PrimitiveChainCandidate]:
    selected = _first_by_primitive(graph, occurrences)
    ingress = selected.get("core.transfer.external_ingress@1")
    if ingress is None:
        return []
    resolved_acquisition_mode = acquisition_mode or (
        CandidateAcquisitionMode(construction_manifest.acquisition_mode)
        if construction_manifest is not None
        else CandidateAcquisitionMode.ordinary_trace
    )
    all_macro_matches = match_semantic_macros(graph, occurrences, registry)
    macro_occurrences = {
        macro_ref: all_macro_matches.get(macro_ref, []) for macro_ref in CANONICAL_MACRO_ORDER
    }
    nodes = [
        ChainNode(
            node_id=f"macro-node-{index}",
            macro_primitive_ref=macro_ref,
            core_occurrence_ids=macro_occurrences[macro_ref],
            public_preconditions=registry.resolve_macro(macro_ref).entry_predicates,
            public_postconditions=registry.resolve_macro(macro_ref).exit_predicates,
            required_edge_inputs=[
                f"{source_ref}->{target_ref}:{edge_type.value}"
                for source_ref, target_ref, edge_type in CANONICAL_REQUIRED_CORE_EDGES
                if target_ref
                in {node.primitive_ref for node in registry.resolve_macro(macro_ref).core_nodes}
            ],
            binding_slots=registry.resolve_macro(macro_ref).binding_slots,
            allowed_outcomes=list(PrimitiveOutcome),
            evidence_requirement=[EvidenceGrade.direct, EvidenceGrade.deterministic_derived],
            required_for_full_chain=True,
        )
        for index, macro_ref in enumerate(CANONICAL_MACRO_ORDER, start=1)
    ]
    macro_pairs = (
        (
            nodes[0],
            nodes[1],
            selected.get("core.transfer.external_ingress@1"),
            selected.get("core.transform.extract@1"),
            DependencyType.data,
        ),
        (
            nodes[1],
            nodes[2],
            selected.get("core.mutate.memory_write@1"),
            selected.get("core.transfer.retrieve@1"),
            DependencyType.state,
        ),
        (
            nodes[2],
            nodes[3],
            selected.get("core.transfer.retrieve@1"),
            selected.get("core.transform.parameterize@1"),
            DependencyType.data,
        ),
        (
            nodes[3],
            nodes[4],
            selected.get("core.transform.parameterize@1"),
            selected.get("core.transfer.request@1"),
            DependencyType.data,
        ),
    )
    chain_edges: list[ChainEdge] = []
    for source_node, target_node, source_occurrence, target_occurrence, edge_type in macro_pairs:
        graph_edge = _matching_graph_edge(graph, source_occurrence, target_occurrence, edge_type)
        if graph_edge is None:
            continue
        chain_edges.append(
            ChainEdge(
                edge_id=f"chain-{graph_edge.edge_id}",
                source_node_id=source_node.node_id,
                target_node_id=target_node.node_id,
                edge_type=graph_edge.edge_type,
                source_fact=graph_edge.source_fact,
                target_precondition=graph_edge.target_precondition,
                artifact_binding=graph_edge.artifact_id,
                state_binding=graph_edge.state_ref,
                guard=graph_edge.guard,
                join_semantics=graph_edge.join_semantics,
                join_k=graph_edge.join_k,
                evidence_ref_ids=graph_edge.evidence_ref_ids,
            )
        )

    effect = selected.get("core.mutate.external_effect@1")
    forbidden_shortcut = False
    if effect and effect.outcome == PrimitiveOutcome.passed:
        full_path_exists = _has_path(graph, ingress.source_event_ids[0], effect.source_event_ids[0])
        direct_shortcut = any(
            edge.source_event_id in ingress.source_event_ids
            and edge.target_event_id in effect.source_event_ids
            and edge.observable
            for edge in graph.edges
        )
        forbidden_shortcut = direct_shortcut or not full_path_exists
    terminal_relation = "hypothesized"
    if effect is not None:
        if effect.outcome == PrimitiveOutcome.passed:
            terminal_relation = "observed"
        elif effect.outcome == PrimitiveOutcome.rejected:
            terminal_relation = "blocked"
        elif effect.outcome in {PrimitiveOutcome.error, PrimitiveOutcome.timeout}:
            terminal_relation = "failed"
    payload = {
        "schema_version": "2.0",
        "candidate_id": f"candidate-{graph.graph_id}",
        "chain_id": f"chain-{graph.graph_id}",
        "registry_hash": registry.registry_hash,
        "interaction_graph_id": graph.graph_id,
        "occurrence_ids": [item.occurrence_id for item in occurrences],
        "nodes": [item.model_dump(mode="json") for item in nodes],
        "edges": [item.model_dump(mode="json") for item in chain_edges],
        "entry_predicates": ["untrusted_artifact_available"],
        "terminal_predicates": ["sandbox_terminal_effect_observed"],
        "acquisition_mode": resolved_acquisition_mode,
        "construction_manifest": (
            construction_manifest.model_dump(mode="json")
            if construction_manifest is not None
            else None
        ),
        "source_trace_refs": [graph.trajectory_id],
        "source_task_id": source_task_id,
        "source_split": source_split,
        "terminal_relation": terminal_relation,
        "forbidden_shortcut_detected": forbidden_shortcut,
        "filter_decisions": [],
    }
    return [
        PrimitiveChainCandidate.model_validate({**payload, "candidate_hash": stable_hash(payload)})
    ]
