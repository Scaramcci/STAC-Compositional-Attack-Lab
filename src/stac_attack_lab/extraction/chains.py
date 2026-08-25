from __future__ import annotations

import time
from collections import Counter, defaultdict
from dataclasses import dataclass

from pydantic import Field, PositiveInt

from stac_attack_lab.contracts import StrictModel
from stac_attack_lab.datasets.primitive_chain import (
    CandidateAcquisitionMode,
    ChainEdge,
    ChainNode,
    PrimitiveChainCandidate,
    PublicCoreEdge,
    PublicCoreNode,
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

# Retained only as a named regression fixture/policy. The miner does not require
# this sequence when enumerating general typed causal paths.
CANONICAL_REQUIRED_CORE_EDGES = (
    ("core.transfer.external_ingress@1", "core.transform.extract@1", DependencyType.data),
    ("core.transform.extract@1", "core.mutate.memory_write@1", DependencyType.data),
    ("core.mutate.memory_write@1", "core.transfer.retrieve@1", DependencyType.state),
    ("core.control.restart@1", "core.transfer.retrieve@1", DependencyType.control),
    ("core.transfer.retrieve@1", "core.transform.parameterize@1", DependencyType.data),
    ("core.transform.parameterize@1", "core.transfer.request@1", DependencyType.data),
    ("core.transfer.request@1", "core.mutate.external_effect@1", DependencyType.state),
)


class ChainMiningPolicy(StrictModel):
    entry_primitive_refs: list[str] = Field(
        default_factory=lambda: ["core.transfer.external_ingress@1"]
    )
    terminal_primitive_refs: list[str] = Field(
        default_factory=lambda: ["core.mutate.external_effect@1"]
    )
    max_path_length: PositiveInt = 16
    max_candidates: PositiveInt = 64
    max_branching_factor: PositiveInt = 8
    max_runtime_ms: PositiveInt = 2000
    minimum_path_length: PositiveInt = 2
    retain_partial_paths: bool = True


@dataclass(frozen=True)
class _OccurrenceArc:
    source_id: str
    target_id: str
    edge: InteractionEdge


def _occurrence_order(
    graph: InteractionGraph, occurrences: list[PrimitiveOccurrence]
) -> dict[str, tuple[int, str]]:
    logical_time = {event.event_id: event.logical_time for event in graph.events}
    return {
        occurrence.occurrence_id: (
            min(logical_time.get(event_id, 2**31) for event_id in occurrence.source_event_ids),
            occurrence.occurrence_id,
        )
        for occurrence in occurrences
    }


def _matching_occurrences_for_macro(
    graph: InteractionGraph,
    occurrences: list[PrimitiveOccurrence],
    registry: FormalPrimitiveRegistry,
) -> dict[str, list[str]]:
    artifacts = {item.artifact_id: item for item in graph.artifacts}
    order = _occurrence_order(graph, occurrences)
    by_primitive: dict[str, list[PrimitiveOccurrence]] = defaultdict(list)
    for occurrence in occurrences:
        by_primitive[occurrence.primitive_ref].append(occurrence)
    for values in by_primitive.values():
        values.sort(key=lambda item: order[item.occurrence_id])
    matches: dict[str, list[str]] = {}
    for macro in registry.attack_macros:
        selected: list[str] = []
        valid = True
        for pattern_node in macro.core_nodes:
            matching: list[PrimitiveOccurrence] = []
            for occurrence in by_primitive.get(pattern_node.primitive_ref, []):
                output_types = {
                    artifacts[artifact_id].artifact_type
                    for artifact_id in occurrence.output_artifact_ids
                    if artifact_id in artifacts
                }
                semantic_values = {
                    *occurrence.semantic_labels,
                    *occurrence.semantic_labels.values(),
                }
                if pattern_node.required_output_types and not (
                    output_types & set(pattern_node.required_output_types)
                ):
                    continue
                if (
                    pattern_node.required_semantic_labels
                    and not set(pattern_node.required_semantic_labels) <= semantic_values
                ):
                    continue
                matching.append(occurrence)
            if not matching and pattern_node.required:
                valid = False
                break
            selected.extend(item.occurrence_id for item in matching)
        if valid:
            matches[macro.macro_id] = sorted(set(selected), key=lambda item: order[item])
    return matches


def match_semantic_macros(
    graph: InteractionGraph,
    occurrences: list[PrimitiveOccurrence],
    registry: FormalPrimitiveRegistry,
) -> dict[str, list[str]]:
    return _matching_occurrences_for_macro(graph, occurrences, registry)


def _complete_macro_matches_for_path(
    path: list[str],
    arcs: list[_OccurrenceArc],
    macro_matches: dict[str, list[str]],
    by_id: dict[str, PrimitiveOccurrence],
    registry: FormalPrimitiveRegistry,
) -> dict[str, list[str]]:
    path_positions = {occurrence_id: index for index, occurrence_id in enumerate(path)}
    complete: dict[str, list[str]] = {}
    for macro_ref, matched_ids in macro_matches.items():
        selected = [item for item in matched_ids if item in path_positions]
        spec = registry.resolve_macro(macro_ref)
        required_refs = Counter(node.primitive_ref for node in spec.core_nodes if node.required)
        selected_refs = Counter(by_id[item].primitive_ref for item in selected)
        if any(selected_refs[ref] < count for ref, count in required_refs.items()):
            continue
        pattern_ref = {node.pattern_node_id: node.primitive_ref for node in spec.core_nodes}
        required_edges_complete = all(
            any(
                by_id[arc.source_id].primitive_ref == pattern_ref[edge.source_pattern_node_id]
                and by_id[arc.target_id].primitive_ref == pattern_ref[edge.target_pattern_node_id]
                and arc.edge.edge_type.value == edge.edge_type
                for arc in arcs
            )
            for edge in spec.core_edges
            if edge.required
        )
        if required_edges_complete:
            complete[macro_ref] = sorted(selected, key=lambda item: path_positions[item])
    return complete


def _occurrence_arcs(
    graph: InteractionGraph, occurrences: list[PrimitiveOccurrence]
) -> tuple[dict[str, list[_OccurrenceArc]], dict[tuple[str, str], list[_OccurrenceArc]]]:
    by_event: dict[str, list[str]] = defaultdict(list)
    for occurrence in occurrences:
        for event_id in occurrence.source_event_ids:
            by_event[event_id].append(occurrence.occurrence_id)
    adjacency: dict[str, list[_OccurrenceArc]] = defaultdict(list)
    pairs: dict[tuple[str, str], list[_OccurrenceArc]] = defaultdict(list)
    for edge in sorted(graph.edges, key=lambda item: item.edge_id):
        if not edge.observable:
            continue
        for source_id in sorted(by_event.get(edge.source_event_id, [])):
            for target_id in sorted(by_event.get(edge.target_event_id, [])):
                if source_id == target_id:
                    continue
                arc = _OccurrenceArc(source_id=source_id, target_id=target_id, edge=edge)
                adjacency[source_id].append(arc)
                pairs[(source_id, target_id)].append(arc)
    return adjacency, pairs


def _enumerate_paths(
    graph: InteractionGraph,
    occurrences: list[PrimitiveOccurrence],
    policy: ChainMiningPolicy,
) -> list[tuple[list[str], list[_OccurrenceArc], bool]]:
    by_id = {item.occurrence_id: item for item in occurrences}
    order = _occurrence_order(graph, occurrences)
    adjacency, _ = _occurrence_arcs(graph, occurrences)
    entries = sorted(
        (item for item in occurrences if item.primitive_ref in set(policy.entry_primitive_refs)),
        key=lambda item: order[item.occurrence_id],
    )
    terminal_refs = set(policy.terminal_primitive_refs)
    started = time.monotonic()
    paths: list[tuple[list[str], list[_OccurrenceArc], bool]] = []
    for entry in entries:
        stack: list[tuple[list[str], list[_OccurrenceArc]]] = [([entry.occurrence_id], [])]
        while stack and len(paths) < policy.max_candidates * 4:
            if (time.monotonic() - started) * 1000 > policy.max_runtime_ms:
                return paths
            path, arcs = stack.pop()
            current = path[-1]
            current_occurrence = by_id[current]
            terminal = current_occurrence.primitive_ref in terminal_refs
            if terminal and len(path) >= policy.minimum_path_length:
                paths.append((path, arcs, True))
                continue
            if len(path) >= policy.max_path_length:
                if policy.retain_partial_paths and len(path) >= policy.minimum_path_length:
                    paths.append((path, arcs, False))
                continue
            outgoing = [arc for arc in adjacency.get(current, []) if arc.target_id not in path]
            outgoing.sort(
                key=lambda arc: (
                    order[arc.target_id],
                    arc.edge.edge_type.value,
                    arc.edge.edge_id,
                ),
                reverse=True,
            )
            outgoing = outgoing[: policy.max_branching_factor]
            if not outgoing:
                if policy.retain_partial_paths and len(path) >= policy.minimum_path_length:
                    paths.append((path, arcs, False))
                continue
            for arc in outgoing:
                stack.append(([*path, arc.target_id], [*arcs, arc]))
    paths.sort(
        key=lambda item: (
            [order[occurrence_id] for occurrence_id in item[0]],
            [arc.edge.edge_id for arc in item[1]],
        )
    )
    return paths


def _terminal_relation(terminal: PrimitiveOccurrence, reached_declared_terminal: bool) -> str:
    if not reached_declared_terminal:
        return "partial"
    return {
        PrimitiveOutcome.passed: "observed",
        PrimitiveOutcome.rejected: "blocked",
        PrimitiveOutcome.error: "error",
        PrimitiveOutcome.timeout: "timeout",
        PrimitiveOutcome.not_observable: "not_observable",
        PrimitiveOutcome.not_reached: "partial",
        PrimitiveOutcome.attempted: "partial",
        PrimitiveOutcome.abstained: "rejected",
        PrimitiveOutcome.stopped: "rejected",
    }[terminal.outcome]


def _public_type_label(value: str) -> str:
    """Keep causal type information without exposing reserved data-field terms."""
    replacements = {
        "payload": "content",
        "prompt": "instruction",
        "secret": "protected_value",
    }
    return "_".join(replacements.get(part, part) for part in value.split("_"))


def _public_core_views(
    graph: InteractionGraph,
    path: list[str],
    arcs: list[_OccurrenceArc],
    by_id: dict[str, PrimitiveOccurrence],
    macro_matches: dict[str, list[str]],
) -> tuple[list[PublicCoreNode], list[PublicCoreEdge]]:
    events = {event.event_id: event for event in graph.events}
    artifacts = {artifact.artifact_id: artifact for artifact in graph.artifacts}
    annotations_by_occurrence: dict[str, list[str]] = defaultdict(list)
    for macro_ref, occurrence_ids in macro_matches.items():
        for occurrence_id in occurrence_ids:
            annotations_by_occurrence[occurrence_id].append(macro_ref)
    nodes: list[PublicCoreNode] = []
    previous_session: str | None = None
    for position, occurrence_id in enumerate(path):
        occurrence = by_id[occurrence_id]
        source_events = [events[item] for item in occurrence.source_event_ids if item in events]
        source_events.sort(key=lambda item: (item.logical_time, item.event_id))
        session_id = source_events[0].session_id if source_events else "unknown-session"
        nodes.append(
            PublicCoreNode(
                node_id=f"core-node-{position + 1}-{stable_hash(occurrence_id)[:8]}",
                position=position,
                family=occurrence.family,
                subtype=occurrence.subtype,
                public_input_state_types=sorted(
                    {
                        _public_type_label(artifacts[item].artifact_type)
                        for item in occurrence.input_artifact_ids
                        if item in artifacts
                    }
                    | ({"state_ref"} if occurrence.pre_state_refs else set())
                ),
                public_output_state_types=sorted(
                    {
                        _public_type_label(artifacts[item].artifact_type)
                        for item in occurrence.output_artifact_ids
                        if item in artifacts
                    }
                    | ({"state_ref"} if occurrence.post_state_refs else set())
                ),
                session_id=session_id,
                session_boundary_before=(
                    previous_session is not None and session_id != previous_session
                ),
                macro_annotations=sorted(annotations_by_occurrence.get(occurrence_id, [])),
            )
        )
        previous_session = session_id
    node_by_occurrence = dict(zip(path, nodes, strict=True))
    public_edges: list[PublicCoreEdge] = []
    for arc in arcs:
        source = node_by_occurrence[arc.source_id]
        target = node_by_occurrence[arc.target_id]
        artifact_type = (
            _public_type_label(artifacts[arc.edge.artifact_id].artifact_type)
            if arc.edge.artifact_id in artifacts
            else None
        )
        public_edges.append(
            PublicCoreEdge(
                edge_id=f"core-{arc.edge.edge_id}",
                source_node_id=source.node_id,
                target_node_id=target.node_id,
                edge_type=arc.edge.edge_type,
                public_artifact_type=artifact_type,
                public_state_type="state_ref" if arc.edge.state_ref else None,
                crosses_session_boundary=source.session_id != target.session_id,
                join_semantics=arc.edge.join_semantics,
                join_k=arc.edge.join_k,
            )
        )
    return nodes, public_edges


def _macro_views(
    path: list[str],
    arcs: list[_OccurrenceArc],
    macro_matches: dict[str, list[str]],
    registry: FormalPrimitiveRegistry,
) -> tuple[list[ChainNode], list[ChainEdge]]:
    path_position = {occurrence_id: index for index, occurrence_id in enumerate(path)}
    macro_items: list[tuple[int, str, list[str]]] = []
    preferred_order = {macro_ref: index for index, macro_ref in enumerate(CANONICAL_MACRO_ORDER)}
    for macro_ref, matched_ids in macro_matches.items():
        selected = [item for item in matched_ids if item in path_position]
        if selected:
            macro_items.append(
                (
                    min(path_position[item] for item in selected),
                    macro_ref,
                    sorted(selected, key=lambda item: path_position[item]),
                )
            )
    macro_items.sort(key=lambda item: (item[0], preferred_order.get(item[1], 1000), item[1]))
    nodes: list[ChainNode] = []
    for index, (_, macro_ref, occurrence_ids) in enumerate(macro_items, start=1):
        spec = registry.resolve_macro(macro_ref)
        nodes.append(
            ChainNode(
                node_id=f"macro-node-{index}",
                macro_primitive_ref=macro_ref,
                core_occurrence_ids=occurrence_ids,
                public_preconditions=spec.entry_predicates,
                public_postconditions=spec.exit_predicates,
                required_edge_inputs=[
                    f"{arc.source_id}->{arc.target_id}:{arc.edge.edge_type.value}"
                    for arc in arcs
                    if arc.target_id in occurrence_ids
                ],
                binding_slots=spec.binding_slots,
                allowed_outcomes=list(PrimitiveOutcome),
                evidence_requirement=[
                    EvidenceGrade.direct,
                    EvidenceGrade.deterministic_derived,
                ],
            )
        )
    chain_edges: list[ChainEdge] = []
    for source, target in zip(nodes, nodes[1:], strict=False):
        matching = next(
            (
                arc
                for arc in arcs
                if arc.source_id in set(source.core_occurrence_ids)
                and arc.target_id in set(target.core_occurrence_ids)
            ),
            None,
        )
        if matching is None:
            continue
        edge = matching.edge
        chain_edges.append(
            ChainEdge(
                edge_id=f"chain-{edge.edge_id}",
                source_node_id=source.node_id,
                target_node_id=target.node_id,
                edge_type=edge.edge_type,
                source_fact=edge.source_fact,
                target_precondition=edge.target_precondition,
                artifact_binding=edge.artifact_id,
                state_binding=edge.state_ref,
                guard=edge.guard,
                join_semantics=edge.join_semantics,
                join_k=edge.join_k,
                evidence_ref_ids=edge.evidence_ref_ids,
            )
        )
    return nodes, chain_edges


def _structural_signature(
    core_nodes: list[PublicCoreNode], core_edges: list[PublicCoreEdge]
) -> str:
    payload = {
        "nodes": [
            {
                "family": node.family.value,
                "subtype": node.subtype,
                "input": node.public_input_state_types,
                "output": node.public_output_state_types,
                "session_boundary_before": node.session_boundary_before,
                "optional": node.optional,
            }
            for node in core_nodes
        ],
        "edges": [
            {
                "source_position": next(
                    node.position for node in core_nodes if node.node_id == edge.source_node_id
                ),
                "target_position": next(
                    node.position for node in core_nodes if node.node_id == edge.target_node_id
                ),
                "type": edge.edge_type.value,
                "join": edge.join_semantics.value,
                "join_k": edge.join_k,
                "cross_session": edge.crosses_session_boundary,
            }
            for edge in core_edges
        ],
    }
    return stable_hash(payload)


def construct_chain_candidates(
    graph: InteractionGraph,
    occurrences: list[PrimitiveOccurrence],
    registry: FormalPrimitiveRegistry,
    *,
    acquisition_mode: CandidateAcquisitionMode | None = None,
    construction_manifest: ConstructionManifest | None = None,
    source_split: str,
    source_task_id: str,
    policy: ChainMiningPolicy | None = None,
) -> list[PrimitiveChainCandidate]:
    mining_policy = policy or ChainMiningPolicy()
    resolved_acquisition_mode = acquisition_mode or (
        CandidateAcquisitionMode(construction_manifest.acquisition_mode)
        if construction_manifest is not None
        else CandidateAcquisitionMode.ordinary_trace
    )
    by_id = {item.occurrence_id: item for item in occurrences}
    macro_matches = match_semantic_macros(graph, occurrences, registry)
    raw_paths = _enumerate_paths(graph, occurrences, mining_policy)
    candidates_by_signature: dict[str, PrimitiveChainCandidate] = {}
    for path, arcs, terminal_reached in raw_paths:
        if len(candidates_by_signature) >= mining_policy.max_candidates:
            break
        path_macro_matches = _complete_macro_matches_for_path(
            path, arcs, macro_matches, by_id, registry
        )
        core_nodes, core_edges = _public_core_views(graph, path, arcs, by_id, path_macro_matches)
        signature = _structural_signature(core_nodes, core_edges)
        existing = candidates_by_signature.get(signature)
        if existing is not None:
            merged_payload = existing.model_dump(mode="json", exclude={"candidate_hash"})
            merged_payload["duplicate_provenance_paths"] = [
                *existing.duplicate_provenance_paths,
                path,
            ]
            candidates_by_signature[signature] = PrimitiveChainCandidate.model_validate(
                {**merged_payload, "candidate_hash": stable_hash(merged_payload)}
            )
            continue
        macro_nodes, macro_edges = _macro_views(path, arcs, path_macro_matches, registry)
        entry = by_id[path[0]]
        terminal = by_id[path[-1]]
        direct_shortcut = len(path) <= 2 and terminal_reached
        terminal_relation = _terminal_relation(terminal, terminal_reached)
        payload = {
            "schema_version": "2.0",
            "candidate_id": f"candidate-{graph.graph_id}-{stable_hash(path)[:12]}",
            "chain_id": f"chain-{signature[:20]}",
            "registry_hash": registry.registry_hash,
            "interaction_graph_id": graph.graph_id,
            "occurrence_ids": path,
            "core_nodes": [item.model_dump(mode="json") for item in core_nodes],
            "core_edges": [item.model_dump(mode="json") for item in core_edges],
            "duplicate_provenance_paths": [path],
            "nodes": [item.model_dump(mode="json") for item in macro_nodes],
            "edges": [item.model_dump(mode="json") for item in macro_edges],
            "entry_predicates": [f"entry:{entry.subtype}"],
            "terminal_predicates": [f"terminal:{terminal.subtype}"] if terminal_reached else [],
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
            "forbidden_shortcut_detected": direct_shortcut,
            "filter_decisions": [],
        }
        candidates_by_signature[signature] = PrimitiveChainCandidate.model_validate(
            {**payload, "candidate_hash": stable_hash(payload)}
        )
    return sorted(
        candidates_by_signature.values(),
        key=lambda item: (item.chain_id, item.candidate_id),
    )
