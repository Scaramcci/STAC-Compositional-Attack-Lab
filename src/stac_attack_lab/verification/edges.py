from __future__ import annotations

from collections import defaultdict, deque

from stac_attack_lab.interactions.models import (
    DependencyType,
    InteractionArtifact,
    InteractionGraph,
    PrimitiveOccurrence,
)
from stac_attack_lab.primitives.core import PrimitiveOutcome
from stac_attack_lab.verification.formal_models import (
    CausalVerdict,
    EdgeVerdict,
    OccurrenceVerdict,
)


def _artifact_ancestry(
    graph: InteractionGraph,
    source_artifact_ids: set[str],
    target_artifact_ids: set[str],
) -> list[str]:
    artifacts: dict[str, InteractionArtifact] = {
        artifact.artifact_id: artifact for artifact in graph.artifacts
    }
    frontier = deque(target_artifact_ids)
    visited: set[str] = set()
    while frontier:
        artifact_id = frontier.popleft()
        if artifact_id in source_artifact_ids:
            return [artifact_id]
        if artifact_id in visited:
            continue
        visited.add(artifact_id)
        artifact = artifacts.get(artifact_id)
        if artifact is not None:
            frontier.extend(artifact.parent_artifact_ids)
    return []


def has_observable_typed_path(
    graph: InteractionGraph, source_event_ids: set[str], target_event_ids: set[str]
) -> bool:
    adjacency: dict[str, list[str]] = defaultdict(list)
    for edge in graph.edges:
        if edge.observable:
            adjacency[edge.source_event_id].append(edge.target_event_id)
    frontier = deque(source_event_ids)
    visited = set(source_event_ids)
    while frontier:
        event_id = frontier.popleft()
        if event_id in target_event_ids:
            return True
        for target_id in adjacency[event_id]:
            if target_id not in visited:
                visited.add(target_id)
                frontier.append(target_id)
    return False


def verify_causal_edge(
    *,
    edge_id: str,
    edge_type: DependencyType,
    source_claim: PrimitiveOccurrence | None,
    target_claim: PrimitiveOccurrence | None,
    source_verdict: OccurrenceVerdict,
    target_verdict: OccurrenceVerdict,
    graph: InteractionGraph,
) -> EdgeVerdict:
    if source_claim is None or source_verdict.outcome != PrimitiveOutcome.passed:
        return EdgeVerdict(
            edge_id=edge_id,
            verdict=CausalVerdict.not_reached,
            source_occurrence_id=source_verdict.occurrence_id,
            target_occurrence_id=target_verdict.occurrence_id,
            evidence_ref_ids=[],
            reason_codes=["source_occurrence_not_passed"],
        )
    if target_claim is None:
        return EdgeVerdict(
            edge_id=edge_id,
            verdict=CausalVerdict.not_reached,
            source_occurrence_id=source_verdict.occurrence_id,
            target_occurrence_id=target_verdict.occurrence_id,
            evidence_ref_ids=[],
            reason_codes=["target_occurrence_not_reached"],
        )
    if target_verdict.outcome == PrimitiveOutcome.not_observable:
        return EdgeVerdict(
            edge_id=edge_id,
            verdict=CausalVerdict.not_observable,
            source_occurrence_id=source_verdict.occurrence_id,
            target_occurrence_id=target_verdict.occurrence_id,
            evidence_ref_ids=[],
            reason_codes=["target_occurrence_not_observable"],
        )
    if target_verdict.outcome != PrimitiveOutcome.passed:
        return EdgeVerdict(
            edge_id=edge_id,
            verdict=CausalVerdict.fail,
            source_occurrence_id=source_verdict.occurrence_id,
            target_occurrence_id=target_verdict.occurrence_id,
            evidence_ref_ids=[],
            reason_codes=["target_occurrence_not_passed"],
        )

    source_events = set(source_claim.source_event_ids)
    target_events = set(target_claim.source_event_ids)
    matching = [
        edge
        for edge in graph.edges
        if edge.edge_type == edge_type
        and edge.source_event_id in source_events
        and edge.target_event_id in target_events
    ]
    observable = [edge for edge in matching if edge.observable]
    if observable:
        return EdgeVerdict(
            edge_id=edge_id,
            verdict=CausalVerdict.causal_pass,
            source_occurrence_id=source_verdict.occurrence_id,
            target_occurrence_id=target_verdict.occurrence_id,
            evidence_ref_ids=sorted({ref for edge in observable for ref in edge.evidence_ref_ids}),
            reason_codes=["observable_typed_dependency_verified"],
        )
    if matching:
        return EdgeVerdict(
            edge_id=edge_id,
            verdict=CausalVerdict.not_observable,
            source_occurrence_id=source_verdict.occurrence_id,
            target_occurrence_id=target_verdict.occurrence_id,
            evidence_ref_ids=[],
            reason_codes=["typed_dependency_marked_unobservable"],
        )

    if edge_type == DependencyType.data:
        ancestry = _artifact_ancestry(
            graph,
            set(source_claim.output_artifact_ids),
            set(target_claim.input_artifact_ids),
        )
        if ancestry:
            return EdgeVerdict(
                edge_id=edge_id,
                verdict=CausalVerdict.causal_pass,
                source_occurrence_id=source_verdict.occurrence_id,
                target_occurrence_id=target_verdict.occurrence_id,
                evidence_ref_ids=ancestry,
                reason_codes=["deterministic_artifact_ancestry_verified"],
            )
    return EdgeVerdict(
        edge_id=edge_id,
        verdict=CausalVerdict.fail,
        source_occurrence_id=source_verdict.occurrence_id,
        target_occurrence_id=target_verdict.occurrence_id,
        evidence_ref_ids=[],
        reason_codes=["missing_observable_typed_dependency"],
    )
