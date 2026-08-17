from __future__ import annotations

from collections import deque

from stac_attack_lab.interactions.models import (
    InteractionArtifact,
    InteractionEvent,
    InteractionEventType,
    InteractionGraph,
    PrimitiveOccurrence,
)
from stac_attack_lab.primitives.core import (
    CorePrimitiveFamily,
    EvidenceGrade,
    PrimitiveOutcome,
)
from stac_attack_lab.verification.formal_models import OccurrenceVerdict


def _artifact_descends_from(
    artifact: InteractionArtifact,
    ancestor_ids: set[str],
    artifacts: dict[str, InteractionArtifact],
) -> bool:
    frontier = deque(artifact.parent_artifact_ids)
    visited: set[str] = set()
    while frontier:
        artifact_id = frontier.popleft()
        if artifact_id in ancestor_ids:
            return True
        if artifact_id in visited:
            continue
        visited.add(artifact_id)
        parent = artifacts.get(artifact_id)
        if parent is not None:
            frontier.extend(parent.parent_artifact_ids)
    return False


def _transfer_observable(events: list[InteractionEvent]) -> bool:
    return any(
        event.input_artifact_ids
        or event.output_artifact_ids
        or (
            event.event_type == InteractionEventType.tool_result
            and event.request_event_id is not None
        )
        for event in events
    )


def _transform_observable(
    events: list[InteractionEvent], artifacts: dict[str, InteractionArtifact]
) -> bool:
    for event in events:
        input_ids = set(event.input_artifact_ids)
        if not input_ids or not event.output_artifact_ids:
            continue
        if any(
            output_id in artifacts
            and _artifact_descends_from(artifacts[output_id], input_ids, artifacts)
            for output_id in event.output_artifact_ids
        ):
            return True
    return False


def _mutation_observable(events: list[InteractionEvent]) -> bool:
    return any(
        event.event_type == InteractionEventType.state_write
        and bool(event.write_state_refs)
        and event.pre_state_ref is not None
        and event.post_state_ref is not None
        and event.pre_state_ref != event.post_state_ref
        for event in events
    )


def _control_observable(events: list[InteractionEvent]) -> bool:
    return any(
        event.event_type in {InteractionEventType.lifecycle, InteractionEventType.policy}
        and (event.lifecycle_id is not None or bool(event.evidence_ref_ids))
        for event in events
    )


def verify_occurrence(claim: PrimitiveOccurrence, graph: InteractionGraph) -> OccurrenceVerdict:
    event_by_id = {event.event_id: event for event in graph.events}
    events = [
        event_by_id[event_id] for event_id in claim.source_event_ids if event_id in event_by_id
    ]
    reasons: list[str] = []
    if len(events) != len(claim.source_event_ids) or not events:
        reasons.append("occurrence_source_event_missing")
        return OccurrenceVerdict(
            occurrence_id=claim.occurrence_id,
            primitive_ref=claim.primitive_ref,
            outcome=PrimitiveOutcome.not_observable,
            hard_fact=False,
            evidence_grades=claim.evidence_grades,
            evidence_ref_ids=claim.evidence_ref_ids,
            reason_codes=reasons,
        )

    if claim.outcome != PrimitiveOutcome.passed:
        event_outcomes = {event.status for event in events}
        observed = claim.outcome in event_outcomes or claim.outcome in {
            PrimitiveOutcome.not_observable,
            PrimitiveOutcome.not_reached,
            PrimitiveOutcome.abstained,
        }
        return OccurrenceVerdict(
            occurrence_id=claim.occurrence_id,
            primitive_ref=claim.primitive_ref,
            outcome=claim.outcome if observed else PrimitiveOutcome.not_observable,
            hard_fact=claim.hard_fact and observed,
            evidence_grades=claim.evidence_grades,
            evidence_ref_ids=claim.evidence_ref_ids,
            reason_codes=claim.reason_codes
            + (["non_pass_outcome_not_observed"] if not observed else []),
        )

    artifacts = {artifact.artifact_id: artifact for artifact in graph.artifacts}
    observable = {
        CorePrimitiveFamily.transfer: lambda: _transfer_observable(events),
        CorePrimitiveFamily.transform: lambda: _transform_observable(events, artifacts),
        CorePrimitiveFamily.mutate: lambda: _mutation_observable(events),
        CorePrimitiveFamily.control: lambda: _control_observable(events),
    }[claim.family]()
    hard_grades = {EvidenceGrade.direct, EvidenceGrade.deterministic_derived}
    hard_evidence = bool(set(claim.evidence_grades) & hard_grades)
    event_passed = all(event.status == PrimitiveOutcome.passed for event in events)
    if not observable:
        reasons.append(f"{claim.family.value.lower()}_transition_not_observable")
    if not hard_evidence:
        reasons.append("hard_evidence_missing")
    if not event_passed:
        reasons.append("source_event_outcome_not_passed")
    passed = observable and hard_evidence and event_passed and claim.hard_fact
    if claim.semantic_labels and not passed:
        reasons.append("semantic_annotation_cannot_override_hard_verdict")
    return OccurrenceVerdict(
        occurrence_id=claim.occurrence_id,
        primitive_ref=claim.primitive_ref,
        outcome=(PrimitiveOutcome.passed if passed else PrimitiveOutcome.not_observable),
        hard_fact=passed,
        evidence_grades=claim.evidence_grades,
        evidence_ref_ids=claim.evidence_ref_ids,
        reason_codes=reasons or ["occurrence_hard_evidence_verified"],
    )


def missing_occurrence_verdict(primitive_ref: str) -> OccurrenceVerdict:
    return OccurrenceVerdict(
        occurrence_id=f"missing:{primitive_ref}",
        primitive_ref=primitive_ref,
        outcome=PrimitiveOutcome.not_reached,
        hard_fact=False,
        evidence_grades=[],
        evidence_ref_ids=[],
        reason_codes=["required_primitive_not_reached"],
    )
