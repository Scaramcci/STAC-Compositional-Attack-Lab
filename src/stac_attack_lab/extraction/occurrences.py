from __future__ import annotations

from pydantic import Field

from stac_attack_lab.contracts import StrictModel
from stac_attack_lab.hashing import stable_hash
from stac_attack_lab.interactions.models import (
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
from stac_attack_lab.primitives.formal_registry import FormalPrimitiveRegistry


class OccurrenceExtractionDecision(StrictModel):
    event_id: str
    matched_primitive_ref: str | None
    emitted_occurrence_id: str | None
    hard_fact: bool
    reason_codes: list[str]
    semantic_labels: dict[str, str] = Field(default_factory=dict)


class OccurrenceExtractionResult(StrictModel):
    graph_id: str
    registry_hash: str
    occurrences: list[PrimitiveOccurrence]
    decisions: list[OccurrenceExtractionDecision]
    extraction_hash: str


def _match_event(event: InteractionEvent) -> tuple[CorePrimitiveFamily, str] | None:
    operation = event.operation.lower()
    if event.event_type == InteractionEventType.lifecycle:
        for subtype in ("restart", "wait", "retry", "stop", "branch", "reject"):
            if subtype in operation:
                return CorePrimitiveFamily.control, subtype
    if (
        event.event_type == InteractionEventType.policy
        and event.status == PrimitiveOutcome.rejected
    ):
        return CorePrimitiveFamily.control, "reject"
    if event.event_type == InteractionEventType.tool_call:
        return CorePrimitiveFamily.transfer, "request"
    if event.event_type == InteractionEventType.tool_result:
        if event.component_role == "untrusted_source":
            return CorePrimitiveFamily.transfer, "external_ingress"
        return CorePrimitiveFamily.transfer, "response"
    if (
        event.event_type == InteractionEventType.message
        and event.component_role == "untrusted_source"
        and "deliver" in operation
    ):
        return CorePrimitiveFamily.transfer, "external_ingress"
    if event.event_type == InteractionEventType.state_read:
        if event.component_role == "persistent_memory":
            return CorePrimitiveFamily.transfer, "retrieve"
        return CorePrimitiveFamily.transfer, "response"
    if event.event_type == InteractionEventType.state_write:
        subtype_by_component = {
            "persistent_memory": "memory_write",
            "workspace_file": "workspace_write",
            "configuration": "config_update",
            "sandbox_external_state": "external_effect",
        }
        component_subtype = subtype_by_component.get(event.component_role)
        if component_subtype:
            return CorePrimitiveFamily.mutate, component_subtype
    if event.event_type == InteractionEventType.message:
        for subtype in ("parameterize", "summarize", "sanitize", "merge", "extract"):
            if subtype in operation:
                return CorePrimitiveFamily.transform, subtype
    return None


def _evidence_for_event(
    event: InteractionEvent, graph: InteractionGraph, family: CorePrimitiveFamily
) -> tuple[list[EvidenceGrade], list[str]]:
    grades = [EvidenceGrade.direct]
    reasons: list[str] = []
    artifact_by_id = {artifact.artifact_id: artifact for artifact in graph.artifacts}
    if family == CorePrimitiveFamily.transfer:
        if event.output_artifact_ids or event.input_artifact_ids:
            grades.append(EvidenceGrade.deterministic_derived)
        else:
            reasons.append("transfer_visibility_not_observable")
    elif family == CorePrimitiveFamily.transform:
        derived = any(
            artifact_by_id[artifact_id].parent_artifact_ids
            for artifact_id in event.output_artifact_ids
            if artifact_id in artifact_by_id
        )
        if event.input_artifact_ids and event.output_artifact_ids and derived:
            grades.append(EvidenceGrade.deterministic_derived)
        else:
            reasons.append("transform_lineage_incomplete")
    elif family == CorePrimitiveFamily.mutate:
        if (
            event.pre_state_ref
            and event.post_state_ref
            and event.pre_state_ref != event.post_state_ref
            and event.write_state_refs
        ):
            grades.append(EvidenceGrade.deterministic_derived)
        else:
            reasons.append("mutation_pre_post_evidence_incomplete")
    elif family == CorePrimitiveFamily.control:
        if event.lifecycle_id or event.public_payload:
            grades.append(EvidenceGrade.deterministic_derived)
        else:
            reasons.append("control_transition_not_observable")
    return list(dict.fromkeys(grades)), reasons


def extract_primitive_occurrences(
    graph: InteractionGraph,
    registry: FormalPrimitiveRegistry,
    *,
    semantic_proposals: dict[str, dict[str, str]] | None = None,
) -> OccurrenceExtractionResult:
    proposals = semantic_proposals or {}
    occurrences: list[PrimitiveOccurrence] = []
    decisions: list[OccurrenceExtractionDecision] = []
    for event in sorted(graph.events, key=lambda item: (item.logical_time, item.sequence_no)):
        matched = _match_event(event)
        semantic_labels = dict(proposals.get(event.event_id, {}))
        if matched is None:
            decisions.append(
                OccurrenceExtractionDecision(
                    event_id=event.event_id,
                    matched_primitive_ref=None,
                    emitted_occurrence_id=None,
                    hard_fact=False,
                    reason_codes=["no_deterministic_primitive_match"],
                    semantic_labels=semantic_labels,
                )
            )
            continue
        family, subtype = matched
        primitive_ref = f"core.{family.value.lower()}.{subtype}@1"
        registry.core_by_id(primitive_ref)
        grades, evidence_reasons = _evidence_for_event(event, graph, family)
        outcome = event.status
        hard_fact = True
        if outcome == PrimitiveOutcome.passed and evidence_reasons:
            outcome = PrimitiveOutcome.not_observable
            hard_fact = False
        occurrence_id = (
            "occ-"
            + stable_hash(
                {
                    "graph_id": graph.graph_id,
                    "event_id": event.event_id,
                    "primitive_ref": primitive_ref,
                }
            )[:16]
        )
        occurrence = PrimitiveOccurrence(
            occurrence_id=occurrence_id,
            graph_id=graph.graph_id,
            primitive_ref=primitive_ref,
            family=family,
            subtype=subtype,
            outcome=outcome,
            source_component_roles=[event.component_role],
            target_component_roles=[event.component_role],
            input_artifact_ids=event.input_artifact_ids,
            output_artifact_ids=event.output_artifact_ids,
            pre_state_refs=[event.pre_state_ref] if event.pre_state_ref else [],
            post_state_refs=[event.post_state_ref] if event.post_state_ref else [],
            source_event_ids=[event.event_id],
            evidence_grades=grades,
            evidence_ref_ids=[event.source_event_ref, *event.evidence_ref_ids],
            confidence=1.0 if hard_fact else 0.0,
            hard_fact=hard_fact,
            reason_codes=evidence_reasons,
            semantic_labels=semantic_labels,
        )
        occurrences.append(occurrence)
        decisions.append(
            OccurrenceExtractionDecision(
                event_id=event.event_id,
                matched_primitive_ref=primitive_ref,
                emitted_occurrence_id=occurrence_id,
                hard_fact=hard_fact,
                reason_codes=evidence_reasons or ["deterministic_match"],
                semantic_labels=semantic_labels,
            )
        )
    payload = {
        "graph_id": graph.graph_id,
        "registry_hash": registry.registry_hash,
        "occurrences": [item.model_dump(mode="json") for item in occurrences],
        "decisions": [item.model_dump(mode="json") for item in decisions],
    }
    return OccurrenceExtractionResult(
        graph_id=graph.graph_id,
        registry_hash=registry.registry_hash,
        occurrences=occurrences,
        decisions=decisions,
        extraction_hash=stable_hash(payload),
    )
