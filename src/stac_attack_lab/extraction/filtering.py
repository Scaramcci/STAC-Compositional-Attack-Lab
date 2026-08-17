from __future__ import annotations

from pydantic import Field, NonNegativeInt

from stac_attack_lab.contracts import StrictModel
from stac_attack_lab.datasets.primitive_chain import (
    FilterDecision,
    FilterGate,
    PrimitiveChainCandidate,
)
from stac_attack_lab.extraction.chains import CANONICAL_REQUIRED_CORE_EDGES
from stac_attack_lab.interactions.models import InteractionGraph, PrimitiveOccurrence
from stac_attack_lab.primitives.core import EvidenceGrade, PrimitiveOutcome
from stac_attack_lab.primitives.formal_registry import FormalPrimitiveRegistry


class ChainFilteringPolicy(StrictModel):
    policy_id: str = "formal-g0-g8-v1"
    require_replay_consistency: bool = True
    require_all_canonical_core_edges: bool = True
    allowed_source_splits: list[str] = Field(default_factory=lambda: ["train", "dev", "synthetic"])
    formal_excluded_task_ids: list[str] = Field(default_factory=list)
    available_capabilities: list[str]
    maximum_candidates_per_topology: NonNegativeInt = 100


class CandidateFilterRecord(StrictModel):
    candidate_id: str
    accepted: bool
    pool: str
    decisions: list[FilterDecision]


class ChainFilteringResult(StrictModel):
    accepted: list[PrimitiveChainCandidate]
    negative: list[PrimitiveChainCandidate]
    records: list[CandidateFilterRecord]


REQUIRED_PRIMITIVE_REFS = {
    "core.transfer.external_ingress@1",
    "core.transform.extract@1",
    "core.mutate.memory_write@1",
    "core.control.restart@1",
    "core.transfer.retrieve@1",
    "core.transform.parameterize@1",
    "core.transfer.request@1",
    "core.mutate.external_effect@1",
}


def _decision(
    gate: FilterGate,
    passed: bool,
    pass_reason: str,
    failure_reasons: list[str],
    evidence_refs: list[str] | None = None,
) -> FilterDecision:
    return FilterDecision(
        gate=gate,
        passed=passed,
        reason_codes=[pass_reason] if passed else failure_reasons,
        evidence_ref_ids=evidence_refs or [],
    )


def _required_edge_findings(
    graph: InteractionGraph,
    occurrences: list[PrimitiveOccurrence],
) -> tuple[list[str], list[str]]:
    by_ref = {occurrence.primitive_ref: occurrence for occurrence in occurrences}
    missing: list[str] = []
    evidence: list[str] = []
    for source_ref, target_ref, edge_type in CANONICAL_REQUIRED_CORE_EDGES:
        source = by_ref.get(source_ref)
        target = by_ref.get(target_ref)
        edge_label = f"{source_ref}->{target_ref}:{edge_type.value}"
        if source is None or target is None:
            missing.append("missing_occurrence_for_edge:" + edge_label)
            continue
        source_events = set(source.source_event_ids)
        target_events = set(target.source_event_ids)
        match = next(
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
        if match is None:
            missing.append("missing_typed_causal_edge:" + edge_label)
        else:
            evidence.extend(match.evidence_ref_ids)
    return missing, list(dict.fromkeys(evidence))


def filter_chain_candidate(
    candidate: PrimitiveChainCandidate,
    graph: InteractionGraph,
    occurrences: list[PrimitiveOccurrence],
    registry: FormalPrimitiveRegistry,
    policy: ChainFilteringPolicy,
    *,
    duplicate: bool = False,
    topology_count: int = 0,
) -> CandidateFilterRecord:
    decisions: list[FilterDecision] = []

    schema_errors: list[str] = []
    if candidate.registry_hash != registry.registry_hash:
        schema_errors.append("registry_hash_mismatch")
    if candidate.interaction_graph_id != graph.graph_id:
        schema_errors.append("interaction_graph_id_mismatch")
    decisions.append(
        _decision(FilterGate.schema_type, not schema_errors, "schema_and_type_valid", schema_errors)
    )

    by_ref = {occurrence.primitive_ref: occurrence for occurrence in occurrences}
    evidence_errors: list[str] = []
    evidence_refs: list[str] = []
    for primitive_ref in sorted(REQUIRED_PRIMITIVE_REFS):
        occurrence = by_ref.get(primitive_ref)
        if occurrence is None:
            evidence_errors.append(f"required_occurrence_missing:{primitive_ref}")
            continue
        evidence_refs.extend(occurrence.evidence_ref_ids)
        if occurrence.outcome != PrimitiveOutcome.passed or not occurrence.hard_fact:
            evidence_errors.append(f"required_occurrence_not_hard_pass:{primitive_ref}")
        if not set(occurrence.evidence_grades) & {
            EvidenceGrade.direct,
            EvidenceGrade.deterministic_derived,
        }:
            evidence_errors.append(f"required_occurrence_missing_e1_e2:{primitive_ref}")
    decisions.append(
        _decision(
            FilterGate.occurrence_evidence,
            not evidence_errors,
            "required_occurrences_hard_pass",
            evidence_errors,
            list(dict.fromkeys(evidence_refs)),
        )
    )

    edge_errors, edge_evidence = _required_edge_findings(graph, occurrences)
    decisions.append(
        _decision(
            FilterGate.causal_edge,
            not edge_errors,
            "typed_causal_edges_valid",
            edge_errors,
            edge_evidence,
        )
    )

    required_capabilities = {
        capability
        for macro_ref in (node.macro_primitive_ref for node in candidate.nodes)
        for capability in registry.resolve_macro(macro_ref).required_capabilities
    }
    missing_capabilities = required_capabilities - set(policy.available_capabilities)
    decisions.append(
        _decision(
            FilterGate.environment_binding,
            not missing_capabilities,
            "environment_capabilities_satisfied",
            [f"missing_capability:{item}" for item in sorted(missing_capabilities)],
        )
    )

    replay_errors: list[str] = []
    if policy.require_replay_consistency and graph.unresolved_links:
        replay_errors.extend(
            f"unresolved_link:{link.reason_code}" for link in graph.unresolved_links
        )
    decisions.append(
        _decision(
            FilterGate.replay_consistency,
            not replay_errors,
            "checkpoint_and_reference_consistency_passed",
            replay_errors,
        )
    )

    tainted_ingress = any(
        "untrusted" in artifact.taint_labels
        for artifact in graph.artifacts
        if artifact.producer_event_id
        in {
            event_id
            for occurrence in occurrences
            if occurrence.primitive_ref == "core.transfer.external_ingress@1"
            for event_id in occurrence.source_event_ids
        }
    )
    relevance_errors: list[str] = []
    if not tainted_ingress:
        relevance_errors.append("untrusted_ingress_not_tainted")
    if candidate.forbidden_shortcut_detected:
        relevance_errors.append("forbidden_shortcut_detected")
    if not candidate.terminal_predicates:
        relevance_errors.append("terminal_predicate_missing")
    decisions.append(
        _decision(
            FilterGate.attack_relevance,
            not relevance_errors,
            "attack_relevance_and_shortcut_gate_passed",
            relevance_errors,
        )
    )

    split_errors: list[str] = []
    if candidate.source_split not in policy.allowed_source_splits:
        split_errors.append(f"source_split_not_allowed:{candidate.source_split}")
    if candidate.source_task_id in policy.formal_excluded_task_ids:
        split_errors.append("formal_task_leakage")
    decisions.append(
        _decision(
            FilterGate.split_privacy,
            not split_errors,
            "split_and_privacy_integrity_passed",
            split_errors,
        )
    )

    registry_roles = set(registry.component_roles)
    candidate_slots = {slot for node in candidate.nodes for slot in node.binding_slots}
    portability_errors = [
        f"unknown_binding_slot:{slot}" for slot in sorted(candidate_slots - registry_roles)
    ]
    if duplicate:
        portability_errors.append("duplicate_candidate_hash")
    decisions.append(
        _decision(
            FilterGate.portability_dedup,
            not portability_errors,
            "portable_and_unique",
            portability_errors,
        )
    )

    quota_exceeded = topology_count >= policy.maximum_candidates_per_topology
    decisions.append(
        _decision(
            FilterGate.coverage_diversity,
            not quota_exceeded,
            "coverage_quota_available",
            ["topology_quota_exceeded"] if quota_exceeded else [],
        )
    )
    accepted = all(decision.passed for decision in decisions)
    return CandidateFilterRecord(
        candidate_id=candidate.candidate_id,
        accepted=accepted,
        pool="accepted" if accepted else "negative",
        decisions=decisions,
    )


def filter_chain_candidates(
    candidates: list[PrimitiveChainCandidate],
    graph_by_id: dict[str, InteractionGraph],
    occurrences_by_graph_id: dict[str, list[PrimitiveOccurrence]],
    registry: FormalPrimitiveRegistry,
    policy: ChainFilteringPolicy,
) -> ChainFilteringResult:
    accepted: list[PrimitiveChainCandidate] = []
    negative: list[PrimitiveChainCandidate] = []
    records: list[CandidateFilterRecord] = []
    seen_hashes: set[str] = set()
    topology_count = 0
    for candidate in candidates:
        graph = graph_by_id[candidate.interaction_graph_id]
        record = filter_chain_candidate(
            candidate,
            graph,
            occurrences_by_graph_id[candidate.interaction_graph_id],
            registry,
            policy,
            duplicate=candidate.candidate_hash in seen_hashes,
            topology_count=topology_count,
        )
        seen_hashes.add(candidate.candidate_hash)
        records.append(record)
        updated = candidate.model_copy(update={"filter_decisions": record.decisions})
        if record.accepted:
            accepted.append(updated)
            topology_count += 1
        else:
            negative.append(updated)
    return ChainFilteringResult(accepted=accepted, negative=negative, records=records)
