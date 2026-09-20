from __future__ import annotations

from collections import Counter

from stac_attack_lab.flow.models import (
    ClaimVerdict,
    DependencyClaim,
    DependencyRelation,
    EffectGraph,
    EvidenceMethod,
    EvidenceRef,
    InterventionResult,
    effect_graph_hash,
)


def verify_dependency_claim(
    claim: DependencyClaim,
    *,
    graph: EffectGraph,
    evidence: dict[str, EvidenceRef],
) -> DependencyClaim:
    if claim.hypothesis:
        return claim.model_copy(
            update={
                "dependency_verdict": ClaimVerdict.unknown,
                "intervention_result": InterventionResult.not_evaluated,
                "reason_code": "hypothesis_is_not_dependency_evidence",
            }
        )
    if not claim.evidence_ids:
        return claim.model_copy(
            update={
                "dependency_verdict": ClaimVerdict.unknown,
                "reason_code": (
                    claim.reason_code
                    if claim.reason_code
                    not in {"not_verified", "awaiting_independent_verification"}
                    else "claim_evidence_missing"
                ),
            }
        )
    missing = [item for item in claim.evidence_ids if item not in evidence]
    if missing:
        return claim.model_copy(
            update={
                "dependency_verdict": ClaimVerdict.refuted,
                "reason_code": "claim_evidence_reference_unresolvable",
            }
        )
    methods = {evidence[item].method for item in claim.evidence_ids}
    ports = {item.port_id: item for item in graph.ports}
    source, target = ports[claim.source_port_id], ports[claim.target_port_id]

    if claim.relation == DependencyRelation.correlates_with:
        required = EvidenceMethod.request_response_correlation
        reason = "request_response_correlation_verified"
    elif claim.relation == DependencyRelation.delivered_to:
        required = EvidenceMethod.direct_observation
        reason = "endpoint_delivery_observed"
        if target.domain_id is None:
            return claim.model_copy(
                update={
                    "dependency_verdict": ClaimVerdict.refuted,
                    "reason_code": "delivery_target_domain_missing",
                }
            )
    elif claim.relation == DependencyRelation.available_input:
        required = EvidenceMethod.provider_request_context
        reason = "provider_request_available_input_verified"
    elif claim.relation == DependencyRelation.data_dep:
        required = EvidenceMethod.exact_projection
        reason = "declared_exact_projection_relation_verified"
    elif claim.relation == DependencyRelation.control_dep:
        required = EvidenceMethod.trusted_control
        reason = "instrumented_control_dependency_verified"
    elif claim.relation == DependencyRelation.happens_before:
        required = EvidenceMethod.explicit_partial_order
        reason = "explicit_partial_order_verified"
    elif claim.relation == DependencyRelation.read_from:
        required = EvidenceMethod.resource_commit
        reason = "resource_version_read_from_verified"
        if source.resource_version_id is None:
            return claim.model_copy(
                update={
                    "dependency_verdict": ClaimVerdict.refuted,
                    "reason_code": "read_from_source_version_missing",
                }
            )
        versions = {item.resource_version_id: item for item in graph.resource_versions}
        version = versions.get(source.resource_version_id)
        if version is None or not set(version.commit_evidence_ids) <= set(claim.evidence_ids):
            return claim.model_copy(
                update={
                    "dependency_verdict": ClaimVerdict.refuted,
                    "reason_code": "read_from_commit_evidence_unbound",
                }
            )
    else:  # pragma: no cover - enum exhaustiveness guard
        return claim.model_copy(
            update={
                "dependency_verdict": ClaimVerdict.unsupported,
                "reason_code": "dependency_relation_unsupported",
            }
        )

    if required not in methods:
        return claim.model_copy(
            update={
                "dependency_verdict": ClaimVerdict.unknown,
                "reason_code": f"{claim.relation.value}_required_evidence_method_missing",
            }
        )
    return claim.model_copy(
        update={
            "dependency_verdict": ClaimVerdict.verified,
            "intervention_result": InterventionResult.not_evaluated,
            "reason_code": reason,
        }
    )


def verify_effect_graph(graph: EffectGraph, evidence_refs: list[EvidenceRef]) -> EffectGraph:
    evidence = {item.evidence_id: item for item in evidence_refs}
    if len(evidence) != len(evidence_refs):
        raise ValueError("duplicate_v3_evidence_id")
    claims = [
        verify_dependency_claim(claim, graph=graph, evidence=evidence) for claim in graph.claims
    ]
    payload = graph.model_dump(mode="json", exclude={"graph_hash"})
    payload["claims"] = [item.model_dump(mode="json") for item in claims]
    payload["graph_hash"] = effect_graph_hash(payload)
    return EffectGraph.model_validate(payload)


def claim_verdict_counts(graph: EffectGraph) -> dict[str, int]:
    return dict(Counter(item.dependency_verdict.value for item in graph.claims))
