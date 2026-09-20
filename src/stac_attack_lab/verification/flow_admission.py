from __future__ import annotations

from stac_attack_lab.flow.analysis import (
    AdmissionProfile,
    AnalysisClassification,
    DependencySlice,
    GateStatus,
    InterventionRecord,
    LayeredAdmission,
    ProfileAssessment,
)
from stac_attack_lab.flow.models import (
    ClaimVerdict,
    DependencyRelation,
    EffectGraph,
    EvidenceRef,
    ExecutionStatus,
    InterventionResult,
)


def assess_flow_profiles(
    graph: EffectGraph,
    dependency_slice: DependencySlice,
    evidence_refs: list[EvidenceRef],
    *,
    intervention: InterventionRecord | None = None,
    input_integrity: GateStatus = GateStatus.passed,
) -> LayeredAdmission:
    evidence_ids = {item.evidence_id for item in evidence_refs}
    referenced_evidence = {
        evidence_id for item in graph.domains for evidence_id in item.identity_evidence_ids
    }
    referenced_evidence.update(
        evidence_id
        for items in (graph.artifacts, graph.effects, graph.claims)
        for item in items
        for evidence_id in item.evidence_ids
    )
    descriptive_reasons: list[str] = []
    if input_integrity != GateStatus.passed:
        descriptive_reasons.append("analysis_input_integrity_not_passed")
    missing_evidence = sorted(referenced_evidence - evidence_ids)
    if missing_evidence:
        descriptive_reasons.append("analysis_evidence_reference_missing")
    if dependency_slice.graph_reference_consistency != "passed":
        descriptive_reasons.append("slice_graph_reference_consistency_failed")
    descriptive_status = GateStatus.passed if not descriptive_reasons else GateStatus.failed
    descriptive = ProfileAssessment(
        profile=AdmissionProfile.descriptive_trace,
        status=descriptive_status,
        classification=(
            AnalysisClassification.accepted
            if descriptive_status == GateStatus.passed
            else AnalysisClassification.incomplete
        ),
        reason_codes=descriptive_reasons or ["descriptive_trace_valid"],
    )

    claim_by_id = {item.claim_id: item for item in graph.claims}
    required_refs = [item for item in dependency_slice.claims if item.required]
    verified_reasons: list[str] = []
    verified_status = GateStatus.unknown
    verified_class = AnalysisClassification.incomplete
    if descriptive.status != GateStatus.passed:
        verified_reasons.append("descriptive_profile_not_passed")
    elif not required_refs:
        verified_reasons.append("verified_dependency_requirements_missing")
    else:
        required_claims = [claim_by_id[item.claim_id] for item in required_refs]
        if any(item.dependency_verdict == ClaimVerdict.refuted for item in required_claims):
            verified_status = GateStatus.failed
            verified_class = AnalysisClassification.verified_negative
            verified_reasons.append("required_dependency_refuted")
        elif any(item.dependency_verdict != ClaimVerdict.verified for item in required_claims):
            verified_reasons.append("required_dependency_not_verified")
        else:
            effect_by_id = {item.effect_id: item for item in graph.effects}
            invalid_effects = [
                effect_by_id[item]
                for item in dependency_slice.effect_ids
                if effect_by_id[item].execution_status
                not in {ExecutionStatus.observed, ExecutionStatus.committed}
            ]
            if invalid_effects:
                verified_status = GateStatus.failed
                verified_reasons.append("required_effect_execution_not_observed")
            elif dependency_slice.truncated:
                verified_reasons.append("dependency_slice_truncated")
            else:
                verified_status = GateStatus.passed
                verified_class = AnalysisClassification.accepted
                verified_reasons.append("required_dependencies_verified")
    verified = ProfileAssessment(
        profile=AdmissionProfile.verified_dependency,
        status=verified_status,
        classification=verified_class,
        reason_codes=verified_reasons,
        evidence_ids=sorted(
            {
                evidence_id
                for item in required_refs
                for evidence_id in claim_by_id[item.claim_id].evidence_ids
            }
        ),
    )

    cross_reasons: list[str] = []
    cross_status = GateStatus.unknown
    if verified.status != GateStatus.passed:
        cross_reasons.append("verified_dependency_profile_not_passed")
    else:
        effect_by_id = {item.effect_id: item for item in graph.effects}
        selected_domain_ids = {
            domain_id
            for effect_id in dependency_slice.effect_ids
            for domain_id in effect_by_id[effect_id].domain_ids
        }
        selected_domains = [item for item in graph.domains if item.domain_id in selected_domain_ids]
        sessions = {item.actual_session_id for item in selected_domains if item.actual_session_id}
        scopes = {item.workspace_scope for item in selected_domains if item.workspace_scope}
        required_claims = [claim_by_id[item.claim_id] for item in required_refs]
        read_from = [
            item
            for item in required_claims
            if item.relation == DependencyRelation.read_from
            and item.dependency_verdict == ClaimVerdict.verified
        ]
        downstream = [
            item
            for item in required_claims
            if item.relation
            in {
                DependencyRelation.available_input,
                DependencyRelation.data_dep,
                DependencyRelation.delivered_to,
            }
            and item.dependency_verdict == ClaimVerdict.verified
        ]
        if len(sessions) < 2:
            cross_reasons.append("cross_session_actual_identity_not_observed")
        if len(scopes) != 1:
            cross_reasons.append("cross_session_workspace_scope_not_unique")
        if not read_from:
            cross_reasons.append("cross_session_read_from_not_verified")
        if not downstream:
            cross_reasons.append("cross_session_downstream_relation_not_verified")
        if not cross_reasons:
            cross_status = GateStatus.passed
            cross_reasons.append("cross_session_propagation_verified")
    cross = ProfileAssessment(
        profile=AdmissionProfile.cross_session_propagation,
        status=cross_status,
        classification=(
            AnalysisClassification.accepted
            if cross_status == GateStatus.passed
            else AnalysisClassification.incomplete
        ),
        reason_codes=cross_reasons,
    )

    intervention_reasons: list[str] = []
    intervention_status = GateStatus.unknown
    if cross.status != GateStatus.passed:
        intervention_reasons.append("cross_session_profile_not_passed")
    elif intervention is None:
        intervention_reasons.append("intervention_record_missing")
    elif intervention.result == InterventionResult.not_evaluated:
        intervention_reasons.append("intervention_not_evaluated")
    elif not intervention.execution_evidence_ids:
        intervention_reasons.append("intervention_execution_evidence_missing")
    elif not intervention.paired_invariants:
        intervention_reasons.append("intervention_pair_invariants_missing")
    else:
        intervention_status = GateStatus.passed
        intervention_reasons.append("intervention_comparison_evidence_present")
    intervention_profile = ProfileAssessment(
        profile=AdmissionProfile.intervention_comparison,
        status=intervention_status,
        classification=(
            AnalysisClassification.accepted
            if intervention_status == GateStatus.passed
            else AnalysisClassification.incomplete
        ),
        reason_codes=intervention_reasons,
        evidence_ids=(intervention.execution_evidence_ids if intervention else []),
    )
    profiles = [descriptive, verified, cross, intervention_profile]
    return LayeredAdmission(
        input_integrity=input_integrity,
        structural_admission=(
            GateStatus.passed if descriptive.status == GateStatus.passed else GateStatus.failed
        ),
        runtime_review=GateStatus.unknown,
        execution_authorization="absent",
        official_outcome="not_evaluated",
        profiles=profiles,
    )
