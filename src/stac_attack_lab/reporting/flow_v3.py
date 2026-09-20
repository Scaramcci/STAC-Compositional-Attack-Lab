from __future__ import annotations

from collections import Counter
from typing import Literal

from stac_attack_lab.flow.analysis import (
    AdmissionProfile,
    DependencySlice,
    FlowAnalysisReport,
    GateStatus,
    LayeredAdmission,
    MacroBinding,
    ProfileAssessment,
)
from stac_attack_lab.flow.models import EffectGraph, InterventionResult


def build_flow_analysis_report(
    *,
    analysis_id: str,
    analysis_key: str,
    input_mode: Literal["collection", "interaction_graph"],
    graphs: list[EffectGraph],
    slices: list[DependencySlice],
    admissions: list[LayeredAdmission],
    macro_bindings: list[MacroBinding],
) -> FlowAnalysisReport:
    effects = Counter(item.primitive.value for graph in graphs for item in graph.effects)
    verdicts = Counter(item.dependency_verdict.value for graph in graphs for item in graph.claims)
    unresolved = Counter(item.reason_code for graph in graphs for item in graph.unresolved)
    scope_errors = Counter(
        {
            reason: count
            for reason, count in unresolved.items()
            if "scope" in reason or "version" in reason
        }
    )
    profile_by_name: dict[AdmissionProfile, ProfileAssessment] = {}
    for admission in admissions:
        for profile in admission.profiles:
            existing = profile_by_name.get(profile.profile)
            if existing is None or existing.status == GateStatus.passed:
                profile_by_name[profile.profile] = profile.model_copy(update={"evidence_ids": []})
    profiles = (
        [
            profile_by_name[item.profile]
            for item in admissions[0].profiles
            if item.profile in profile_by_name
        ]
        if admissions
        else []
    )
    return FlowAnalysisReport(
        analysis_id=analysis_id,
        analysis_key=analysis_key,
        input_mode=input_mode,
        graph_count=len(graphs),
        slice_count=len(slices),
        object_counts={
            "domains": sum(len(item.domains) for item in graphs),
            "artifacts": sum(len(item.artifacts) for item in graphs),
            "ports": sum(len(item.ports) for item in graphs),
            "resource_versions": sum(len(item.resource_versions) for item in graphs),
            "effect_groups": sum(len(item.effect_groups) for item in graphs),
        },
        effect_counts=dict(effects),
        claim_verdict_counts=dict(verdicts),
        unresolved_reason_counts=dict(unresolved),
        scope_or_version_error_counts=dict(scope_errors),
        deduplication_basis=(
            "stable source operation/effect identity; content hash does not merge occurrences"
        ),
        profiles=profiles,
        macro_bindings=macro_bindings,
        truncated=any(item.truncated for item in slices),
        truncation_reasons=sorted(
            {reason for item in slices for reason in item.truncation_reasons}
        ),
        runtime_review=GateStatus.unknown,
        execution_authorization="absent",
        intervention_result=InterventionResult.not_evaluated,
        limitations=[
            "serializable graphs do not establish attack success",
            "legacy accepted, negative, and causal_pass verdicts are not inherited",
            "same-raw representation comparison retains collection sampling bias",
            "real provider compatibility and runtime closure were not evaluated",
            "official evaluator and intervention execution were not run",
        ],
    )
