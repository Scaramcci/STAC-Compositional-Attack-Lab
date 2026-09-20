from __future__ import annotations

from enum import StrEnum
from typing import Any, Literal

from pydantic import Field, NonNegativeInt, PositiveInt, model_validator

from stac_attack_lab.contracts import StrictModel
from stac_attack_lab.flow.models import (
    ClaimVerdict,
    DependencyRelation,
    InterventionResult,
    PrimitiveKind,
)
from stac_attack_lab.hashing import stable_hash


class FlowRegistry(StrictModel):
    schema_version: Literal["3.0"] = "3.0"
    registry_id: str
    registry_version: str
    primitive_kinds: list[PrimitiveKind]
    dependency_relations: list[DependencyRelation]
    projector_version: str
    verifier_version: str
    macro_contract_version: str

    @model_validator(mode="after")
    def validate_registry(self) -> FlowRegistry:
        if set(self.primitive_kinds) != set(PrimitiveKind):
            raise ValueError("flow_registry_primitive_set_invalid")
        if set(self.dependency_relations) != set(DependencyRelation):
            raise ValueError("flow_registry_relation_set_invalid")
        if len(self.primitive_kinds) != len(set(self.primitive_kinds)):
            raise ValueError("flow_registry_duplicate_primitive")
        if len(self.dependency_relations) != len(set(self.dependency_relations)):
            raise ValueError("flow_registry_duplicate_relation")
        for name in (
            "registry_id",
            "registry_version",
            "projector_version",
            "verifier_version",
            "macro_contract_version",
        ):
            if not str(getattr(self, name)).strip():
                raise ValueError(f"flow_registry_{name}_missing")
        return self

    @property
    def registry_hash(self) -> str:
        return stable_hash(self.model_dump(mode="json"))


class SliceJoinSemantics(StrEnum):
    all = "ALL"
    any = "ANY"
    k_of_n = "K_OF_N"


class SliceBudget(StrictModel):
    max_nodes: PositiveInt = 256
    max_edges: PositiveInt = 512
    max_candidates: PositiveInt = 2048
    max_depth: PositiveInt = 32
    max_wall_time_ms: PositiveInt = 2000


class JoinRequirement(StrictModel):
    join_group_id: str
    target_port_id: str
    member_claim_ids: list[str]
    semantics: SliceJoinSemantics
    k: PositiveInt | None = None
    origin: Literal["observed", "template_requirement"]

    @model_validator(mode="after")
    def validate_join(self) -> JoinRequirement:
        if not self.join_group_id or not self.member_claim_ids:
            raise ValueError("slice_join_identity_missing")
        if len(self.member_claim_ids) != len(set(self.member_claim_ids)):
            raise ValueError("slice_join_duplicate_member")
        if self.semantics == SliceJoinSemantics.k_of_n:
            if self.k is None or self.k > len(self.member_claim_ids):
                raise ValueError("slice_join_k_invalid")
        elif self.k is not None:
            raise ValueError("slice_join_k_only_for_k_of_n")
        return self


class SliceClaimRef(StrictModel):
    claim_id: str
    source_port_id: str
    target_port_id: str
    relation: DependencyRelation
    verdict: ClaimVerdict
    origin: Literal["observed", "template_requirement"]
    required: bool


class ExternalPrecondition(StrictModel):
    precondition_id: str
    boundary_port_id: str
    omitted_claim_id: str | None = None
    reason_code: str


class DependencySlice(StrictModel):
    schema_version: Literal["3.0"] = "3.0"
    slice_id: str
    source_graph_id: str
    source_graph_hash: str
    sink_port_ids: list[str]
    effect_ids: list[str]
    port_ids: list[str]
    resource_version_ids: list[str]
    effect_group_ids: list[str]
    claims: list[SliceClaimRef]
    joins: list[JoinRequirement]
    external_preconditions: list[ExternalPrecondition]
    display_paths: list[list[str]]
    budget: SliceBudget
    candidate_count: NonNegativeInt
    truncated: bool
    truncation_reasons: list[str]
    graph_reference_consistency: Literal["passed", "failed"]
    replay_consistency: Literal["not_evaluated"] = "not_evaluated"
    slice_hash: str

    @model_validator(mode="after")
    def validate_slice(self) -> DependencySlice:
        for name, values in (
            ("sink", self.sink_port_ids),
            ("effect", self.effect_ids),
            ("port", self.port_ids),
            ("resource", self.resource_version_ids),
            ("group", self.effect_group_ids),
        ):
            if len(values) != len(set(values)):
                raise ValueError(f"duplicate_slice_{name}_id")
        expected = self.model_dump(mode="json", exclude={"slice_hash"})
        if self.slice_hash != stable_hash(expected):
            raise ValueError("dependency_slice_hash_mismatch")
        return self


class AdmissionProfile(StrEnum):
    descriptive_trace = "descriptive_trace"
    verified_dependency = "verified_dependency"
    cross_session_propagation = "cross_session_propagation"
    intervention_comparison = "intervention_comparison"


class GateStatus(StrEnum):
    passed = "passed"
    failed = "failed"
    unknown = "unknown"
    not_applicable = "not_applicable"


class AnalysisClassification(StrEnum):
    accepted = "accepted"
    infra_failure = "infra_failure"
    incomplete = "incomplete"
    unsupported = "unsupported"
    verified_negative = "verified_negative"


class ProfileAssessment(StrictModel):
    profile: AdmissionProfile
    status: GateStatus
    classification: AnalysisClassification
    reason_codes: list[str]
    evidence_ids: list[str] = Field(default_factory=list)


class LayeredAdmission(StrictModel):
    schema_version: Literal["3.0"] = "3.0"
    input_integrity: GateStatus
    structural_admission: GateStatus
    runtime_review: GateStatus = GateStatus.unknown
    execution_authorization: Literal["absent", "granted"] = "absent"
    official_outcome: Literal["not_evaluated", "passed", "failed", "unknown"] = "not_evaluated"
    profiles: list[ProfileAssessment]

    @model_validator(mode="after")
    def validate_profile_order(self) -> LayeredAdmission:
        expected = list(AdmissionProfile)
        observed = [item.profile for item in self.profiles]
        if observed != expected:
            raise ValueError("layered_admission_profile_order_invalid")
        passed_higher = False
        for item in reversed(self.profiles):
            if item.status == GateStatus.passed:
                passed_higher = True
            elif passed_higher:
                raise ValueError("higher_profile_pass_requires_lower_profile_pass")
        return self


class MacroBindingStatus(StrEnum):
    bound = "bound"
    unsupported = "unsupported"
    unknown = "unknown"


class MacroBinding(StrictModel):
    schema_version: Literal["3.0"] = "3.0"
    binding_id: str
    macro_name: Literal["PersistRecall", "Bind"]
    macro_version: str
    status: MacroBindingStatus
    effect_ids: list[str]
    port_ids: list[str]
    claim_ids: list[str]
    constraints: dict[str, str]
    reason_codes: list[str]


class InterventionRecord(StrictModel):
    schema_version: Literal["3.0"] = "3.0"
    intervention_id: str
    changed_field_paths: list[str]
    changed_resource_version_ids: list[str]
    target_claim_ids: list[str]
    potentially_affected_claim_ids: list[str]
    paired_invariants: dict[str, str]
    execution_evidence_ids: list[str]
    execution_deviations: list[str]
    result: InterventionResult = InterventionResult.not_evaluated

    @model_validator(mode="after")
    def validate_intervention(self) -> InterventionRecord:
        if self.result != InterventionResult.not_evaluated and not self.execution_evidence_ids:
            raise ValueError("intervention_result_requires_execution_evidence")
        return self


class AnalysisInputRef(StrictModel):
    relative_or_declared_path: str
    content_hash: str
    kind: str


class AnalysisOutputRef(StrictModel):
    relative_path: str
    content_hash: str
    kind: str


class AnalysisManifest(StrictModel):
    schema_version: Literal["3.0"] = "3.0"
    analysis_id: str
    analysis_key: str
    run_id: str | None = None
    template_id: str | None = None
    input_mode: Literal["collection", "interaction_graph"]
    input_refs: list[AnalysisInputRef]
    collection_manifest_hash: str | None = None
    collection_tree_hash: str | None = None
    collection_config_hash: str | None = None
    collection_registry_hash: str | None = None
    sampling_strategy: dict[str, str]
    profile_id: str
    profile_version: str
    profile_hash: str
    registry_id: str
    registry_version: str
    registry_hash: str
    projector_version: str
    verifier_version: str
    policy_hashes: list[str]
    processing_source_hashes: dict[str, str]
    parameters: dict[str, Any]
    evidence_bundle_refs: list[AnalysisInputRef]
    output_refs: list[AnalysisOutputRef]
    completeness: Literal["complete", "partial", "blocked", "error"]
    truncated: bool
    truncation_reasons: list[str]
    legacy_verdicts_inherited: Literal[False] = False
    sampling_bias_acknowledged: Literal[True] = True
    manifest_hash: str

    @model_validator(mode="after")
    def validate_manifest(self) -> AnalysisManifest:
        expected = self.model_dump(mode="json", exclude={"manifest_hash"})
        if self.manifest_hash != stable_hash(expected):
            raise ValueError("analysis_manifest_hash_mismatch")
        return self


class FlowAnalysisReport(StrictModel):
    schema_version: Literal["3.0"] = "3.0"
    analysis_id: str
    analysis_key: str
    input_mode: Literal["collection", "interaction_graph"]
    graph_count: NonNegativeInt
    slice_count: NonNegativeInt
    object_counts: dict[str, NonNegativeInt]
    effect_counts: dict[str, NonNegativeInt]
    claim_verdict_counts: dict[str, NonNegativeInt]
    unresolved_reason_counts: dict[str, NonNegativeInt]
    scope_or_version_error_counts: dict[str, NonNegativeInt]
    deduplication_basis: str
    profiles: list[ProfileAssessment]
    macro_bindings: list[MacroBinding]
    truncated: bool
    truncation_reasons: list[str]
    runtime_review: GateStatus
    execution_authorization: Literal["absent", "granted"]
    intervention_result: InterventionResult
    official_outcome: Literal["not_evaluated"] = "not_evaluated"
    limitations: list[str]
