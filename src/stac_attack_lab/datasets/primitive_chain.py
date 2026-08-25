from __future__ import annotations

from enum import StrEnum
from typing import Literal

from pydantic import Field, NonNegativeInt, PositiveInt, model_validator

from stac_attack_lab.contracts import StrictModel
from stac_attack_lab.interactions.models import ConstructionManifest, DependencyType, JoinSemantics
from stac_attack_lab.primitives.core import CorePrimitiveFamily, EvidenceGrade, PrimitiveOutcome


class CandidateAcquisitionMode(StrEnum):
    ordinary_trace = "ordinary_trace"
    adversarial_trace = "adversarial_trace"
    generated = "generated"
    composed = "composed"


class FilterGate(StrEnum):
    schema_type = "G0"
    occurrence_evidence = "G1"
    causal_edge = "G2"
    environment_binding = "G3"
    replay_consistency = "G4"
    attack_relevance = "G5"
    split_privacy = "G6"
    portability_dedup = "G7"
    coverage_diversity = "G8"


class FilterDecision(StrictModel):
    gate: FilterGate
    passed: bool
    reason_codes: list[str]
    evidence_ref_ids: list[str]


class ChainNode(StrictModel):
    node_id: str
    macro_primitive_ref: str
    core_occurrence_ids: list[str]
    public_preconditions: list[str]
    public_postconditions: list[str]
    required_edge_inputs: list[str]
    binding_slots: list[str]
    allowed_outcomes: list[PrimitiveOutcome]
    evidence_requirement: list[EvidenceGrade]
    required_for_full_chain: bool = True


class ChainEdge(StrictModel):
    edge_id: str
    source_node_id: str
    target_node_id: str
    edge_type: DependencyType
    source_fact: str
    target_precondition: str
    artifact_binding: str | None = None
    state_binding: str | None = None
    guard: str | None = None
    join_semantics: JoinSemantics = JoinSemantics.all
    join_k: int | None = Field(default=None, ge=1)
    source_occurrence_outcome: PrimitiveOutcome = PrimitiveOutcome.passed
    evidence_ref_ids: list[str]
    required_for_full_chain: bool = True


class PrimitiveChainCandidate(StrictModel):
    schema_version: Literal["2.0"] = "2.0"
    candidate_id: str
    chain_id: str
    registry_hash: str
    interaction_graph_id: str
    occurrence_ids: list[str]
    core_nodes: list[PublicCoreNode] = Field(default_factory=list)
    core_edges: list[PublicCoreEdge] = Field(default_factory=list)
    duplicate_provenance_paths: list[list[str]] = Field(default_factory=list)
    nodes: list[ChainNode]
    edges: list[ChainEdge]
    entry_predicates: list[str]
    terminal_predicates: list[str]
    acquisition_mode: CandidateAcquisitionMode
    construction_manifest: ConstructionManifest | None = None
    source_trace_refs: list[str]
    source_task_id: str
    source_split: str
    terminal_relation: Literal[
        "observed",
        "hypothesized",
        "partial",
        "blocked",
        "rejected",
        "error",
        "timeout",
        "not_observable",
    ]
    forbidden_shortcut_detected: bool
    filter_decisions: list[FilterDecision] = Field(default_factory=list)
    candidate_hash: str

    @model_validator(mode="after")
    def validate_chain(self) -> PrimitiveChainCandidate:
        node_ids = [node.node_id for node in self.nodes]
        if len(node_ids) != len(set(node_ids)):
            raise ValueError("duplicate_chain_node_id")
        known = set(node_ids)
        for edge in self.edges:
            if edge.source_node_id not in known or edge.target_node_id not in known:
                raise ValueError("chain_edge_references_unknown_node")
        return self


class BindingSlot(StrictModel):
    slot_id: str
    value_type: str
    required_component_role: str
    required_capability: str | None = None
    allowed_public_sources: list[str]
    sensitive: Literal[False] = False


class PublicCoreNode(StrictModel):
    node_id: str
    position: NonNegativeInt
    family: CorePrimitiveFamily
    subtype: str
    public_input_state_types: list[str]
    public_output_state_types: list[str]
    multiplicity: PositiveInt = 1
    session_id: str
    session_boundary_before: bool = False
    optional: bool = False
    macro_annotations: list[str] = Field(default_factory=list)


class PublicCoreEdge(StrictModel):
    edge_id: str
    source_node_id: str
    target_node_id: str
    edge_type: DependencyType
    public_artifact_type: str | None = None
    public_state_type: str | None = None
    crosses_session_boundary: bool = False
    required_for_full_chain: bool = True
    join_semantics: JoinSemantics = JoinSemantics.all
    join_k: int | None = Field(default=None, ge=1)


class PlannerSampleView(StrictModel):
    sample_id: str
    sample_version: str
    public_summary: str
    core_nodes: list[PublicCoreNode] = Field(default_factory=list)
    core_edges: list[PublicCoreEdge] = Field(default_factory=list)
    macro_nodes: list[ChainNode]
    macro_edges: list[ChainEdge]
    applicability_predicates: list[str]
    required_capabilities: list[str]
    component_role_signature: list[str]
    binding_slots: list[BindingSlot]
    budget_profile: dict[str, PositiveInt]
    fallback_node_ids: list[str]
    evidence_strength: Literal["direct", "deterministic", "interventional", "mixed"]


class ExecutionBindingView(StrictModel):
    sample_id: str
    core_pattern_refs: dict[str, list[str]]
    allowed_benchmark_surfaces: list[str]
    parameter_schemas: dict[str, dict[str, str]]
    session_requirements: list[str]
    materialization_template_ids: list[str]
    legal_retry_node_ids: list[str]
    legal_reroute_node_ids: list[str]


class PrivateEvidenceView(StrictModel):
    sample_id: str
    source_trace_refs: list[str]
    occurrence_refs: list[str]
    artifact_lineage_refs: list[str]
    snapshot_refs: list[str]
    hard_verifier_refs: list[str]
    known_failure_modes: list[str]
    counterexample_refs: list[str]
    construction_outcome_counts: dict[str, NonNegativeInt]
    provenance_hashes: dict[str, str]


class SampleValidationSummary(StrictModel):
    validation_level: Literal[
        "structurally_valid",
        "causally_grounded",
        "environment_feasible",
        "portable_to_interface",
    ]
    gate_decisions: list[FilterDecision]
    validation_environment: str
    validation_seeds: list[int]
    replay_refs: list[str]


class PrimitiveChainSample(StrictModel):
    schema_version: Literal["2.0"] = "2.0"
    sample_id: str
    sample_version: str
    dataset_version: str
    chain_id: str
    chain_hash: str
    sample_hash: str
    registry_version: str
    registry_hash: str
    observation_schema_version: str
    construction_pipeline_version: str
    acquisition_mode: Literal["adversarial_trace"]
    planner_view: PlannerSampleView
    execution_view: ExecutionBindingView
    private_evidence_view: PrivateEvidenceView
    validation: SampleValidationSummary
    source_split: str
    source_task_ids: list[str]

    @model_validator(mode="after")
    def validate_view_identity(self) -> PrimitiveChainSample:
        ids = {
            self.sample_id,
            self.planner_view.sample_id,
            self.execution_view.sample_id,
            self.private_evidence_view.sample_id,
        }
        if len(ids) != 1:
            raise ValueError("sample_view_identity_mismatch")
        return self


class AcceptedSampleRecord(StrictModel):
    schema_version: Literal["2.1"] = "2.1"
    sample_id: str
    sample_version: str
    dataset_version: str
    chain_id: str
    chain_hash: str
    sample_hash: str
    registry_version: str
    registry_hash: str
    observation_schema_version: str
    construction_pipeline_version: str
    acquisition_mode: Literal["adversarial_trace"]
    validation_level: str
    validation_hash: str
    planner_view_hash: str
    execution_view_hash: str
    private_evidence_hash: str
    source_split: str
    source_task_ids: list[str]


class SampleLibraryManifest(StrictModel):
    schema_version: Literal["2.1"] = "2.1"
    manifest_type: Literal["primitive_chain_library"] = "primitive_chain_library"
    library_id: str
    library_version: str
    registry_version: str
    registry_hash: str
    observation_schema_version: str
    construction_pipeline_version: str
    source_split_summary: dict[str, NonNegativeInt]
    formal_exclusion_hash: str
    filter_policy_hash: str
    accepted_count: NonNegativeInt
    negative_count: NonNegativeInt
    candidate_count: NonNegativeInt
    attempted_count: NonNegativeInt
    partial_count: NonNegativeInt = 0
    blocked_count: NonNegativeInt = 0
    rejected_count: NonNegativeInt = 0
    error_count: NonNegativeInt = 0
    not_observable_count: NonNegativeInt = 0
    reason_code_distribution: dict[str, NonNegativeInt] = Field(default_factory=dict)
    attacker_stage_implemented: bool = False
    content_hashes: dict[str, str]
    tree_hash: str
    frozen: bool
    created_at: str

    @model_validator(mode="after")
    def validate_counts(self) -> SampleLibraryManifest:
        if self.accepted_count + self.negative_count > self.candidate_count:
            raise ValueError("library_pool_counts_exceed_candidates")
        # Candidate/sample cardinality is independent of collection-attempt
        # cardinality: one completed interaction graph may mine several chains.
        classified_attempts = (
            self.partial_count
            + self.blocked_count
            + self.rejected_count
            + self.error_count
            + self.not_observable_count
        )
        if classified_attempts > self.attempted_count:
            raise ValueError("library_attempt_outcome_counts_exceed_attempts")
        return self
