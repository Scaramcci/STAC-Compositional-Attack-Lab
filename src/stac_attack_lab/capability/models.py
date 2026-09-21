from __future__ import annotations

from enum import StrEnum
from typing import Any, Literal

from pydantic import Field, NonNegativeInt, PositiveInt, model_validator

from stac_attack_lab.contracts import StrictModel
from stac_attack_lab.hashing import stable_hash


class PrimitiveKind(StrEnum):
    INGEST = "Ingest"
    ADOPT = "Adopt"
    PERSIST = "Persist"
    RECALL = "Recall"
    SELECT = "Select"
    BIND = "Bind"
    ACT = "Act"
    RECORD = "Record"
    RECOVER = "Recover"


class ExecutionState(StrEnum):
    NOT_REACHED = "not_reached"
    ATTEMPTED = "attempted"
    OBSERVED = "observed"
    COMMITTED = "committed"
    BLOCKED = "blocked"
    ERROR = "error"
    UNKNOWN = "unknown"


class SemanticAlignment(StrEnum):
    ALIGNED = "aligned"
    DEVIATED = "deviated"
    AMBIGUOUS = "ambiguous"
    NOT_APPLICABLE = "not_applicable"


class EvidenceSupport(StrEnum):
    DIRECT = "direct"
    BEHAVIORAL_ANNOTATION = "behavioral_annotation"
    INTERVENTION_SUPPORTED = "intervention_supported"
    INSUFFICIENT = "insufficient"


class AttributionState(StrEnum):
    SUPPORTED = "supported"
    CONTRADICTED = "contradicted"
    UNRESOLVED = "unresolved"


class Verdict(StrEnum):
    TRUE = "true"
    FALSE = "false"
    UNKNOWN = "unknown"
    NOT_APPLICABLE = "not_applicable"


class ConstraintStatus(StrEnum):
    SATISFIED = "satisfied"
    VIOLATED = "violated"
    UNKNOWN = "unknown"
    NOT_APPLICABLE = "not_applicable"


class VariantKind(StrEnum):
    BENIGN = "benign"
    DIRECT = "direct"
    SEMANTIC = "semantic"


class PrimitiveSpec(StrictModel):
    primitive: PrimitiveKind
    version: Literal["1.0"] = "1.0"
    input_type: str
    output_type: str
    preconditions: list[str]
    minimum_observations: list[str]
    neutral_example: str
    counterexample: str


class CapabilityProfile(StrictModel):
    schema_version: Literal["capability-profile/1.0"] = "capability-profile/1.0"
    platform: Literal["openclaw"] = "openclaw"
    upstream_commit: str
    upstream_schema_hash: str
    evaluator_source_hash: str
    available_tools: list[str]
    session_capabilities: list[str]
    memory_capabilities: list[str]
    observation_channels: list[str]
    observation_gaps: list[str]


class BusinessOracleSpec(StrictModel):
    oracle_id: str
    target_project_id: str
    trusted_proof_field: str
    status_field: str
    harmful_status: str
    legal_status_without_proof: str
    version: Literal["1.0"] = "1.0"


class TaskContract(StrictModel):
    schema_version: Literal["capability-task/1.0"] = "capability-task/1.0"
    case_id: str
    family: Literal["F1"]
    track: Literal["safeclaw_derived_extension"]
    base_task_id: str
    split: Literal["synthetic", "dev", "validation", "test"]
    split_group_id: str
    legitimate_goal: str
    trusted_rules: list[str]
    trusted_ledger: dict[str, dict[str, Any]]
    allowed_operations: list[str]
    business_authorizations: list[str]
    normal_utility_predicates: list[str]
    oracle: BusinessOracleSpec


class AttackSurface(StrictModel):
    surface_id: str
    source_trust: Literal["low"] = "low"
    editable_json_pointers: list[str]
    immutable_json_pointers: list[str]
    exposure_time: Literal["episode_start"] = "episode_start"
    max_characters: PositiveInt
    prohibited_fields: list[str]

    @model_validator(mode="after")
    def validate_disjoint_fields(self) -> AttackSurface:
        if set(self.editable_json_pointers) & set(self.immutable_json_pointers):
            raise ValueError("attack_surface_editable_immutable_overlap")
        return self


class CompositionNode(StrictModel):
    node_id: str
    primitive: PrimitiveKind
    required: bool = True
    external_preconditions: list[str] = Field(default_factory=list)


class CompositionEdge(StrictModel):
    source_node_id: str
    target_node_id: str
    relation: Literal[
        "precedes",
        "content_available",
        "resource_read_from",
        "argument_binding",
        "decision_support",
        "triggered_recovery",
    ]


class CompositionSpec(StrictModel):
    composition_id: str
    family: Literal["F1"]
    nodes: list[CompositionNode]
    edges: list[CompositionEdge]
    max_recovery_transitions: NonNegativeInt = 1

    @model_validator(mode="after")
    def validate_graph(self) -> CompositionSpec:
        ids = [node.node_id for node in self.nodes]
        if len(ids) != len(set(ids)):
            raise ValueError("composition_node_id_duplicate")
        for edge in self.edges:
            if edge.source_node_id not in ids or edge.target_node_id not in ids:
                raise ValueError("composition_edge_node_missing")
        return self


class CapabilityCase(StrictModel):
    schema_version: Literal["capability-case/1.0"] = "capability-case/1.0"
    case_id: str
    variant: VariantKind
    task_contract: TaskContract
    attack_surface: AttackSurface
    composition: CompositionSpec
    low_trust_material: str
    contract_hash: str
    case_hash: str

    @model_validator(mode="after")
    def validate_hashes(self) -> CapabilityCase:
        contract_payload = self.task_contract.model_dump(mode="json")
        if self.contract_hash != stable_hash(contract_payload):
            raise ValueError("capability_contract_hash_mismatch")
        payload = self.model_dump(mode="json", exclude={"case_hash"})
        if self.case_hash != stable_hash(payload):
            raise ValueError("capability_case_hash_mismatch")
        return self


class VictimPublicView(StrictModel):
    schema_version: Literal["capability-public-view/1.0"] = "capability-public-view/1.0"
    task_id: str
    user_goal: str
    trusted_rules: list[str]
    trusted_ledger_path: str
    low_trust_material_path: str
    low_trust_material: str
    allowed_operations: list[str]
    public_view_hash: str

    @model_validator(mode="after")
    def validate_hash(self) -> VictimPublicView:
        if self.public_view_hash != stable_hash(
            self.model_dump(mode="json", exclude={"public_view_hash"})
        ):
            raise ValueError("capability_public_view_hash_mismatch")
        return self


class RuntimeTask(StrictModel):
    schema_version: Literal["capability-runtime-task/1.0"] = "capability-runtime-task/1.0"
    case: CapabilityCase
    public_view: VictimPublicView
    initial_state: dict[str, Any]
    private_oracle: BusinessOracleSpec
    upstream_schema_compatible: Literal[False] = False
    runtime_task_hash: str

    @model_validator(mode="after")
    def validate_hash(self) -> RuntimeTask:
        if self.private_oracle != self.case.task_contract.oracle:
            raise ValueError("capability_oracle_contract_mismatch")
        if self.runtime_task_hash != stable_hash(
            self.model_dump(mode="json", exclude={"runtime_task_hash"})
        ):
            raise ValueError("capability_runtime_task_hash_mismatch")
        return self


class RuntimeEvent(StrictModel):
    schema_version: Literal["capability-event/1.0"] = "capability-event/1.0"
    run_id: str
    episode_id: str
    event_id: str
    sequence_no: PositiveInt
    actor: Literal["harness", "user", "victim", "tool", "environment"]
    event_type: Literal[
        "session_started",
        "source_delivered",
        "semantic_use",
        "tool_selected",
        "tool_request",
        "tool_result",
        "state_write",
        "state_read",
        "record_write",
        "recovery",
        "response",
    ]
    session_label: str
    actual_session_key: str
    invocation_id: str | None = None
    attempt_id: str | None = None
    tool_name: str | None = None
    arguments: dict[str, Any] | None = None
    status: Literal["observed", "attempted", "committed", "blocked", "error", "unknown"]
    resource_id: str | None = None
    resource_version_before: str | None = None
    resource_version_after: str | None = None
    evidence: dict[str, Any] = Field(default_factory=dict)


class StateCheckpoint(StrictModel):
    checkpoint_id: str
    stage: Literal["initial", "final"]
    state: dict[str, Any] | None
    state_hash: str | None
    capture_status: Literal["observed", "error", "unknown"]
    reason_code: str

    @model_validator(mode="after")
    def validate_state(self) -> StateCheckpoint:
        if self.capture_status == "observed":
            if self.state is None or self.state_hash != stable_hash(self.state):
                raise ValueError("checkpoint_observed_state_invalid")
        elif self.state is not None:
            raise ValueError("checkpoint_unobserved_state_present")
        return self


class PrimitiveOccurrence(StrictModel):
    occurrence_id: str
    planned_node_id: str | None
    primitive: PrimitiveKind
    event_ids: list[str]
    execution: ExecutionState
    semantic_alignment: SemanticAlignment
    support: EvidenceSupport
    attribution: AttributionState
    reason_codes: list[str]

    @model_validator(mode="after")
    def validate_runtime_evidence(self) -> PrimitiveOccurrence:
        if (
            self.execution in {ExecutionState.OBSERVED, ExecutionState.COMMITTED}
            and not self.event_ids
        ):
            raise ValueError("primitive_occurrence_runtime_evidence_missing")
        return self


class PrimitiveAssessment(StrictModel):
    primitive: PrimitiveKind
    planned_node_ids: list[str]
    occurrences: list[PrimitiveOccurrence]
    overall_execution: ExecutionState
    reason_codes: list[str]


class HarmResult(StrictModel):
    verdict: Verdict
    attempted_harm: bool
    target_project_id: str
    evidence_event_ids: list[str]
    reason_code: str


class ConstraintCheck(StrictModel):
    constraint_id: str
    applicable: bool
    status: ConstraintStatus
    check_version: str
    coverage: list[str]
    evidence_event_ids: list[str]
    reason_code: str


class EpisodeResult(StrictModel):
    schema_version: Literal["capability-episode-result/1.0"] = "capability-episode-result/1.0"
    episode_id: str
    case_id: str
    variant: VariantKind
    execution_status: Literal["completed", "partial", "blocked", "error"]
    official_verdict: Verdict
    harm: HarmResult
    benign_utility: Verdict
    goal_fidelity: Verdict
    constraints: list[ConstraintCheck]
    pp_success: bool
    primitive_analysis: list[PrimitiveAssessment]
    residual_compromise: Verdict
    missing_information: list[str]
    event_count: NonNegativeInt
    report_hash: str

    @model_validator(mode="after")
    def validate_pp_and_hash(self) -> EpisodeResult:
        applicable = [item for item in self.constraints if item.applicable]
        expected_pp = (
            self.harm.verdict == Verdict.TRUE
            and bool(applicable)
            and all(item.status == ConstraintStatus.SATISFIED for item in applicable)
        )
        if self.pp_success != expected_pp:
            raise ValueError("capability_pp_success_inconsistent")
        if self.report_hash != stable_hash(self.model_dump(mode="json", exclude={"report_hash"})):
            raise ValueError("capability_episode_report_hash_mismatch")
        return self


class CompilationManifest(StrictModel):
    schema_version: Literal["capability-compilation/1.0"] = "capability-compilation/1.0"
    compilation_id: str
    created_at: str
    upstream_commit: str
    profile_hash: str
    registry_hash: str
    source_config_hash: str
    case_refs: list[str]
    case_hashes: dict[str, str]
    runtime_task_hashes: dict[str, str]
    network_requests_performed: Literal[False] = False
    manifest_hash: str

    @model_validator(mode="after")
    def validate_hash(self) -> CompilationManifest:
        if self.manifest_hash != stable_hash(
            self.model_dump(mode="json", exclude={"manifest_hash"})
        ):
            raise ValueError("capability_compilation_manifest_hash_mismatch")
        return self


class CompatibilityConfig(StrictModel):
    schema_version: Literal["capability-experiment/1.0"] = "capability-experiment/1.0"
    execution_enabled: Literal[False]
    study_stage: Literal["M1-real-provider-compatibility"]
    task_config: str
    case_id: str
    variant: Literal["benign"]
    platform: Literal["openclaw"]
    upstream_commit: str
    model_id: str
    provider_base_url_env: str
    provider_api_key_env: str
    attacker_mode: Literal["fixed_reviewed_fixture"]
    max_attacker_http_attempts: Literal[0]
    max_victim_http_attempts: PositiveInt
    max_embedding_http_attempts: Literal[0]
    max_annotation_http_attempts: Literal[0]
    automatic_retries: Literal[0]
    max_output_tokens_per_request: PositiveInt
    episode_wallclock_seconds: PositiveInt
    max_batch_http_attempts: PositiveInt
    max_batch_cost_usd: float
    run_id: str
    output_root: str
    authorization_reference: None
    notes: str

    @model_validator(mode="after")
    def validate_budget(self) -> CompatibilityConfig:
        if self.max_batch_http_attempts != self.max_victim_http_attempts:
            raise ValueError("capability_compatibility_batch_budget_mismatch")
        if self.max_batch_cost_usd <= 0:
            raise ValueError("capability_compatibility_cost_must_be_positive")
        if self.run_id not in self.output_root:
            raise ValueError("capability_compatibility_output_not_unique_to_run")
        if not self.model_id.strip() or self.model_id.startswith("REQUIRED_"):
            raise ValueError("capability_compatibility_model_missing")
        return self
