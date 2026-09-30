"""R0/R1 contracts. These do not reinterpret legacy chain or flow records."""

from __future__ import annotations

from typing import Any, Literal

from pydantic import Field, PositiveInt, model_validator

from stac_attack_lab.contracts import StrictModel

Primitive = Literal[
    "Ingest", "Adopt", "Persist", "Recall", "Select", "Bind", "Act", "Record", "Recover"
]
PRIMITIVES = ("Ingest", "Adopt", "Persist", "Recall", "Select", "Bind", "Act", "Record", "Recover")
Arm = Literal["no_library", "raw_examples", "primitive_examples"]


class RuntimeEvent(StrictModel):
    """Observed runtime event for the current attack program."""

    schema_version: Literal["attack-runtime-event/1"] = "attack-runtime-event/1"
    run_id: str
    episode_id: str
    event_id: str
    sequence_no: PositiveInt
    actor: Literal["harness", "user", "victim", "tool", "environment"]
    event_type: Literal[
        "session_started",
        "source_delivered",
        "source_prepared",
        "source_read_requested",
        "source_summary_visible",
        "source_result_delivered",
        "provider_context_reachable",
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
    actual_session_key: str | None
    invocation_id: str | None = None
    attempt_id: str | None = None
    tool_name: str | None = None
    arguments: dict[str, Any] | None = None
    status: Literal["observed", "attempted", "committed", "blocked", "error", "unknown"]
    resource_id: str | None = None
    resource_version_before: str | None = None
    resource_version_after: str | None = None
    evidence: dict[str, Any] = Field(default_factory=dict)


class AttackSurface(StrictModel):
    pointer: str
    mirror_pointer: str | None = None
    value_type: Literal["string"] = "string"
    max_chars: int = 8192
    stage: Literal["before_initialization"] = "before_initialization"
    owner: Literal["external_sender"] = "external_sender"
    trust: Literal["low"] = "low"
    resource_path: str
    immutable_root_hash: str


class TaskEntry(StrictModel):
    task_id: str
    task_group_id: str
    template_group_id: str
    task_path: str
    task_hash: str
    upstream_commit: str
    track: Literal["official_conformance", "official_task_payload_variant", "synthetic_extension"]
    support: Literal["offline_validated", "pending_runtime", "unsupported"]
    reason_codes: list[str] = Field(default_factory=list)
    known_exposure: bool = False
    exposure_status: Literal["known_exposed", "unknown"] = "unknown"
    exposure_evidence: str | None = None
    capability_evidence: list[str] = Field(default_factory=list)
    public_view: dict[str, Any]
    attack_surfaces: list[AttackSurface]
    evaluator_ref: str
    evaluator_hash: str


class Catalog(StrictModel):
    schema_version: Literal["attack-program-catalog/1"] = "attack-program-catalog/1"
    upstream_commit: str
    schema_hash: str
    patch_hash: str
    entries: list[TaskEntry]
    catalog_hash: str


class Split(StrictModel):
    schema_version: Literal["attack-program-split/1"] = "attack-program-split/1"
    catalog_hash: str
    rule: Literal["template-group-explicit-v1"] = "template-group-explicit-v1"
    group_assignments: dict[str, Literal["development", "validation", "test"]]
    known_exposure: list[str]
    exposure_registry_hash: str
    split_hash: str


class Patch(StrictModel):
    pointer: str
    value: str


class AttackCandidate(StrictModel):
    schema_version: Literal["attack-candidate/1"] = "attack-candidate/1"
    candidate_id: str
    task_id: str
    task_group_id: str
    source_split: Literal["development", "validation", "test"]
    patches: list[Patch]
    planned_primitives: list[Primitive] = Field(default_factory=list)


class R4GenerationPlan(StrictModel):
    """Versioned, bounded Attacker generation configuration."""

    schema_version: Literal["attack-r4-generation-plan/1"] = "attack-r4-generation-plan/1"
    plan_id: str
    task_id: str
    task_group_id: str
    source_split: Literal["development"] = "development"
    slot_count: Literal[3] = 3
    max_attacker_http_attempts: Literal[3] = 3
    max_output_tokens: int = Field(default=2048, ge=1, le=2048)
    request_timeout_seconds: int = Field(default=90, ge=1, le=90)
    wall_clock_seconds: int = Field(default=600, ge=1, le=600)
    concurrency: Literal[1] = 1
    http_502_retries: Literal[0] = 0
    generation_seed: int = 17
    execution_enabled: Literal[False] = False
    attacker_model_id: str | None = None
    attacker_endpoint_identity: str | None = None
    attacker_endpoint_env: str = "STAC_R4_ATTACKER_URL"
    attacker_api_key_env: str = "STAC_R4_ATTACKER_KEY"
    prompt_file: str
    candidate_schema: Literal["attack-candidate/1"] = "attack-candidate/1"
    public_goal: str = Field(min_length=1, max_length=1000)


class R4GenerationSlot(StrictModel):
    """Durable per-slot outcome; every assigned slot remains in the denominator."""

    schema_version: Literal["attack-r4-generation-slot/1"] = "attack-r4-generation-slot/1"
    slot_id: str
    status: Literal["assigned", "valid", "invalid", "duplicate", "error", "not_started"]
    request_attempted: bool
    request_sequence: int | None = None
    model_candidate_id: str | None = None
    candidate_hash: str | None = None
    materialized_task_hash: str | None = None
    reason_code: str | None = None
    response_hash: str | None = None
    response_bytes: int | None = None
    usage: dict[str, Any] | None = None
    usage_observation: Literal["returned", "unknown"] = "unknown"


class R4GenerationSummary(StrictModel):
    schema_version: Literal["attack-r4-generation-summary/1"] = "attack-r4-generation-summary/1"
    plan_id: str
    task_id: str
    source_split: Literal["development"]
    assigned_slots: int
    attacker_http_attempts: int
    valid_candidates: int
    invalid_candidates: int
    duplicate_candidates: int
    not_started: int
    slots: list[R4GenerationSlot]
    candidate_files: list[str]
    status: Literal["prepared_disabled", "completed", "interrupted", "rejected"]
    plan_hash: str
    prompt_hash: str
    public_request_hash: str


class PrimitiveOccurrence(StrictModel):
    occurrence_id: str
    primitive: Primitive
    evidence_refs: list[str] = Field(default_factory=list)
    status: Literal["observed", "unknown"] = "unknown"


class PrimitiveRelation(StrictModel):
    source_id: str
    target_id: str
    kind: Literal[
        "precedes",
        "delivered_to",
        "read_from",
        "argument_binding",
        "triggered_recovery",
        "annotated_decision_support",
    ]
    evidence_refs: list[str] = Field(default_factory=list)


class RawExampleView(StrictModel):
    view: Literal["raw_examples"] = "raw_examples"
    sample_id: str
    source_task_group_id: str
    source_split: Literal["development"] = "development"
    validation_class: str
    raw_example: str


class StructuredExampleView(StrictModel):
    view: Literal["primitive_examples"] = "primitive_examples"
    sample_id: str
    source_task_group_id: str
    source_split: Literal["development"] = "development"
    validation_class: str
    raw_example: str
    occurrences: list[PrimitiveOccurrence]
    relations: list[PrimitiveRelation]
    primitive_status: dict[Primitive, Literal["observed", "unknown"]]
    preconditions: list[str]
    evidence_boundary: str

    @model_validator(mode="after")
    def check_primitive_status(self) -> StructuredExampleView:
        if set(self.primitive_status) != set(PRIMITIVES):
            raise ValueError("primitive_status_incomplete")
        return self


class RawSession(StrictModel):
    session_id: str
    actual_session_key: str | None = None
    agent_response: str
    tool_calls: list[dict[str, Any]] = Field(default_factory=list)


class RawObservation(StrictModel):
    schema_version: Literal["attack-observation/1", "attack-observation/2"] = "attack-observation/1"
    source: Literal["synthetic_runtime_fixture", "local_fake", "real"]
    run_id: str
    task_id: str
    candidate_id: str
    materialized_task_hash: str | None = None
    sessions: list[RawSession] = Field(max_length=16)
    pre_state: dict[str, Any] | None
    post_state: dict[str, Any] | None
    events: list[RuntimeEvent] = Field(max_length=500)
    event_log_complete: bool = False
    state_capture_complete: bool = False

    @model_validator(mode="after")
    def check_materialized_binding(self) -> RawObservation:
        if self.schema_version == "attack-observation/2" and not self.materialized_task_hash:
            raise ValueError("materialized_task_hash_required")
        return self


class DevelopmentInput(StrictModel):
    schema_version: Literal["attack-development-input/1"] = "attack-development-input/1"
    task_id: str
    max_candidates: int
    max_attempts: int
    source: Literal["synthetic_runtime_fixture", "local_fake", "real"]
    candidates: list[AttackCandidate]
    observations: dict[str, RawObservation]


class LibraryManifest(StrictModel):
    schema_version: Literal["primitive-attack-library/1"] = "primitive-attack-library/1"
    scope: Literal["synthetic_only"] = "synthetic_only"
    library_id: str
    source_run: str
    source_manifest_hash: str
    catalog_hash: str
    split_hash: str
    attempt_denominator: int
    attempt_ids: list[str]
    sample_ids: list[str]
    policy: Literal["synthetic-only/1"] = "synthetic-only/1"
    rule_version: str
    file_hashes: dict[str, str]
    manifest_hash: str


class R3Config(StrictModel):
    schema_version: Literal["attack-evaluation-config/1"] = "attack-evaluation-config/1"
    scope: Literal["engineering_only", "formal"] = "engineering_only"
    task_id: str
    repeats: int = Field(ge=1, le=10)
    top_k: int = Field(ge=2, le=10)
    planner_model_id: str
    planner_max_output_tokens: int = Field(default=1200, ge=1, le=8192)
    planner_request_budget: int = Field(ge=1, le=100)
    victim_request_budget: int = Field(ge=0, le=100)
    seed: int = 17


class R3Case(StrictModel):
    schema_version: Literal["attack-evaluation-case/1"] = "attack-evaluation-case/1"
    case_id: str
    task_id: str
    task_group_id: str
    repeat: int
    arm: Arm
    public_task_hash: str
    planner_model_id: str
    planner_max_output_tokens: int
    planner_request_budget: int
    victim_request_budget: int
    seed: int
    retrieved_sample_ids: list[str]


class R3Manifest(StrictModel):
    schema_version: Literal["attack-evaluation-manifest/1"] = "attack-evaluation-manifest/1"
    scope: Literal["engineering_only"] = "engineering_only"
    library_manifest_hash: str
    library_id: str
    catalog_hash: str
    split_hash: str
    config_hash: str
    prompt_hash: str
    retrieval_policy: Literal["public-compatible-id-order/1"] = "public-compatible-id-order/1"
    included_validation_classes: list[str]
    case_ids: list[str]
    cases: list[R3Case]
    files: dict[str, str]
    processing_sources: dict[str, str]
    manifest_hash: str


class R3PlannerInput(StrictModel):
    schema_version: Literal["attack-planner-input/1"] = "attack-planner-input/1"
    case: R3Case
    public_task: dict[str, Any]
    public_goal: str
    allowed_surfaces: list[dict[str, Any]]
    compatible_samples: list[RawExampleView | StructuredExampleView]
    max_patches: Literal[1] = 1
    max_selected_samples: Literal[2] = 2


class R3Plan(StrictModel):
    schema_version: Literal["attack-plan/1"] = "attack-plan/1"
    selected_sample_ids: list[str]
    patches: list[Patch]
    abstain: bool
    decision_summary: str = Field(max_length=500)


class R3Result(StrictModel):
    schema_version: Literal["attack-evaluation-result/1"] = "attack-evaluation-result/1"
    case_id: str
    status: Literal[
        "assigned",
        "not_started",
        "abstained",
        "invalid_plan",
        "infra_error",
        "incomplete",
        "completed",
    ]
    reason_codes: list[str]
    selected_sample_ids: list[str]
    planner_decisions: int
    planner_source: Literal["scripted", "local_fake", "real"] | None
    planner_http_attempts: int
    victim_http_attempts: int
    planner_usage: dict[str, Any] | None
    planner_usage_observation: Literal["returned", "unknown"]
    planner_prompt_tokens: int | None
    planner_output_tokens: int | None
    prompt_chars: int
    sample_view_chars: int
    materialized_hash: str | None
    execution_source: Literal["synthetic_runtime_fixture", "local_fake", "real"] | None
    official: dict[str, Any] | None
    independent: dict[str, Any] | None
    occurrences: list[PrimitiveOccurrence]
    relations: list[PrimitiveRelation]
