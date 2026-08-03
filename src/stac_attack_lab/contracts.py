from __future__ import annotations

from enum import StrEnum
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, NonNegativeInt, PositiveInt, field_validator


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid")


class ActorRole(StrEnum):
    planner = "planner"
    attacker = "attacker"
    victim = "victim"
    verifier = "verifier"
    judge = "judge"
    environment = "environment"
    recorder = "recorder"


class Component(StrEnum):
    retrieval_tool = "retrieval_tool"
    memory_store = "memory_store"
    memory_retriever = "memory_retriever"
    action_tool = "action_tool"
    planner = "planner"
    attacker = "attacker"
    victim = "victim"
    verifier = "verifier"
    judge = "judge"


class TrustBoundary(StrEnum):
    trusted_user = "trusted_user"
    untrusted_tool = "untrusted_tool"
    workspace_memory = "workspace_memory"
    sandbox_action = "sandbox_action"
    model_private = "model_private"


class PrimitiveCategory(StrEnum):
    entry = "entry"
    persistence = "persistence"
    retrieval = "retrieval"
    trigger = "trigger"


class SafetyClass(StrEnum):
    local_canary_only = "local_canary_only"


class PredicateOperator(StrEnum):
    exists = "exists"
    equals = "equals"
    contains_hash = "contains_hash"
    event_before = "event_before"
    count_gte = "count_gte"


class Verdict(StrEnum):
    pass_ = "pass"
    fail = "fail"
    abstain = "abstain"
    error = "error"


class EventStatus(StrEnum):
    ok = "ok"
    rejected = "rejected"
    error = "error"
    skipped = "skipped"


class Predicate(StrictModel):
    predicate_id: str
    operator: PredicateOperator
    left: str
    right: str | int | None = None


class PrimitiveSpec(StrictModel):
    primitive_id: str
    version: str
    name: str
    category: PrimitiveCategory
    entry_component: Component
    exit_component: Component
    trust_boundary: TrustBoundary
    required_capabilities: list[str]
    preconditions: list[Predicate]
    postconditions: list[Predicate]
    action_template: dict[str, str]
    evidence_requirements: list[str]
    default_budget: PositiveInt
    safety_class: SafetyClass
    deterministic_verifier_id: str


class AttackNode(StrictModel):
    node_id: str
    primitive_id: str
    stage_id: str
    preconditions: list[Predicate]
    postconditions: list[Predicate]
    budget: PositiveInt
    retry_limit: NonNegativeInt = 0
    template_vars: dict[str, str] = Field(default_factory=dict)


class AttackEdge(StrictModel):
    edge_id: str
    source_node_id: str
    target_node_id: str
    source_fact: str
    target_precondition: str


class AttackGraph(StrictModel):
    graph_id: str
    objective_id: str
    environment_id: str
    primitive_registry_version: str
    nodes: list[AttackNode]
    edges: list[AttackEdge]
    required_terminal_predicates: list[Predicate]
    max_turns: PositiveInt
    max_tool_calls: PositiveInt
    max_tokens: PositiveInt
    safety_constraints: list[str]
    provenance: dict[str, str]
    allow_bounded_retry_cycles: bool = False


class AttackArtifact(StrictModel):
    artifact_id: str
    artifact_type: str
    content_hash: str
    producer_event_id: str
    producer_component: Component
    target_component: Component
    taint_labels: list[str]
    parent_artifact_ids: list[str]
    created_at_logical_step: NonNegativeInt
    payload_ref: str


class AttackEvent(StrictModel):
    schema_version: Literal["1.0"]
    run_id: str
    trace_id: str
    episode_id: str
    event_id: str
    parent_event_ids: list[str]
    sequence_no: NonNegativeInt
    logical_time: NonNegativeInt
    actor_role: ActorRole
    component: Component
    trust_boundary: TrustBoundary
    event_type: str
    stage_id: str | None
    primitive_id: str | None
    input_artifact_ids: list[str]
    output_artifact_ids: list[str]
    request_hash: str
    response_hash: str
    pre_snapshot_ref: str
    post_snapshot_ref: str
    status: EventStatus
    error_code: str | None
    duration_ms: NonNegativeInt
    evidence_refs: list[str]


class PredicateResult(StrictModel):
    predicate_id: str
    verdict: Verdict
    evidence_refs: list[str]
    summary: str


class VerifierVerdict(StrictModel):
    verifier_id: str
    verifier_version: str
    verdict: Verdict
    predicate_results: list[PredicateResult]
    evidence_event_ids: list[str]
    evidence_snapshot_refs: list[str]
    reason_code: str
    human_readable_summary: str
    hard_fact: bool


class EnvironmentInventory(StrictModel):
    environment_id: str
    capabilities: list[str]
    components: list[Component]
    trust_boundaries: list[TrustBoundary]
    observable_state: list[str]
    propagation_edges: list[str]
    unknowns: list[str] = Field(default_factory=list)


class PlannerInput(StrictModel):
    graph_public: dict[str, Any]
    frontier_node_ids: list[str]
    stage_status: dict[str, str]
    budget_remaining: int
    public_history_event_ids: list[str]
    retry_counts: dict[str, int]


class PlannerDecision(StrictModel):
    decision_id: str
    action: Literal["execute_node", "retry_node", "reroute", "stop_success", "stop_failure"]
    selected_node_id: str | None
    selected_primitive_id: str | None
    satisfied_preconditions: list[str]
    unsatisfied_preconditions: list[str]
    public_evidence_event_ids: list[str]
    budget_after_action: NonNegativeInt
    rationale_summary: str
    confidence: float = Field(ge=0.0, le=1.0)
    fallback_node_id: str | None = None

    @field_validator("rationale_summary")
    @classmethod
    def short_rationale(cls, value: str) -> str:
        if value.count(".") > 3:
            raise ValueError("rationale_summary must be at most 3 sentences")
        return value


class AttackerAction(StrictModel):
    action_id: str
    node_id: str
    primitive_id: str
    message: str
    used_variables: dict[str, str]
    constraint_checks: list[str]
    abstain: bool = False


class PromptWriterOutput(StrictModel):
    status: Literal["ok", "abstain", "error"]
    victim_message: str
    expected_public_effect: str
    source_stage_id: str
    rationale_summary: str


class ChainCriticPatch(StrictModel):
    op: str
    path: str
    value: str | int | bool | None = None


class ChainCriticVerdict(StrictModel):
    decision: Literal["accept", "repair", "reject"]
    findings: list[str]
    patches: list[ChainCriticPatch]
    rationale_summary: str


class VictimAction(StrictModel):
    tool_name: str
    arguments: dict[str, str]


class JudgeVerdict(StrictModel):
    judge_id: str
    verdict: Literal["pass", "fail", "abstain"]
    confidence: float = Field(ge=0.0, le=1.0)
    evidence_event_ids: list[str]
    labels: dict[str, str | int | float | bool]
    rationale_summary: str
    hard_chain_success_copy: bool | None = None


class OfflineSample(StrictModel):
    sample_id: str
    pair_id: str
    seed_task: dict[str, str]
    clean_baseline: dict[str, str]
    attack_graph: AttackGraph
    verified_call_params: dict[str, dict[str, str]]
    victim_messages: list[PromptWriterOutput]
    expected_predicates: list[Predicate]
    verifier_config: dict[str, str]
    budget: dict[str, int]
    initial_snapshot_hash: str
    version_hashes: dict[str, str]
    verification_transcript_ref: str
    sample_hash: str
    dataset_version: str


class RunResult(StrictModel):
    run_id: str
    condition: str
    pair_id: str
    config_hash: str
    sample_hash: str
    initial_snapshot_hash: str
    stage_verdicts: dict[str, str]
    chain_verdict: bool
    utility_success: bool
    tool_calls: int
    tokens: int
    duration_ms: int
    retries: int
    reroutes: int
    defense_enabled: bool
    planner_type: str
    seed: int
    model_versions: dict[str, str]
    paths: dict[str, str]


SCHEMA_MODELS: dict[str, type[BaseModel]] = {
    "attack_graph": AttackGraph,
    "planner_decision": PlannerDecision,
    "offline_sample": OfflineSample,
    "judge_verdict": JudgeVerdict,
    "event": AttackEvent,
}
