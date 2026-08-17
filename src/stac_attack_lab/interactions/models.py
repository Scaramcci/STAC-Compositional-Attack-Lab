from __future__ import annotations

from enum import StrEnum
from typing import Any, Literal

from pydantic import Field, NonNegativeInt, model_validator

from stac_attack_lab.contracts import StrictModel
from stac_attack_lab.primitives.core import (
    CorePrimitiveFamily,
    EvidenceGrade,
    PrimitiveOutcome,
)


class InteractionEventType(StrEnum):
    message = "message"
    tool_call = "tool_call"
    tool_result = "tool_result"
    state_read = "state_read"
    state_write = "state_write"
    lifecycle = "lifecycle"
    policy = "policy"
    evaluator = "evaluator"


class DependencyType(StrEnum):
    data = "data"
    state = "state"
    control = "control"
    authorization = "authorization"


class JoinSemantics(StrEnum):
    all = "ALL"
    any = "ANY"
    k_of_n = "K_OF_N"


class SourceReference(StrictModel):
    ref_id: str
    kind: str
    relative_path: str | None = None
    content_hash: str


class RawInteractionTrajectory(StrictModel):
    schema_version: Literal["2.0"] = "2.0"
    trajectory_id: str
    source_adapter_id: str
    source_adapter_version: str
    source_environment_family: str
    source_environment_version: str
    source_task_id: str
    source_split: Literal["train", "dev", "test", "synthetic"]
    episode_id: str
    session_ids: list[str]
    event_refs: list[SourceReference]
    checkpoint_refs: list[SourceReference]
    model_hashes: dict[str, str]
    config_hash: str
    collection_seed: int
    collection_status: Literal["complete", "partial", "blocked", "error"]
    failure_category: str | None = None
    provenance: dict[str, str]


class InteractionArtifact(StrictModel):
    artifact_id: str
    artifact_type: str
    content_hash: str
    producer_event_id: str | None
    parent_artifact_ids: list[str]
    taint_labels: list[str]
    trust_label: str
    source_ref_ids: list[str]


class InteractionEvent(StrictModel):
    schema_version: Literal["2.0"] = "2.0"
    event_id: str
    trajectory_id: str
    episode_id: str
    session_id: str
    sequence_no: NonNegativeInt
    logical_time: NonNegativeInt
    actor_role: str
    event_type: InteractionEventType
    component_role: str
    operation: str
    status: PrimitiveOutcome
    input_artifact_ids: list[str]
    output_artifact_ids: list[str]
    read_state_refs: list[str]
    write_state_refs: list[str]
    pre_state_ref: str | None = None
    post_state_ref: str | None = None
    request_event_id: str | None = None
    lifecycle_id: str | None = None
    public_payload: dict[str, Any] = Field(default_factory=dict)
    evidence_ref_ids: list[str] = Field(default_factory=list)
    source_event_ref: str


class InteractionEdge(StrictModel):
    edge_id: str
    edge_type: DependencyType
    source_event_id: str
    target_event_id: str
    source_fact: str
    target_precondition: str
    artifact_id: str | None = None
    state_ref: str | None = None
    guard: str | None = None
    join_semantics: JoinSemantics = JoinSemantics.all
    join_k: int | None = Field(default=None, ge=1)
    evidence_ref_ids: list[str]
    observable: bool = True

    @model_validator(mode="after")
    def validate_join(self) -> InteractionEdge:
        if (self.join_semantics == JoinSemantics.k_of_n) != (self.join_k is not None):
            raise ValueError("join_k_required_only_for_k_of_n")
        return self


class UnresolvedInteractionLink(StrictModel):
    link_id: str
    reason_code: str
    source_event_id: str | None = None
    target_event_id: str | None = None
    source_ref_ids: list[str]


class InteractionGraph(StrictModel):
    schema_version: Literal["2.0"] = "2.0"
    graph_id: str
    trajectory_id: str
    observable_projection_version: str
    source_trajectory_hash: str
    events: list[InteractionEvent]
    artifacts: list[InteractionArtifact]
    edges: list[InteractionEdge]
    unresolved_links: list[UnresolvedInteractionLink]
    normalization_audit_ref: str
    graph_hash: str

    @model_validator(mode="after")
    def validate_links(self) -> InteractionGraph:
        event_ids = [event.event_id for event in self.events]
        artifact_ids = [artifact.artifact_id for artifact in self.artifacts]
        if len(event_ids) != len(set(event_ids)):
            raise ValueError("duplicate_interaction_event_id")
        if len(artifact_ids) != len(set(artifact_ids)):
            raise ValueError("duplicate_interaction_artifact_id")
        known_events = set(event_ids)
        known_artifacts = set(artifact_ids)
        for event in self.events:
            if not set(event.input_artifact_ids + event.output_artifact_ids) <= known_artifacts:
                raise ValueError(f"event_references_unknown_artifact:{event.event_id}")
        for edge in self.edges:
            if edge.source_event_id not in known_events or edge.target_event_id not in known_events:
                raise ValueError(f"edge_references_unknown_event:{edge.edge_id}")
            if edge.artifact_id is not None and edge.artifact_id not in known_artifacts:
                raise ValueError(f"edge_references_unknown_artifact:{edge.edge_id}")
        return self


class PrimitiveOccurrence(StrictModel):
    schema_version: Literal["2.0"] = "2.0"
    occurrence_id: str
    graph_id: str
    primitive_ref: str
    family: CorePrimitiveFamily
    subtype: str
    outcome: PrimitiveOutcome
    source_component_roles: list[str]
    target_component_roles: list[str]
    input_artifact_ids: list[str]
    output_artifact_ids: list[str]
    pre_state_refs: list[str]
    post_state_refs: list[str]
    source_event_ids: list[str]
    evidence_grades: list[EvidenceGrade]
    evidence_ref_ids: list[str]
    confidence: float = Field(ge=0.0, le=1.0)
    hard_fact: bool
    reason_codes: list[str]
    semantic_labels: dict[str, str] = Field(default_factory=dict)

    @model_validator(mode="after")
    def validate_hard_pass(self) -> PrimitiveOccurrence:
        if (
            self.hard_fact
            and self.outcome == PrimitiveOutcome.passed
            and not set(self.evidence_grades)
            & {EvidenceGrade.direct, EvidenceGrade.deterministic_derived}
        ):
            raise ValueError("hard_pass_requires_e1_or_e2")
        return self
