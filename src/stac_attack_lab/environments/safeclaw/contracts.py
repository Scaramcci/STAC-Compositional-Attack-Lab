from __future__ import annotations

from enum import StrEnum
from typing import Any, Literal

from pydantic import Field, NonNegativeInt, PositiveInt, model_validator

from stac_attack_lab.contracts import StrictModel
from stac_attack_lab.environments.safeclaw.model_config import SafeClawEmbeddingRuntime
from stac_attack_lab.hashing import stable_hash


class SafeClawTrack(StrEnum):
    conformance = "safeclaw_conformance"
    compositional = "safeclaw_compositional"


class SafeClawExecutionStatus(StrEnum):
    completed = "completed"
    rejected = "rejected"
    blocked = "blocked"
    timeout = "timeout"
    environment_error = "environment_error"
    api_error = "api_error"
    invalid_binding = "invalid_binding"


class SafeClawBindingSlot(StrictModel):
    slot_id: str
    json_pointer: str
    value_type: Literal["string", "integer", "boolean", "string_list", "object"]
    public: bool
    allowed_sources: list[str]
    description: str


class PublicBenchmarkSessionPrompt(StrictModel):
    session_id: str
    sequence_no: PositiveInt
    user_instruction: str
    instruction_context: str | None = None


class BenchmarkPublicPrompt(StrictModel):
    schema_version: Literal["1.0"] = "1.0"
    task_id: str
    title: str
    description: str
    sessions: list[PublicBenchmarkSessionPrompt]
    prompt_hash: str

    @model_validator(mode="after")
    def validate_prompt_hash(self) -> BenchmarkPublicPrompt:
        payload = self.model_dump(mode="json", exclude={"prompt_hash"})
        if self.prompt_hash != stable_hash(payload):
            raise ValueError("benchmark_public_prompt_hash_mismatch")
        return self


class SafeClawPublicTaskView(StrictModel):
    schema_version: Literal["2.0"] = "2.0"
    task_id: str
    track: SafeClawTrack
    dimension: str
    category: str
    platform: Literal["openclaw"] = "openclaw"
    public_goal: str
    public_capabilities: list[str]
    component_roles: dict[str, list[str]]
    session_count: PositiveInt
    lifecycle_boundaries: list[str]
    bindable_slots: list[SafeClawBindingSlot]
    allowed_actions: list[str]
    materialization_template_id: str | None = None
    task_source_hash: str


class SafeClawTaskDescriptor(StrictModel):
    schema_version: Literal["2.0"] = "2.0"
    task_id: str
    track: SafeClawTrack
    dimension: str
    category: str
    title: str
    platform: Literal["openclaw"] = "openclaw"
    source_relative_path: str
    source_hash: str
    upstream_commit: str
    public_view: SafeClawPublicTaskView
    benchmark_public_prompt: BenchmarkPublicPrompt
    private_oracle_ref: str
    official_success_condition_hash: str
    official_safe_condition_hash: str
    materialization_template_id: str | None = None
    supported: bool
    unsupported_reason: str | None = None

    @model_validator(mode="after")
    def validate_support_status(self) -> SafeClawTaskDescriptor:
        if self.supported == (self.unsupported_reason is not None):
            raise ValueError("safeclaw_support_reason_mismatch")
        if self.public_view.task_id != self.task_id:
            raise ValueError("safeclaw_public_descriptor_task_mismatch")
        if self.benchmark_public_prompt.task_id != self.task_id:
            raise ValueError("safeclaw_public_prompt_task_mismatch")
        return self


class BindingAssignment(StrictModel):
    sample_slot_id: str
    benchmark_slot_id: str
    public_value_ref: str
    component_role: str
    capability: str


class BenchmarkBinding(StrictModel):
    schema_version: Literal["2.0"] = "2.0"
    binding_id: str
    sample_id: str
    chain_id: str
    task_id: str
    materialization_template_id: str | None = None
    task_source_hash: str
    assignments: list[BindingAssignment]
    node_component_mapping: dict[str, str]
    node_session_mapping: dict[str, str]
    edge_artifact_mapping: dict[str, str]
    allowed_actions: list[str]
    binding_valid: bool
    validation_reason_codes: list[str]
    binding_hash: str


class BaselineBinding(StrictModel):
    schema_version: Literal["2.0"] = "2.0"
    binding_id: str
    materialization_source: Literal["legal_baseline"] = "legal_baseline"
    task_id: str
    materialization_template_id: str
    task_source_hash: str
    assignments: list[BindingAssignment]
    allowed_actions: list[str]
    binding_valid: bool
    validation_reason_codes: list[str]
    binding_hash: str


class MaterializedTaskReference(StrictModel):
    task_id: str
    template_id: str
    binding_id: str
    materialized_task_hash: str
    sanitized_projection_ref: str
    binding_manifest_ref: str
    temporary_path_retained: Literal[False] = False


class SanitizedSessionResult(StrictModel):
    session_id: str
    sequence_no: NonNegativeInt
    status: str
    transcript_ref: str
    public_stage_status: dict[str, str]


class SafeClawEpisodeResult(StrictModel):
    schema_version: Literal["2.0"] = "2.0"
    episode_id: str
    case_id: str
    task_id: str
    binding_id: str | None
    status: SafeClawExecutionStatus
    error_category: str | None = None
    upstream_commit: str
    runner_version: str
    target_model_id: str
    started_at: str
    ended_at: str
    duration_ms: NonNegativeInt
    attempt_count: PositiveInt
    sessions: list[SanitizedSessionResult]
    sanitized_result_ref: str | None
    sanitized_result_hash: str | None
    canonical_trajectory_ref: str | None
    official_checks_ref: str | None
    state_evidence_refs: list[str]
    taint_evidence_refs: list[str]
    secret_scan_passed: bool
    provenance: dict[str, str]


class EpisodeRequest(StrictModel):
    case_id: str
    task_ref: MaterializedTaskReference
    target_model_id: str
    target_base_url: str
    target_api_key_env: str
    embedding: SafeClawEmbeddingRuntime | None = None
    timeout_seconds: PositiveInt
    max_attempts: PositiveInt
    output_root: str
    seed: int
    condition: str
    runtime_options: dict[str, Any] = Field(default_factory=dict)
