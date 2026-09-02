from __future__ import annotations

from enum import StrEnum
from typing import Literal

from pydantic import Field, NonNegativeInt

from stac_attack_lab.contracts import StrictModel
from stac_attack_lab.primitives.core import EvidenceGrade, PrimitiveOutcome


class CausalVerdict(StrEnum):
    causal_pass = "causal_pass"
    fail = "fail"
    not_reached = "not_reached"
    not_observable = "not_observable"
    error = "error"


class OccurrenceVerdict(StrictModel):
    occurrence_id: str
    primitive_ref: str
    outcome: PrimitiveOutcome
    hard_fact: bool
    evidence_grades: list[EvidenceGrade]
    evidence_ref_ids: list[str]
    reason_codes: list[str]


class EdgeVerdict(StrictModel):
    edge_id: str
    verdict: CausalVerdict
    source_occurrence_id: str
    target_occurrence_id: str
    evidence_ref_ids: list[str]
    reason_codes: list[str]


class MacroVerdict(StrictModel):
    node_id: str
    macro_ref: str
    outcome: PrimitiveOutcome
    required_occurrence_ids: list[str]
    required_edge_ids: list[str]
    evidence_ref_ids: list[str]
    reason_codes: list[str]


class DependencyAblationEvaluation(StrictModel):
    intervention_id: str
    target_edge_id: str
    observed_mechanism_edge_id: str | None
    observed_verdict: CausalVerdict | None
    target_dependency_absent: bool | None
    reason_codes: list[str]


class OfficialSafeClawVerdict(StrictModel):
    evaluator_version: str
    execution_complete: bool
    attack_succeeded: bool | None
    security_score: float | None = Field(default=None, ge=0.0)
    utility_success: bool | None
    safe_check_results: dict[str, bool | None]
    success_check_results: dict[str, bool | None]
    taint_channels: list[str]
    evidence_ref_ids: list[str]
    instrumentation_gaps: list[str]


class FormalExecutionAccounting(StrictModel):
    planner_model_calls: NonNegativeInt
    attacker_model_calls: NonNegativeInt
    attacker_decision_calls: NonNegativeInt
    victim_gateway_requests: NonNegativeInt
    victim_provider_completions_when_observable: NonNegativeInt | None
    embedding_calls_when_observable: NonNegativeInt | None
    whole_episode_attempts: NonNegativeInt
    input_tokens: NonNegativeInt | None
    output_tokens: NonNegativeInt | None
    cached_tokens: NonNegativeInt | None
    provider_cost_when_returned: float | None = Field(default=None, ge=0.0)
    wall_time_ms: NonNegativeInt
    instrumentation_gap_reasons: list[str] = Field(default_factory=list)

    @property
    def total_known_api_requests(self) -> int:
        return self.planner_model_calls + self.attacker_model_calls + self.victim_gateway_requests


class FormalRunResult(StrictModel):
    schema_version: Literal["2.0"] = "2.0"
    result_id: str
    run_id: str
    case_id: str
    pair_id: str
    condition: str
    seed: int
    planner_type: str
    library_version: str
    sample_id: str | None
    plan_id: str
    binding_id: str | None
    task_id: str
    binding_valid: bool
    binding_reason_codes: list[str]
    occurrence_verdicts: list[OccurrenceVerdict]
    edge_verdicts: list[EdgeVerdict]
    macro_verdicts: list[MacroVerdict]
    all_required_occurrences_passed: bool
    all_required_edges_passed: bool
    all_required_macros_passed: bool
    official_verdict: OfficialSafeClawVerdict
    forbidden_shortcut: bool
    full_chain_success: bool
    terminal_only_or_shortcut: bool
    mechanism_completed_terminal_failed: bool
    execution_error: bool
    execution_error_category: str | None
    not_observable_count: NonNegativeInt
    tool_calls: NonNegativeInt
    tokens: NonNegativeInt | None
    api_calls: NonNegativeInt
    duration_ms: NonNegativeInt
    cost: float | None = Field(default=None, ge=0.0)
    artifact_paths: dict[str, str]
    provenance_hashes: dict[str, str]
    accounting: FormalExecutionAccounting | None = None
    action_lineage_complete: bool = True
    action_lineage_reason_codes: list[str] = Field(default_factory=list)
    linked_action_ids: list[str] = Field(default_factory=list)
    dependency_ablation_evaluation: DependencyAblationEvaluation | None = None
