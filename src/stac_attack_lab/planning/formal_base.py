from __future__ import annotations

from typing import Literal, Protocol

from pydantic import Field, PositiveInt, model_validator

from stac_attack_lab.contracts import StrictModel
from stac_attack_lab.datasets.primitive_chain import PlannerSampleView
from stac_attack_lab.environments.safeclaw.contracts import (
    BenchmarkBinding,
    SafeClawPublicTaskView,
)


class FormalBudget(StrictModel):
    max_sessions: PositiveInt
    max_turns: PositiveInt
    max_tool_calls: PositiveInt
    max_tokens: PositiveInt
    max_wall_time_seconds: PositiveInt


class PublicSampleIndexEntry(StrictModel):
    sample_id: str
    sample_hash: str
    planner_view: PlannerSampleView


class FormalPlannerInput(StrictModel):
    schema_version: Literal["2.0"] = "2.0"
    planner_input_id: str
    library_id: str
    library_version: str
    library_hash: str
    public_samples: list[PublicSampleIndexEntry]
    public_task: SafeClawPublicTaskView
    budget: FormalBudget
    condition: str
    seed: int
    prior_public_session_status: dict[str, str] = Field(default_factory=dict)


class PlannerSelectionEvidence(StrictModel):
    compatible_sample_ids: list[str]
    rejected_sample_reason_codes: dict[str, list[str]]
    rank_scores: dict[str, float]
    decision_source: Literal["deterministic", "random_compatible", "llm_tiebreak", "abstain"]
    public_prompt_hash: str | None = None


class FormalEvaluationPlan(StrictModel):
    schema_version: Literal["2.0"] = "2.0"
    plan_id: str
    planner_input_id: str
    planner_type: str
    selected_sample_id: str | None
    selected_chain_id: str | None
    task_template_id: str
    binding: BenchmarkBinding | None
    materialization_variant: str
    condition: str
    budget: FormalBudget
    expected_public_stage_effects: dict[str, str]
    ablation_labels: list[str]
    selection_evidence: PlannerSelectionEvidence
    plan_hash: str
    abstain_reason: str | None = None

    @model_validator(mode="after")
    def validate_plan_or_abstention(self) -> FormalEvaluationPlan:
        abstained = self.selected_sample_id is None
        if abstained != (self.binding is None) or abstained != (self.abstain_reason is not None):
            raise ValueError("formal_plan_abstention_fields_mismatch")
        return self


class FormalPlanner(Protocol):
    def plan(self, planner_input: FormalPlannerInput) -> FormalEvaluationPlan: ...
