from __future__ import annotations

from enum import StrEnum
from typing import Literal, Protocol

from pydantic import Field, PositiveInt, model_validator

from stac_attack_lab.contracts import StrictModel
from stac_attack_lab.datasets.primitive_chain import PlannerSampleView
from stac_attack_lab.environments.safeclaw.contracts import (
    BaselineBinding,
    BenchmarkBinding,
    SafeClawPublicTaskView,
)
from stac_attack_lab.primitives.core import CorePrimitiveFamily

AdversarialRole = Literal[
    "entry", "propagation", "persistence", "dormant", "activation", "effect", "control"
]
ControlIntervention = Literal[
    "remove_poisoning",
    "remove_trigger",
    "break_primitive_dependency",
    "replace_with_benign_state",
    "truncate_before_activation",
]


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


class LongHorizonAttackFamily(StrEnum):
    objective_drifting = "objective_drifting"
    intent_hijacking = "intent_hijacking"
    persistent_state_poisoning = "persistent_state_poisoning"
    trigger_based = "trigger_based"
    compound_hybrid = "compound_hybrid"


class PrimitiveTrajectoryStage(StrictModel):
    stage_id: str
    macro_ref: str
    primary_family: CorePrimitiveFamily
    input_state_refs: list[str]
    output_state_ref: str
    carried_state_refs: list[str]
    adversarial_role: AdversarialRole
    activation_condition: str | None = None
    trust_boundary_crossing: bool = False


class ObjectiveTrajectoryPoint(StrictModel):
    stage_id: str
    objective: str
    transition_basis: str


class PersistencePlan(StrictModel):
    enabled: bool
    stored_state_ref: str | None
    storage_stage_id: str | None
    retrieval_stage_id: str | None
    dormant_between_stages: bool


class TriggerPlan(StrictModel):
    enabled: bool
    condition: str | None
    activation_stage_id: str | None


class PlannerControlCase(StrictModel):
    control_id: str
    intervention: ControlIntervention
    expected_observation: str


class LongHorizonAdversarialTrajectory(StrictModel):
    attack_family: LongHorizonAttackFamily
    benign_objective: str
    target_security_property: str
    primitive_sequence: list[PrimitiveTrajectoryStage]
    attack_entry_stage_id: str
    intermediate_state_refs: list[str]
    persistence: PersistencePlan
    objective_trajectory: list[ObjectiveTrajectoryPoint]
    trigger: TriggerPlan
    expected_final_effect: str
    observable_evidence: list[str]
    judge_condition: str
    sandbox_constraints: list[str]
    rationale: str
    control_cases: list[PlannerControlCase]

    @model_validator(mode="after")
    def validate_causal_backbone(self) -> LongHorizonAdversarialTrajectory:
        if len(self.primitive_sequence) < 2:
            raise ValueError("long_horizon_plan_requires_multiple_primitives")
        stage_ids = [stage.stage_id for stage in self.primitive_sequence]
        if len(stage_ids) != len(set(stage_ids)):
            raise ValueError("duplicate_primitive_plan_stage")
        if self.attack_entry_stage_id not in set(stage_ids):
            raise ValueError("attack_entry_stage_missing")
        for previous, current in zip(
            self.primitive_sequence, self.primitive_sequence[1:], strict=False
        ):
            if previous.output_state_ref not in current.input_state_refs:
                raise ValueError(
                    f"primitive_state_dependency_missing:{previous.stage_id}:{current.stage_id}"
                )
        if self.persistence.enabled and (
            self.persistence.storage_stage_id is None
            or self.persistence.retrieval_stage_id is None
            or self.persistence.stored_state_ref is None
        ):
            raise ValueError("enabled_persistence_requires_storage_and_retrieval")
        known_stage_ids = set(stage_ids)
        if self.persistence.enabled and (
            self.persistence.storage_stage_id not in known_stage_ids
            or self.persistence.retrieval_stage_id not in known_stage_ids
        ):
            raise ValueError("persistence_references_unknown_stage")
        if self.trigger.enabled and (
            self.trigger.condition is None or self.trigger.activation_stage_id is None
        ):
            raise ValueError("enabled_trigger_requires_condition_and_stage")
        if self.trigger.enabled and self.trigger.activation_stage_id not in known_stage_ids:
            raise ValueError("trigger_references_unknown_stage")
        objective_stage_ids = {point.stage_id for point in self.objective_trajectory}
        if not objective_stage_ids <= known_stage_ids | {"t0"}:
            raise ValueError("objective_trajectory_references_unknown_stage")
        control_ids = [control.control_id for control in self.control_cases]
        if len(control_ids) != len(set(control_ids)):
            raise ValueError("duplicate_planner_control_case")
        return self


class FormalEvaluationPlan(StrictModel):
    schema_version: Literal["2.0"] = "2.0"
    plan_id: str
    planner_input_id: str
    planner_type: str
    selected_sample_id: str | None
    selected_chain_id: str | None
    task_template_id: str
    binding: BenchmarkBinding | None
    baseline_binding: BaselineBinding | None = None
    materialization_variant: str
    condition: str
    budget: FormalBudget
    expected_public_stage_effects: dict[str, str]
    ablation_labels: list[str]
    selection_evidence: PlannerSelectionEvidence
    adversarial_trajectory: LongHorizonAdversarialTrajectory | None = None
    plan_hash: str
    abstain_reason: str | None = None

    @model_validator(mode="after")
    def validate_plan_or_abstention(self) -> FormalEvaluationPlan:
        selected = self.selected_sample_id is not None
        has_sample_binding = self.binding is not None
        has_baseline_binding = self.baseline_binding is not None
        if selected:
            if (
                not has_sample_binding
                or has_baseline_binding
                or self.selected_chain_id is None
                or self.abstain_reason is not None
                or self.adversarial_trajectory is None
            ):
                raise ValueError("formal_plan_selection_fields_mismatch")
        elif has_baseline_binding:
            if (
                has_sample_binding
                or self.selected_chain_id is not None
                or self.abstain_reason is not None
                or self.materialization_variant != "legal_baseline"
                or self.adversarial_trajectory is not None
            ):
                raise ValueError("formal_plan_baseline_fields_mismatch")
        elif (
            has_sample_binding
            or self.selected_chain_id is not None
            or self.abstain_reason is None
            or self.adversarial_trajectory is not None
        ):
            raise ValueError("formal_plan_abstention_fields_mismatch")
        return self


class FormalPlanner(Protocol):
    def plan(self, planner_input: FormalPlannerInput) -> FormalEvaluationPlan: ...
