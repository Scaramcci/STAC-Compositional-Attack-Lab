from __future__ import annotations

from enum import StrEnum
from typing import Literal, Protocol

from pydantic import Field, PositiveInt, model_validator

from stac_attack_lab.contracts import StrictModel
from stac_attack_lab.datasets.primitive_chain import PlannerSampleView
from stac_attack_lab.environments.safeclaw.contracts import (
    BaselineBinding,
    BenchmarkBinding,
    BenchmarkPublicPrompt,
    SafeClawPublicTaskView,
)
from stac_attack_lab.hashing import stable_hash
from stac_attack_lab.interactions.models import DependencyType
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


class FormalCaseAssignment(StrictModel):
    schema_version: Literal["3.0"] = "3.0"
    assignment_id: str
    case_id: str
    pair_group: str
    benchmark_task_id: str
    benchmark_public_prompt: BenchmarkPublicPrompt
    benchmark_public_prompt_hash: str
    selected_sample_id: str | None
    selected_sample_hash: str | None
    condition: str
    seed: int
    budget: FormalBudget
    task_set_hash: str
    library_hash: str
    registry_hash: str
    assignment_hash: str

    @model_validator(mode="after")
    def validate_assignment(self) -> FormalCaseAssignment:
        if self.benchmark_public_prompt.task_id != self.benchmark_task_id:
            raise ValueError("assignment_public_prompt_task_mismatch")
        if self.benchmark_public_prompt.prompt_hash != self.benchmark_public_prompt_hash:
            raise ValueError("assignment_public_prompt_hash_mismatch")
        if (self.selected_sample_id is None) != (self.selected_sample_hash is None):
            raise ValueError("assignment_selected_sample_fields_mismatch")
        if self.condition == "no_sample" and self.selected_sample_id is not None:
            raise ValueError("no_sample_assignment_contains_sample")
        payload = self.model_dump(mode="json", exclude={"assignment_hash"})
        if self.assignment_hash != stable_hash(payload):
            raise ValueError("formal_case_assignment_hash_mismatch")
        return self


class SingleSamplePlannerInput(StrictModel):
    schema_version: Literal["3.0"] = "3.0"
    planner_input_id: str
    assignment_id: str
    public_task: SafeClawPublicTaskView
    benchmark_public_prompt: BenchmarkPublicPrompt
    selected_sample: PublicSampleIndexEntry | None
    budget: FormalBudget
    condition: str
    seed: int
    prior_public_session_status: dict[str, str] = Field(default_factory=dict)

    @model_validator(mode="after")
    def validate_single_sample_contract(self) -> SingleSamplePlannerInput:
        if self.public_task.task_id != self.benchmark_public_prompt.task_id:
            raise ValueError("planner_public_prompt_task_mismatch")
        if self.condition == "no_sample" and self.selected_sample is not None:
            raise ValueError("no_sample_planner_input_contains_sample")
        if self.condition != "no_sample" and self.selected_sample is None:
            raise ValueError("sample_condition_planner_input_missing_sample")
        return self


# Shared name for the strict single-sample planner contract. The schema rejects
# full-library metadata, so a Planner can only receive the scheduled sample.
FormalPlannerInput = SingleSamplePlannerInput


class PlannerSelectionEvidence(StrictModel):
    compatible_sample_ids: list[str]
    rejected_sample_reason_codes: dict[str, list[str]]
    rank_scores: dict[str, float]
    decision_source: Literal[
        "scheduler_assigned",
        "deterministic",
        "random_compatible",
        "llm_tiebreak",
        "abstain",
    ]
    public_prompt_hash: str | None = None


class LongHorizonAttackFamily(StrEnum):
    objective_drifting = "objective_drifting"
    intent_hijacking = "intent_hijacking"
    persistent_state_poisoning = "persistent_state_poisoning"
    trigger_based = "trigger_based"
    compound_hybrid = "compound_hybrid"


class PrimitiveTrajectoryStage(StrictModel):
    stage_id: str
    core_node_ref: str
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


class DependencyAblationPlan(StrictModel):
    intervention_id: str
    sample_id: str
    target_edge_id: str
    source_stage_id: str
    target_stage_id: str
    edge_type: DependencyType
    materialization_slot_id: str
    replacement_source: Literal["baseline.task_set"] = "baseline.task_set"
    expected_observation: Literal["target_dependency_absent"] = "target_dependency_absent"
    trajectory_hash: str


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
    dependency_ablation: DependencyAblationPlan | None = None
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
        trajectory = self.adversarial_trajectory
        if self.condition == "dependency_ablation":
            if not selected or self.dependency_ablation is None or trajectory is None:
                raise ValueError("dependency_ablation_plan_missing_intervention")
            stage_ids = {stage.stage_id for stage in trajectory.primitive_sequence}
            if (
                self.dependency_ablation.source_stage_id not in stage_ids
                or self.dependency_ablation.target_stage_id not in stage_ids
            ):
                raise ValueError("dependency_ablation_references_unknown_stage")
        elif self.dependency_ablation is not None:
            raise ValueError("non_ablation_plan_contains_dependency_intervention")
        return self


class FormalPlanner(Protocol):
    def plan(self, planner_input: FormalPlannerInput) -> FormalEvaluationPlan: ...
