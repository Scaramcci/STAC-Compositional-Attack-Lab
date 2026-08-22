from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Literal, Protocol

from pydantic import Field, model_validator

from stac_attack_lab.contracts import StrictModel
from stac_attack_lab.datasets.primitive_chain import ExecutionBindingView
from stac_attack_lab.environments.safeclaw.contracts import SafeClawPublicTaskView
from stac_attack_lab.hashing import stable_hash
from stac_attack_lab.models.base import ModelCallError, ModelClient
from stac_attack_lab.planning.formal_base import FormalEvaluationPlan
from stac_attack_lab.prompts.loader import PromptAsset, load_prompt


class FormalAttackerInput(StrictModel):
    schema_version: Literal["1.0"] = "1.0"
    attacker_input_id: str
    public_task: SafeClawPublicTaskView
    execution_view: ExecutionBindingView
    validated_plan: FormalEvaluationPlan
    remaining_budget: dict[str, int]
    prior_public_session_status: dict[str, str] = Field(default_factory=dict)

    @model_validator(mode="after")
    def validate_identity(self) -> FormalAttackerInput:
        if self.validated_plan.selected_sample_id != self.execution_view.sample_id:
            raise ValueError("formal_attacker_sample_identity_mismatch")
        if self.validated_plan.binding is None:
            raise ValueError("formal_attacker_requires_validated_sample_binding")
        return self


class FormalAttackerStageAction(StrictModel):
    stage_id: str
    macro_ref: str
    action_type: Literal["victim_message", "session_transition", "tool_surface", "stop"]
    benchmark_surface: str
    victim_visible_content: str | None = None
    public_slot_refs: list[str]
    expected_public_predicate: str
    rationale_summary: str

    @model_validator(mode="after")
    def validate_content_shape(self) -> FormalAttackerStageAction:
        needs_content = self.action_type in {"victim_message", "tool_surface"}
        if needs_content != (self.victim_visible_content is not None):
            raise ValueError("formal_attacker_content_shape_mismatch")
        return self


class FormalAttackRealization(StrictModel):
    schema_version: Literal["1.0"] = "1.0"
    attacker_input_id: str
    sample_id: str
    plan_id: str
    public_slot_values: dict[str, Any]
    stage_actions: list[FormalAttackerStageAction]
    abstain_reason: str | None = None
    realization_hash: str


class FormalAttacker(Protocol):
    attacker_id: str

    def realize(self, attacker_input: FormalAttackerInput, *, seed: int) -> FormalAttackRealization:
        ...


def _realization_payload(realization: FormalAttackRealization) -> dict[str, Any]:
    return realization.model_dump(mode="json", exclude={"realization_hash"})


def validate_formal_realization(
    realization: FormalAttackRealization,
    attacker_input: FormalAttackerInput,
) -> FormalAttackRealization:
    plan = attacker_input.validated_plan
    binding = plan.binding
    trajectory = plan.adversarial_trajectory
    if binding is None or trajectory is None:
        raise ValueError("formal_realization_requires_selected_trajectory")
    if (
        realization.attacker_input_id != attacker_input.attacker_input_id
        or realization.sample_id != attacker_input.execution_view.sample_id
        or realization.plan_id != plan.plan_id
    ):
        raise ValueError("formal_realization_identity_mismatch")
    required_slots = {assignment.sample_slot_id for assignment in binding.assignments}
    if set(realization.public_slot_values) != required_slots:
        raise ValueError("formal_realization_slot_set_mismatch")
    public_slots = {slot.slot_id: slot for slot in attacker_input.public_task.bindable_slots}
    benchmark_slot_by_sample = {
        assignment.sample_slot_id: assignment.benchmark_slot_id
        for assignment in binding.assignments
    }
    for slot_id, value in realization.public_slot_values.items():
        slot = public_slots.get(benchmark_slot_by_sample[slot_id])
        if slot is None or not slot.public:
            raise ValueError(f"formal_realization_unknown_public_slot:{slot_id}")
        valid = {
            "string": isinstance(value, str),
            "integer": isinstance(value, int) and not isinstance(value, bool),
            "boolean": isinstance(value, bool),
            "string_list": isinstance(value, list)
            and all(isinstance(item, str) for item in value),
            "object": isinstance(value, dict),
        }[slot.value_type]
        if not valid:
            raise ValueError(f"formal_realization_slot_type_mismatch:{slot_id}")
    expected_stages = [stage.stage_id for stage in trajectory.primitive_sequence]
    actual_stages = [action.stage_id for action in realization.stage_actions]
    if actual_stages != expected_stages:
        raise ValueError("formal_realization_stage_order_mismatch")
    trajectory_by_stage = {stage.stage_id: stage for stage in trajectory.primitive_sequence}
    public_predicates = set(plan.expected_public_stage_effects.values())
    allowed_surfaces = set(attacker_input.execution_view.allowed_benchmark_surfaces)
    for action in realization.stage_actions:
        stage = trajectory_by_stage[action.stage_id]
        if action.macro_ref != stage.macro_ref:
            raise ValueError("formal_realization_macro_mismatch")
        if action.benchmark_surface not in allowed_surfaces:
            raise ValueError("formal_realization_surface_not_allowed")
        if not set(action.public_slot_refs) <= required_slots:
            raise ValueError("formal_realization_references_unknown_slot")
        if action.expected_public_predicate not in public_predicates:
            raise ValueError("formal_realization_invents_public_predicate")
    if realization.abstain_reason is not None:
        raise ValueError("formal_realization_cannot_abstain_with_actions")
    expected_hash = stable_hash(_realization_payload(realization))
    if realization.realization_hash != expected_hash:
        raise ValueError("formal_realization_hash_mismatch")
    serialized = realization.model_dump_json().lower()
    forbidden = (
        "private_oracle",
        "success_condition",
        "safe_condition",
        "official_evaluation",
        "auth_profiles",
        "api_key",
        "password",
        "credential",
    )
    if any(token in serialized for token in forbidden):
        raise ValueError("formal_realization_contains_forbidden_private_term")
    return realization


class ModelFormalAttacker:
    attacker_id = "independent_model_formal_attacker_v1"

    def __init__(self, client: ModelClient, prompt_path: Path) -> None:
        self.client = client
        self.prompt: PromptAsset = load_prompt(prompt_path)

    def realize(self, attacker_input: FormalAttackerInput, *, seed: int) -> FormalAttackRealization:
        public_payload = attacker_input.model_dump(mode="json")
        try:
            value = self.client.generate(
                [
                    {"role": "system", "content": self.prompt.body},
                    {"role": "user", "content": json.dumps(public_payload, sort_keys=True)},
                ],
                FormalAttackRealization,
                seed=seed,
                timeout=60,
            )
        except ModelCallError as exc:
            raise ValueError("formal_attacker_model_call_failed") from exc
        if not isinstance(value, FormalAttackRealization):
            raise TypeError("formal_attacker_response_type_mismatch")
        canonical = value.model_copy(
            update={"realization_hash": stable_hash(_realization_payload(value))}
        )
        return validate_formal_realization(canonical, attacker_input)


def make_formal_attacker_input(
    *,
    case_id: str,
    public_task: SafeClawPublicTaskView,
    execution_view: ExecutionBindingView,
    plan: FormalEvaluationPlan,
) -> FormalAttackerInput:
    input_hash = stable_hash({"case_id": case_id, "plan": plan.plan_hash})
    return FormalAttackerInput(
        attacker_input_id=f"attacker-input-{input_hash[:20]}",
        public_task=public_task,
        execution_view=execution_view,
        validated_plan=plan,
        remaining_budget={
            "sessions": plan.budget.max_sessions,
            "turns": plan.budget.max_turns,
            "tool_calls": plan.budget.max_tool_calls,
            "tokens": plan.budget.max_tokens,
            "wall_time_seconds": plan.budget.max_wall_time_seconds,
        },
    )
