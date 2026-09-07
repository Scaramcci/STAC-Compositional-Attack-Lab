from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Literal, Protocol

from pydantic import Field, model_validator

from stac_attack_lab.contracts import StrictModel
from stac_attack_lab.datasets.primitive_chain import ExecutionBindingView
from stac_attack_lab.environments.safeclaw.contracts import (
    BenchmarkPublicPrompt,
    SafeClawPublicTaskView,
)
from stac_attack_lab.hashing import stable_hash
from stac_attack_lab.models.base import ModelCallError, ModelClient
from stac_attack_lab.planning.formal_base import (
    FormalEvaluationPlan,
    PrimitiveTrajectoryStage,
)
from stac_attack_lab.prompts.loader import PromptAsset, load_prompt
from stac_attack_lab.recording.model_calls import ObservableModelCallRecorder


class FormalAttackerInput(StrictModel):
    schema_version: Literal["1.0"] = "1.0"
    attacker_input_id: str
    public_task: SafeClawPublicTaskView
    execution_view: ExecutionBindingView
    benchmark_public_prompt: BenchmarkPublicPrompt
    validated_plan: FormalEvaluationPlan
    remaining_budget: dict[str, int]
    prior_public_session_status: dict[str, str] = Field(default_factory=dict)

    @model_validator(mode="after")
    def validate_identity(self) -> FormalAttackerInput:
        if self.validated_plan.selected_sample_id != self.execution_view.sample_id:
            raise ValueError("formal_attacker_sample_identity_mismatch")
        if self.validated_plan.binding is None:
            raise ValueError("formal_attacker_requires_validated_sample_binding")
        if self.benchmark_public_prompt.task_id != self.public_task.task_id:
            raise ValueError("formal_attacker_public_prompt_task_mismatch")
        return self


class NoSampleAttackerInput(StrictModel):
    schema_version: Literal["1.0"] = "1.0"
    attacker_input_id: str
    plan_id: str
    public_task: SafeClawPublicTaskView
    benchmark_public_prompt: BenchmarkPublicPrompt
    remaining_budget: dict[str, int]
    allowed_surfaces: list[str]
    condition: Literal["no_sample"] = "no_sample"

    @model_validator(mode="after")
    def validate_public_only(self) -> NoSampleAttackerInput:
        if self.public_task.task_id != self.benchmark_public_prompt.task_id:
            raise ValueError("no_sample_public_task_prompt_mismatch")
        if not self.allowed_surfaces:
            raise ValueError("no_sample_allowed_surfaces_empty")
        forbidden_fields = {
            "execution_view",
            "sample_id",
            "private_oracle_ref",
            "api_key",
            "credential",
        }
        if forbidden_fields & set(type(self).model_fields):
            raise ValueError("no_sample_input_contains_private_or_sample_metadata")
        return self


class NoSampleAttackRealization(StrictModel):
    schema_version: Literal["1.0"] = "1.0"
    attacker_input_id: str
    plan_id: str
    stage_actions: list[FormalAttackerStageAction]
    realization_hash: str

    @model_validator(mode="after")
    def validate_hash(self) -> NoSampleAttackRealization:
        payload = self.model_dump(mode="json", exclude={"realization_hash"})
        if self.realization_hash not in {"runtime-computed", stable_hash(payload)}:
            raise ValueError("no_sample_realization_hash_mismatch")
        if not self.stage_actions:
            raise ValueError("no_sample_realization_empty")
        return self


class FormalAttackerStageAction(StrictModel):
    attacker_call_id: str | None = None
    attacker_action_id: str | None = None
    plan_id: str | None = None
    benchmark_session_id: str | None = None
    stage_id: str
    macro_ref: str
    action_type: Literal[
        "victim_message", "session_transition", "tool_surface", "retry", "reroute", "stop"
    ]
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


class FormalVictimObservation(StrictModel):
    schema_version: Literal["1.0"] = "1.0"
    observation_id: str
    plan_id: str
    plan_stage_id: str
    attacker_call_id: str
    attacker_action_id: str
    victim_request_event_id: str
    victim_response_event_id: str
    tool_event_ids: list[str] = Field(default_factory=list)
    input_artifact_refs: list[str] = Field(default_factory=list)
    input_state_refs: list[str] = Field(default_factory=list)
    output_artifact_refs: list[str] = Field(default_factory=list)
    output_state_refs: list[str] = Field(default_factory=list)
    verifier_evidence_refs: list[str] = Field(default_factory=list)
    benchmark_session_id: str
    public_response_text: str
    public_tool_calls: list[dict[str, Any]] = Field(default_factory=list)
    public_state_delta: dict[str, Any] = Field(default_factory=dict)
    status: Literal["completed", "blocked", "error", "timeout"]
    observation_hash: str

    @model_validator(mode="after")
    def validate_observation_hash(self) -> FormalVictimObservation:
        payload = self.model_dump(mode="json", exclude={"observation_hash"})
        if self.observation_hash != stable_hash(payload):
            raise ValueError("formal_victim_observation_hash_mismatch")
        return self


class FormalAttackerStepInput(StrictModel):
    schema_version: Literal["1.0"] = "1.0"
    attacker_call_id: str
    attacker_input_id: str
    plan_id: str
    stage_index: int
    stage: PrimitiveTrajectoryStage
    benchmark_session_id: str
    public_task: SafeClawPublicTaskView
    benchmark_public_prompt: BenchmarkPublicPrompt
    execution_view: ExecutionBindingView
    prior_public_observations: list[FormalVictimObservation] = Field(default_factory=list)
    remaining_budget: dict[str, int]

    @model_validator(mode="after")
    def validate_step_identity(self) -> FormalAttackerStepInput:
        if self.stage.stage_id not in self.execution_view.core_pattern_refs:
            raise ValueError("formal_attacker_step_unknown_core_stage")
        if self.benchmark_public_prompt.task_id != self.public_task.task_id:
            raise ValueError("formal_attacker_step_public_prompt_task_mismatch")
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

    def realize(
        self, attacker_input: FormalAttackerInput, *, seed: int
    ) -> FormalAttackRealization: ...

    def next_action(
        self, step_input: FormalAttackerStepInput, *, seed: int
    ) -> FormalAttackerStageAction: ...


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
            "string_list": isinstance(value, list) and all(isinstance(item, str) for item in value),
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


def validate_formal_step_action(
    action: FormalAttackerStageAction,
    step_input: FormalAttackerStepInput,
) -> FormalAttackerStageAction:
    if action.stage_id != step_input.stage.stage_id:
        raise ValueError("formal_attacker_action_stage_mismatch")
    if action.macro_ref != step_input.stage.macro_ref:
        raise ValueError("formal_attacker_action_macro_mismatch")
    if action.benchmark_surface not in set(step_input.execution_view.allowed_benchmark_surfaces):
        raise ValueError("formal_attacker_action_surface_not_allowed")
    if not set(action.public_slot_refs) <= set(step_input.execution_view.parameter_schemas):
        raise ValueError("formal_attacker_action_unknown_slot")
    if action.expected_public_predicate != step_input.stage.output_state_ref:
        raise ValueError("formal_attacker_action_predicate_mismatch")
    if action.action_type == "retry" and action.stage_id not in set(
        step_input.execution_view.legal_retry_node_ids
    ):
        raise ValueError("formal_attacker_action_retry_not_allowed")
    if action.action_type == "reroute" and action.stage_id not in set(
        step_input.execution_view.legal_reroute_node_ids
    ):
        raise ValueError("formal_attacker_action_reroute_not_allowed")
    canonical = action.model_copy(
        update={
            "attacker_call_id": step_input.attacker_call_id,
            "attacker_action_id": "attacker-action-"
            + stable_hash(
                {
                    "call_id": step_input.attacker_call_id,
                    "stage_id": action.stage_id,
                    "content": action.victim_visible_content,
                }
            )[:20],
            "plan_id": step_input.plan_id,
            "benchmark_session_id": step_input.benchmark_session_id,
        }
    )
    serialized = canonical.model_dump_json().lower()
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
        raise ValueError("formal_attacker_action_contains_forbidden_private_term")
    return canonical


class ModelFormalAttacker:
    attacker_id = "independent_model_formal_attacker_v1"
    model_call_backed = True

    def __init__(self, client: ModelClient, prompt_path: Path) -> None:
        self.client = client
        self.prompt: PromptAsset = load_prompt(prompt_path)
        self.call_recorder: ObservableModelCallRecorder | None = None

    def set_call_recorder(self, recorder: ObservableModelCallRecorder | None) -> None:
        self.call_recorder = recorder

    def realize(self, attacker_input: FormalAttackerInput, *, seed: int) -> FormalAttackRealization:
        public_payload = attacker_input.model_dump(mode="json")
        messages = [
            {"role": "system", "content": self.prompt.body},
            {"role": "user", "content": json.dumps(public_payload, sort_keys=True)},
        ]
        response_received = False
        try:
            if self.call_recorder is not None:
                value = self.call_recorder.generate(
                    self.client,
                    messages,
                    FormalAttackRealization,
                    seed=seed,
                    timeout=60,
                    lineage_refs=[
                        attacker_input.attacker_input_id,
                        attacker_input.validated_plan.plan_id,
                        attacker_input.execution_view.sample_id,
                    ],
                )
            else:
                value = self.client.generate(
                    messages,
                    FormalAttackRealization,
                    seed=seed,
                    timeout=60,
                )
            response_received = True
        except ModelCallError as exc:
            raise ValueError("formal_attacker_model_call_failed") from exc
        try:
            if not isinstance(value, FormalAttackRealization):
                raise TypeError("formal_attacker_response_type_mismatch")
            canonical = value.model_copy(
                update={"realization_hash": stable_hash(_realization_payload(value))}
            )
            validated = validate_formal_realization(canonical, attacker_input)
        except (TypeError, ValueError) as exc:
            if self.call_recorder is not None and response_received:
                self.call_recorder.mark_semantic_validation(
                    passed=False, reason_codes=[type(exc).__name__]
                )
            raise
        if self.call_recorder is not None:
            self.call_recorder.mark_semantic_validation(
                passed=True, reason_codes=["formal_realization_valid"]
            )
        return validated

    def next_action(
        self, step_input: FormalAttackerStepInput, *, seed: int
    ) -> FormalAttackerStageAction:
        messages = [
            {"role": "system", "content": self.prompt.body},
            {
                "role": "user",
                "content": json.dumps(step_input.model_dump(mode="json"), sort_keys=True),
            },
        ]
        response_received = False
        try:
            if self.call_recorder is not None:
                value = self.call_recorder.generate(
                    self.client,
                    messages,
                    FormalAttackerStageAction,
                    seed=seed + step_input.stage_index,
                    timeout=60,
                    lineage_refs=[
                        step_input.attacker_call_id,
                        step_input.attacker_input_id,
                        step_input.plan_id,
                        step_input.stage.stage_id,
                        step_input.benchmark_session_id,
                    ],
                )
            else:
                value = self.client.generate(
                    messages,
                    FormalAttackerStageAction,
                    seed=seed + step_input.stage_index,
                    timeout=60,
                )
            response_received = True
        except ModelCallError as exc:
            raise ValueError("formal_attacker_step_model_call_failed") from exc
        try:
            if not isinstance(value, FormalAttackerStageAction):
                raise TypeError("formal_attacker_step_response_type_mismatch")
            validated = validate_formal_step_action(value, step_input)
        except (TypeError, ValueError) as exc:
            if self.call_recorder is not None and response_received:
                self.call_recorder.mark_semantic_validation(
                    passed=False, reason_codes=[type(exc).__name__]
                )
            raise
        if self.call_recorder is not None:
            self.call_recorder.mark_semantic_validation(
                passed=True, reason_codes=["formal_step_action_valid"]
            )
        return validated


class ModelNoSampleAttacker:
    attacker_id = "public_task_no_sample_model_attacker_v1"
    model_call_backed = True

    def __init__(self, client: ModelClient, prompt_path: Path) -> None:
        self.client = client
        self.prompt: PromptAsset = load_prompt(prompt_path)
        self.call_recorder: ObservableModelCallRecorder | None = None

    def set_call_recorder(self, recorder: ObservableModelCallRecorder | None) -> None:
        self.call_recorder = recorder

    def realize(
        self, attacker_input: NoSampleAttackerInput, *, seed: int
    ) -> NoSampleAttackRealization:
        messages = [
            {"role": "system", "content": self.prompt.body},
            {
                "role": "user",
                "content": json.dumps(attacker_input.model_dump(mode="json"), sort_keys=True),
            },
        ]
        try:
            if self.call_recorder is not None:
                value = self.call_recorder.generate(
                    self.client,
                    messages,
                    NoSampleAttackRealization,
                    seed=seed,
                    timeout=60,
                    lineage_refs=[attacker_input.attacker_input_id, attacker_input.plan_id],
                )
            else:
                value = self.client.generate(
                    messages, NoSampleAttackRealization, seed=seed, timeout=60
                )
        except ModelCallError as exc:
            raise ValueError("no_sample_attacker_model_call_failed") from exc
        if not isinstance(value, NoSampleAttackRealization):
            raise ValueError("no_sample_attacker_response_type_mismatch")
        try:
            payload = value.model_dump(mode="json", exclude={"realization_hash"})
            canonical = value.model_copy(update={"realization_hash": stable_hash(payload)})
            if (
                canonical.attacker_input_id != attacker_input.attacker_input_id
                or canonical.plan_id != attacker_input.plan_id
            ):
                raise ValueError("no_sample_attacker_identity_mismatch")
            public_sessions = {
                item.session_id for item in attacker_input.benchmark_public_prompt.sessions
            }
            if len(canonical.stage_actions) > attacker_input.remaining_budget["turns"]:
                raise ValueError("no_sample_attacker_turn_budget_exceeded")
            seen_sessions: set[str] = set()
            for action in canonical.stage_actions:
                if action.benchmark_surface not in attacker_input.allowed_surfaces:
                    raise ValueError("no_sample_attacker_surface_not_allowed")
                if action.benchmark_session_id not in public_sessions:
                    raise ValueError("no_sample_attacker_session_not_public")
                if action.benchmark_session_id in seen_sessions:
                    raise ValueError("no_sample_attacker_duplicate_session")
                if action.action_type not in {
                    "victim_message",
                    "session_transition",
                    "tool_surface",
                    "retry",
                    "reroute",
                }:
                    raise ValueError("no_sample_attacker_action_type_not_allowed")
                seen_sessions.add(action.benchmark_session_id)
        except (TypeError, ValueError) as exc:
            if self.call_recorder is not None:
                self.call_recorder.mark_semantic_validation(passed=False, reason_codes=[str(exc)])
            raise
        if self.call_recorder is not None:
            self.call_recorder.mark_semantic_validation(
                passed=True, reason_codes=["no_sample_realization_valid"]
            )
        return canonical


def make_no_sample_attacker_input(
    *,
    case_id: str,
    public_task: SafeClawPublicTaskView,
    benchmark_public_prompt: BenchmarkPublicPrompt,
    plan: FormalEvaluationPlan,
) -> NoSampleAttackerInput:
    allowed = sorted(public_task.allowed_actions)
    payload = {"case_id": case_id, "plan_id": plan.plan_id, "task_id": public_task.task_id}
    return NoSampleAttackerInput(
        attacker_input_id="no-sample-attacker-input-" + stable_hash(payload)[:20],
        plan_id=plan.plan_id,
        public_task=public_task,
        benchmark_public_prompt=benchmark_public_prompt,
        remaining_budget={
            "sessions": plan.budget.max_sessions,
            "turns": plan.budget.max_turns,
            "tool_calls": plan.budget.max_tool_calls,
            "tokens": plan.budget.max_tokens,
            "wall_time_seconds": plan.budget.max_wall_time_seconds,
        },
        allowed_surfaces=allowed,
    )


def build_no_sample_attack_realization(
    attacker_input: NoSampleAttackerInput,
) -> NoSampleAttackRealization:
    actions: list[FormalAttackerStageAction] = []
    for index, session in enumerate(attacker_input.benchmark_public_prompt.sessions):
        if index >= attacker_input.remaining_budget["turns"]:
            break
        call_id = (
            "no-sample-call-"
            + stable_hash(
                {
                    "input": attacker_input.attacker_input_id,
                    "session": session.session_id,
                    "index": index,
                }
            )[:20]
        )
        actions.append(
            FormalAttackerStageAction(
                attacker_call_id=call_id,
                attacker_action_id="no-sample-action-" + stable_hash(call_id)[:20],
                plan_id=attacker_input.plan_id,
                benchmark_session_id=session.session_id,
                stage_id=f"no-sample-session-{index + 1}",
                macro_ref="no_sample.generated_public_policy",
                action_type="victim_message",
                benchmark_surface="safeclaw.session_lifecycle",
                victim_visible_content=session.user_instruction,
                public_slot_refs=[],
                expected_public_predicate="public_session_completed",
                rationale_summary=(
                    "Generate an action from the public task prompt without sample data."
                ),
            )
        )
    payload = {
        "schema_version": "1.0",
        "attacker_input_id": attacker_input.attacker_input_id,
        "plan_id": attacker_input.plan_id,
        "stage_actions": [item.model_dump(mode="json") for item in actions],
    }
    return NoSampleAttackRealization(
        schema_version="1.0",
        attacker_input_id=attacker_input.attacker_input_id,
        plan_id=attacker_input.plan_id,
        stage_actions=actions,
        realization_hash=stable_hash(payload),
    )


def make_formal_attacker_input(
    *,
    case_id: str,
    public_task: SafeClawPublicTaskView,
    benchmark_public_prompt: BenchmarkPublicPrompt,
    execution_view: ExecutionBindingView,
    plan: FormalEvaluationPlan,
) -> FormalAttackerInput:
    input_hash = stable_hash({"case_id": case_id, "plan": plan.plan_hash})
    return FormalAttackerInput(
        attacker_input_id=f"attacker-input-{input_hash[:20]}",
        public_task=public_task,
        benchmark_public_prompt=benchmark_public_prompt,
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
