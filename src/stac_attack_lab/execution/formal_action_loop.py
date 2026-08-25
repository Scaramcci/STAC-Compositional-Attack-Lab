from __future__ import annotations

import time
from typing import Protocol

from pydantic import Field, NonNegativeInt, model_validator

from stac_attack_lab.contracts import StrictModel
from stac_attack_lab.execution.formal_attacker import (
    FormalAttacker,
    FormalAttackerInput,
    FormalAttackerStageAction,
    FormalAttackerStepInput,
    FormalAttackRealization,
    FormalVictimObservation,
    validate_formal_realization,
    validate_formal_step_action,
)
from stac_attack_lab.hashing import stable_hash


class FormalVictimStepDriver(Protocol):
    driver_id: str

    def apply(
        self,
        action: FormalAttackerStageAction,
        *,
        timeout_seconds: int,
    ) -> FormalVictimObservation: ...


class FormalActionLoopAccounting(StrictModel):
    attacker_model_calls: NonNegativeInt
    victim_gateway_requests: NonNegativeInt
    attacker_decision_calls: NonNegativeInt
    victim_provider_completions_when_observable: NonNegativeInt | None = None
    sessions_used: NonNegativeInt
    turns_used: NonNegativeInt
    tool_calls_observed: NonNegativeInt
    wall_time_ms: NonNegativeInt
    input_tokens: int | None = None
    output_tokens: int | None = None
    cached_tokens: int | None = None
    provider_cost: float | None = None
    instrumentation_gap_reasons: list[str] = Field(default_factory=list)


class FormalActionLoopResult(StrictModel):
    schema_version: str = "1.0"
    realization: FormalAttackRealization
    observations: list[FormalVictimObservation]
    accounting: FormalActionLoopAccounting
    loop_hash: str

    @model_validator(mode="after")
    def validate_loop_hash(self) -> FormalActionLoopResult:
        payload = self.model_dump(mode="json", exclude={"loop_hash"})
        if self.loop_hash != stable_hash(payload):
            raise ValueError("formal_action_loop_hash_mismatch")
        return self


def _benchmark_session_id(attacker_input: FormalAttackerInput, stage_id: str) -> str:
    binding = attacker_input.validated_plan.binding
    if binding is None:
        raise ValueError("formal_action_loop_requires_sample_binding")
    label = binding.node_session_mapping.get(stage_id)
    if label is None:
        raise ValueError(f"formal_action_loop_stage_session_missing:{stage_id}")
    try:
        ordinal = int(label.rsplit("-", 1)[1])
    except (IndexError, ValueError) as exc:
        raise ValueError(f"formal_action_loop_invalid_session_label:{label}") from exc
    sessions = attacker_input.benchmark_public_prompt.sessions
    if ordinal < 1 or ordinal > len(sessions):
        raise ValueError(f"formal_action_loop_session_out_of_range:{label}")
    return sessions[ordinal - 1].session_id


def _validate_observation_lineage(
    action: FormalAttackerStageAction,
    observation: FormalVictimObservation,
) -> None:
    required_action_fields = (
        action.plan_id,
        action.attacker_call_id,
        action.attacker_action_id,
        action.benchmark_session_id,
    )
    if any(value is None or not value for value in required_action_fields):
        raise ValueError("formal_action_lineage_incomplete")
    if (
        observation.plan_id != action.plan_id
        or observation.plan_stage_id != action.stage_id
        or observation.attacker_call_id != action.attacker_call_id
        or observation.attacker_action_id != action.attacker_action_id
        or observation.benchmark_session_id != action.benchmark_session_id
    ):
        raise ValueError("formal_action_observation_lineage_mismatch")
    if not observation.victim_request_event_id or not observation.victim_response_event_id:
        raise ValueError("formal_victim_event_lineage_incomplete")
    if not observation.input_state_refs or not observation.output_state_refs:
        raise ValueError("formal_victim_state_lineage_incomplete")
    if not observation.verifier_evidence_refs:
        raise ValueError("formal_victim_evidence_lineage_incomplete")


def execute_formal_action_loop(
    attacker: FormalAttacker,
    attacker_input: FormalAttackerInput,
    setup_realization: FormalAttackRealization,
    driver: FormalVictimStepDriver,
    *,
    seed: int,
    execution_attempt_id: str = "attempt-001",
) -> FormalActionLoopResult:
    trajectory = attacker_input.validated_plan.adversarial_trajectory
    if trajectory is None:
        raise ValueError("formal_action_loop_requires_trajectory")
    budget = attacker_input.validated_plan.budget
    started = time.monotonic()
    actions: list[FormalAttackerStageAction] = []
    observations: list[FormalVictimObservation] = []
    used_sessions: set[str] = set()
    tool_calls = 0
    for stage_index, stage in enumerate(trajectory.primitive_sequence):
        if len(actions) >= budget.max_turns:
            raise ValueError("formal_action_loop_turn_budget_exhausted")
        elapsed = time.monotonic() - started
        if elapsed >= budget.max_wall_time_seconds:
            raise ValueError("formal_action_loop_wall_time_budget_exhausted")
        benchmark_session_id = _benchmark_session_id(attacker_input, stage.stage_id)
        candidate_sessions = {*used_sessions, benchmark_session_id}
        if len(candidate_sessions) > budget.max_sessions:
            raise ValueError("formal_action_loop_session_budget_exhausted")
        call_id = (
            "attacker-call-"
            + stable_hash(
                {
                    "attacker_input_id": attacker_input.attacker_input_id,
                    "execution_attempt_id": execution_attempt_id,
                    "stage_id": stage.stage_id,
                    "stage_index": stage_index,
                    "prior_observation_hashes": [item.observation_hash for item in observations],
                }
            )[:20]
        )
        step_input = FormalAttackerStepInput(
            attacker_call_id=call_id,
            attacker_input_id=attacker_input.attacker_input_id,
            plan_id=attacker_input.validated_plan.plan_id,
            stage_index=stage_index,
            stage=stage,
            benchmark_session_id=benchmark_session_id,
            public_task=attacker_input.public_task,
            benchmark_public_prompt=attacker_input.benchmark_public_prompt,
            execution_view=attacker_input.execution_view,
            prior_public_observations=observations,
            remaining_budget={
                "sessions": budget.max_sessions - len(used_sessions),
                "turns": budget.max_turns - len(actions),
                "tool_calls": budget.max_tool_calls - tool_calls,
                "tokens": budget.max_tokens,
                "wall_time_seconds": max(0, budget.max_wall_time_seconds - int(elapsed)),
            },
        )
        proposed = attacker.next_action(step_input, seed=seed)
        action = validate_formal_step_action(proposed, step_input)
        if action.action_type == "stop":
            raise ValueError(f"formal_attacker_stopped_before_stage:{stage.stage_id}")
        observation = driver.apply(
            action,
            timeout_seconds=max(1, step_input.remaining_budget["wall_time_seconds"]),
        )
        _validate_observation_lineage(action, observation)
        tool_calls += len(observation.tool_event_ids)
        if tool_calls > budget.max_tool_calls:
            raise ValueError("formal_action_loop_tool_budget_exhausted")
        used_sessions = candidate_sessions
        actions.append(action)
        observations.append(observation)
        if observation.status in {"blocked", "error", "timeout"}:
            raise ValueError(f"formal_victim_step_{observation.status}:{stage.stage_id}")
    aggregate_payload = {
        "schema_version": "1.0",
        "attacker_input_id": setup_realization.attacker_input_id,
        "sample_id": setup_realization.sample_id,
        "plan_id": setup_realization.plan_id,
        "public_slot_values": setup_realization.public_slot_values,
        "stage_actions": [item.model_dump(mode="json") for item in actions],
        "abstain_reason": None,
    }
    realization = validate_formal_realization(
        FormalAttackRealization.model_validate(
            {
                **aggregate_payload,
                "realization_hash": stable_hash(aggregate_payload),
            }
        ),
        attacker_input,
    )
    decision_calls = 1 + len(actions)
    accounting = FormalActionLoopAccounting(
        attacker_model_calls=(
            decision_calls if bool(getattr(attacker, "model_call_backed", False)) else 0
        ),
        attacker_decision_calls=decision_calls,
        victim_gateway_requests=sum(
            action.action_type in {"victim_message", "tool_surface"} for action in actions
        ),
        sessions_used=len(used_sessions),
        turns_used=len(actions),
        tool_calls_observed=tool_calls,
        wall_time_ms=int((time.monotonic() - started) * 1000),
        instrumentation_gap_reasons=[
            "attacker_provider_usage_not_exposed_by_model_client",
            "victim_provider_completion_count_not_exposed_by_gateway",
            "provider_cost_not_returned",
        ],
    )
    payload = {
        "schema_version": "1.0",
        "realization": realization.model_dump(mode="json"),
        "observations": [item.model_dump(mode="json") for item in observations],
        "accounting": accounting.model_dump(mode="json"),
    }
    return FormalActionLoopResult.model_validate({**payload, "loop_hash": stable_hash(payload)})
