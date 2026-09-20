from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Literal, Protocol

from pydantic import Field, NonNegativeInt, model_validator

from stac_attack_lab.contracts import StrictModel
from stac_attack_lab.hashing import file_hash, stable_hash
from stac_attack_lab.interactions.base import (
    CollectedInteraction,
    CollectionBudget,
    SourceInteractionTask,
)
from stac_attack_lab.interactions.models import InteractionGraph, RawInteractionTrajectory
from stac_attack_lab.interactions.normalizer import normalize_source_events

_FORBIDDEN_BENIGN_TERMS = (
    "attack",
    "exploit",
    "exfiltrat",
    "injection",
    "malicious",
    "tainted",
    "jailbreak",
)


def _reject_adversarial_language(values: list[str], reason: str) -> None:
    combined = " ".join(values).casefold()
    if any(term in combined for term in _FORBIDDEN_BENIGN_TERMS):
        raise ValueError(reason)


class SanitizationChange(StrictModel):
    field_path: str
    action: Literal["removed", "replaced", "retained"]
    reason: str
    replacement_kind: str | None = None


class NeutralizationResult(StrictModel):
    source_task_hash: str
    sanitized_task: dict[str, Any]
    applied_field_paths: list[str]
    sanitization_hash: str


def neutralize_source_task(
    *,
    source_task: dict[str, Any],
    source_task_hash: str,
    mapping: SourceTaskMapping,
    replacements: dict[str, object],
) -> NeutralizationResult:
    if mapping.source_kind != "safeclaw_derived":
        raise ValueError("neutralization_requires_safeclaw_derived_mapping")
    if stable_hash(source_task) != source_task_hash or mapping.source_task_hash != source_task_hash:
        raise ValueError("neutralization_source_hash_mismatch")
    sanitized = json.loads(json.dumps(source_task))
    applied: list[str] = []
    for change in mapping.changes:
        if not change.field_path.startswith("/") or "//" in change.field_path:
            raise ValueError("neutralization_field_path_invalid")
        tokens = change.field_path[1:].split("/")
        parent: object = sanitized
        for token in tokens[:-1]:
            if not isinstance(parent, dict) or token not in parent:
                raise ValueError("neutralization_field_path_missing")
            parent = parent[token]
        if not isinstance(parent, dict) or tokens[-1] not in parent:
            raise ValueError("neutralization_field_path_missing")
        if change.action == "removed":
            parent.pop(tokens[-1])
        elif change.action == "replaced":
            if change.field_path not in replacements:
                raise ValueError("neutralization_replacement_missing")
            parent[tokens[-1]] = replacements[change.field_path]
        elif change.field_path in replacements:
            raise ValueError("neutralization_retained_field_cannot_be_replaced")
        applied.append(change.field_path)
    if set(replacements) - set(applied):
        raise ValueError("neutralization_unreviewed_replacement")
    payload = {
        "source_task_hash": source_task_hash,
        "sanitized_task": sanitized,
        "applied_field_paths": applied,
    }
    return NeutralizationResult(
        **payload,
        sanitization_hash=stable_hash(payload),
    )


class SourceTaskMapping(StrictModel):
    source_kind: Literal["independent_synthetic", "safeclaw_derived"]
    source_task_id: str | None = None
    source_task_hash: str | None = None
    changes: list[SanitizationChange]
    retained_conditions: list[str]

    @model_validator(mode="after")
    def validate_mapping(self) -> SourceTaskMapping:
        if self.source_kind == "safeclaw_derived":
            if not self.source_task_id or not self.source_task_hash or not self.changes:
                raise ValueError("benign_derived_source_requires_sanitization_mapping")
        elif self.source_task_id is not None or self.source_task_hash is not None:
            raise ValueError("benign_synthetic_source_cannot_claim_upstream_task")
        return self


class BenignInteractionStep(StrictModel):
    step_id: str
    user_message: str
    followup_index: NonNegativeInt
    source_events: list[dict[str, Any]]
    stop_after: bool = False

    @model_validator(mode="after")
    def validate_step(self) -> BenignInteractionStep:
        if not self.step_id or not self.user_message.strip() or not self.source_events:
            raise ValueError("benign_step_incomplete")
        return self


class BenignScenario(StrictModel):
    schema_version: Literal["1.0"] = "1.0"
    scenario_id: str
    scenario_family: Literal[
        "read_only_answer",
        "multi_source_synthesis",
        "legitimate_memory",
        "resource_versioning",
        "delegation",
        "refusal_recovery",
    ]
    split_group: Literal["development", "validation", "synthetic"]
    environment_family: str
    environment_version: str
    legitimate_goal: str
    authorized_operations: list[str]
    normal_success_criteria: list[str]
    allowed_followups: NonNegativeInt
    domain_inventory: list[str]
    surface_inventory: list[str]
    lifecycle_policy: Literal["single_session", "explicit_new_session_allowed"]
    source_task_mapping: SourceTaskMapping
    instrumentation: list[str] = Field(default_factory=list)
    scripted_steps: list[BenignInteractionStep]

    @model_validator(mode="after")
    def validate_benign_scope(self) -> BenignScenario:
        identifiers = [
            self.scenario_id,
            self.legitimate_goal,
            *self.authorized_operations,
            *self.normal_success_criteria,
        ]
        _reject_adversarial_language(identifiers, "benign_scenario_adversarial_semantics_forbidden")
        if len(self.authorized_operations) != len(set(self.authorized_operations)):
            raise ValueError("benign_scenario_duplicate_authorized_operation")
        if len(self.scripted_steps) > self.allowed_followups + 1:
            raise ValueError("benign_scenario_followup_budget_exceeded")
        indexes = [item.followup_index for item in self.scripted_steps]
        if indexes != list(range(len(indexes))):
            raise ValueError("benign_scenario_followup_sequence_invalid")
        if not self.scripted_steps[-1].stop_after:
            raise ValueError("benign_scenario_stop_rule_missing")
        if self.lifecycle_policy == "single_session":
            sessions = {
                str(event.get("session_id"))
                for step in self.scripted_steps
                for event in step.source_events
            }
            if len(sessions) != 1:
                raise ValueError("benign_single_session_scenario_has_multiple_sessions")
        return self


class BenignScenarioSet(StrictModel):
    schema_version: Literal["1.0"] = "1.0"
    scenario_set_id: str
    scenarios: list[BenignScenario]

    @model_validator(mode="after")
    def validate_scenarios(self) -> BenignScenarioSet:
        ids = [item.scenario_id for item in self.scenarios]
        if not ids or len(ids) != len(set(ids)):
            raise ValueError("benign_scenario_set_ids_invalid")
        return self


class BenignPolicyObservation(StrictModel):
    scenario_id: str
    legitimate_goal: str
    public_response_summary: str | None = None
    completed_steps: NonNegativeInt
    remaining_followups: NonNegativeInt
    authorized_operations: list[str]


class BenignPolicyAction(StrictModel):
    action_id: str
    action_type: Literal["deliver_legitimate_message", "stop"]
    message: str | None = None
    reason_code: str

    @model_validator(mode="after")
    def validate_action(self) -> BenignPolicyAction:
        if (self.action_type == "deliver_legitimate_message") != (self.message is not None):
            raise ValueError("benign_policy_message_binding_invalid")
        return self


class CooperativeInteractionPolicy(Protocol):
    policy_id: str
    policy_version: str

    def next_action(
        self, scenario: BenignScenario, observation: BenignPolicyObservation
    ) -> BenignPolicyAction: ...


class ScriptedCooperativePolicy:
    policy_id = "stac.benign.scripted-cooperative"
    policy_version = "1.0.0"

    def next_action(
        self, scenario: BenignScenario, observation: BenignPolicyObservation
    ) -> BenignPolicyAction:
        if observation.completed_steps >= len(scenario.scripted_steps):
            return BenignPolicyAction(
                action_id=f"{scenario.scenario_id}:stop",
                action_type="stop",
                reason_code="normal_success_or_script_complete",
            )
        step = scenario.scripted_steps[observation.completed_steps]
        return BenignPolicyAction(
            action_id=f"{scenario.scenario_id}:{step.step_id}",
            action_type="deliver_legitimate_message",
            message=step.user_message,
            reason_code="scripted_legitimate_followup",
        )


class BenignScenarioAdapter:
    adapter_id = "benign_scenario_fixture"
    adapter_version = "1.0.0"

    def __init__(
        self,
        scenario_set_path: Path,
        *,
        policy: CooperativeInteractionPolicy | None = None,
    ) -> None:
        self.scenario_set_path = scenario_set_path
        self.scenario_set = BenignScenarioSet.model_validate_json(
            scenario_set_path.read_text(encoding="utf-8")
        )
        self.policy = policy or ScriptedCooperativePolicy()
        self.environment_version = "benign-scenario-fixture-v1"
        self._scenarios = {item.scenario_id: item for item in self.scenario_set.scenarios}

    def inventory(self) -> list[SourceInteractionTask]:
        return [
            SourceInteractionTask(
                source_task_id=item.scenario_id,
                source_split="synthetic",
                public_summary=item.legitimate_goal,
                environment_family=item.environment_family,
                metadata={
                    "scenario_family": item.scenario_family,
                    "source_mode": "benign_interaction",
                },
            )
            for item in self.scenario_set.scenarios
        ]

    def collect(
        self, task: SourceInteractionTask, *, seed: int, budget: CollectionBudget
    ) -> CollectedInteraction:
        scenario = self._scenarios[task.source_task_id]
        events: list[dict[str, Any]] = []
        delivered_messages: list[str] = []
        for index, step in enumerate(scenario.scripted_steps):
            action = self.policy.next_action(
                scenario,
                BenignPolicyObservation(
                    scenario_id=scenario.scenario_id,
                    legitimate_goal=scenario.legitimate_goal,
                    completed_steps=index,
                    remaining_followups=len(scenario.scripted_steps) - index - 1,
                    authorized_operations=scenario.authorized_operations,
                ),
            )
            if action.action_type != "deliver_legitimate_message":
                break
            if action.message != step.user_message:
                raise ValueError("benign_policy_departed_from_reviewed_scenario")
            delivered_messages.append(stable_hash(action.message))
            events.extend(step.source_events)
            if step.stop_after:
                break
        if len(events) > budget.max_events:
            raise ValueError("benign_source_event_budget_exceeded")
        session_ids = list(
            dict.fromkeys(str(item.get("session_id")) for item in events if item.get("session_id"))
        )
        return CollectedInteraction(
            source_task=task,
            episode_id=f"benign-{scenario.scenario_id}-{seed}",
            session_ids=session_ids,
            source_events=events,
            checkpoints=[],
            model_hashes={"interaction_policy": stable_hash(self.policy.policy_id)},
            config_hash=stable_hash(
                {
                    "scenario": scenario.model_dump(mode="json"),
                    "policy": [self.policy.policy_id, self.policy.policy_version],
                    "seed": seed,
                }
            ),
            status="complete",
            provenance={
                "source_mode": "benign_interaction",
                "scenario_id": scenario.scenario_id,
                "scenario_family": scenario.scenario_family,
                "scenario_set_hash": file_hash(self.scenario_set_path),
                "interaction_policy_id": self.policy.policy_id,
                "interaction_policy_version": self.policy.policy_version,
                "delivered_message_hashes": stable_hash(delivered_messages),
                "sanitization_manifest_hash": stable_hash(
                    scenario.source_task_mapping.model_dump(mode="json")
                ),
                "normal_success_evaluator": "fixture_declared_only",
                "security_evaluator_used": "false",
            },
        )

    def normalize(
        self, trajectory: RawInteractionTrajectory, artifact_root: str
    ) -> InteractionGraph:
        event_ref = trajectory.event_refs[0]
        if event_ref.relative_path is None:
            raise ValueError("benign_collection_event_ref_missing")
        source_events = [
            json.loads(line)
            for line in (Path(artifact_root) / event_ref.relative_path)
            .read_text(encoding="utf-8")
            .splitlines()
            if line.strip()
        ]
        graph, _ = normalize_source_events(
            trajectory,
            source_events,
            audit_ref=f"{artifact_root}/normalization_audit.json",
        )
        return graph
