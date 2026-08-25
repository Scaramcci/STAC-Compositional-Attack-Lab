from __future__ import annotations

import json
from pathlib import Path
from typing import Literal, Protocol

from pydantic import Field, model_validator

from stac_attack_lab.contracts import StrictModel
from stac_attack_lab.hashing import stable_hash
from stac_attack_lab.interactions.base import SourceInteractionTask
from stac_attack_lab.interactions.models import ConstructionManifest
from stac_attack_lab.models.base import ModelCallError, ModelClient
from stac_attack_lab.prompts.loader import PromptAsset, load_prompt


class ConstructionObservation(StrictModel):
    """Evaluator-free state exposed to the construction attacker."""

    task_id: str
    session_index: int
    action_index: int
    public_transcript: list[dict[str, str]] = Field(default_factory=list)
    public_component_inventory: dict[str, list[str]] = Field(default_factory=dict)
    public_capabilities: list[str] = Field(default_factory=list)
    public_stage_status: dict[str, str] = Field(default_factory=dict)
    remaining_sessions: int
    remaining_turns: int
    remaining_actions: int
    remaining_tool_calls: int
    remaining_tokens: int
    elapsed_wall_time_ms: int
    remaining_events: int
    legal_retry_ids: list[str] = Field(default_factory=list)
    legal_reroute_ids: list[str] = Field(default_factory=list)


class ConstructionAttackerAction(StrictModel):
    action_id: str
    action_type: Literal["deliver_message", "start_new_session", "retry", "reroute", "stop"]
    delivery_surface: str | None = None
    public_message: str | None = None
    retry_id: str | None = None
    reroute_id: str | None = None
    expected_public_predicate_id: str | None = None
    rationale_summary: str

    @model_validator(mode="after")
    def validate_action_shape(self) -> ConstructionAttackerAction:
        message_action = self.action_type == "deliver_message"
        if message_action != (self.public_message is not None):
            raise ValueError("construction_message_required_only_for_delivery")
        if message_action != (self.delivery_surface is not None):
            raise ValueError("construction_surface_required_only_for_delivery")
        if (self.action_type == "retry") != (self.retry_id is not None):
            raise ValueError("construction_retry_id_shape_mismatch")
        if (self.action_type == "reroute") != (self.reroute_id is not None):
            raise ValueError("construction_reroute_id_shape_mismatch")
        return self


class ConstructionAttacker(Protocol):
    attacker_id: str

    def prepare(self, task: SourceInteractionTask, *, seed: int) -> ConstructionManifest: ...

    def next_action(
        self,
        task: SourceInteractionTask,
        manifest: ConstructionManifest,
        observation: ConstructionObservation,
        *,
        seed: int,
    ) -> ConstructionAttackerAction: ...


class DeterministicConstructionAttacker:
    """Creates a public synthetic objective without evaluator-private state."""

    attacker_id = "deterministic_synthetic_construction_attacker"

    def __init__(
        self,
        *,
        objective_id: str,
        public_attack_goal: str,
        allowed_delivery_surfaces: list[str],
        required_trust_boundary_crossings: list[str],
        public_terminal_predicate_ids: list[str],
        safety_constraint_ids: list[str],
        model_hash: str,
        prompt_hash: str,
    ) -> None:
        self.objective_id = objective_id
        self.public_attack_goal = public_attack_goal
        self.allowed_delivery_surfaces = allowed_delivery_surfaces
        self.required_trust_boundary_crossings = required_trust_boundary_crossings
        self.public_terminal_predicate_ids = public_terminal_predicate_ids
        self.safety_constraint_ids = safety_constraint_ids
        self.model_hash = model_hash
        self.prompt_hash = prompt_hash

    def prepare(self, task: SourceInteractionTask, *, seed: int) -> ConstructionManifest:
        return ConstructionManifest(
            acquisition_mode="adversarial_trace",
            construction_objective_id=f"{self.objective_id}:{task.source_task_id}",
            public_attack_goal=self.public_attack_goal,
            allowed_delivery_surfaces=self.allowed_delivery_surfaces,
            required_trust_boundary_crossings=self.required_trust_boundary_crossings,
            public_terminal_predicate_ids=self.public_terminal_predicate_ids,
            safety_constraint_ids=self.safety_constraint_ids,
            construction_attacker_model_hash=self.model_hash,
            construction_prompt_hash=self.prompt_hash
            or stable_hash({"attacker_id": self.attacker_id, "seed": seed}),
        )

    def next_action(
        self,
        task: SourceInteractionTask,
        manifest: ConstructionManifest,
        observation: ConstructionObservation,
        *,
        seed: int,
    ) -> ConstructionAttackerAction:
        del task, manifest, seed
        return ConstructionAttackerAction(
            action_id=f"stop-{observation.session_index}",
            action_type="stop",
            rationale_summary="The deterministic fixture attacker does not generate live content.",
        )


class ModelConstructionAttacker:
    """Model-backed attacker restricted to public construction observations."""

    attacker_id = "model_construction_attacker_v1"

    def __init__(
        self,
        *,
        client: ModelClient,
        prompt_path: Path,
        objective_id: str,
        public_attack_goal: str,
        allowed_delivery_surfaces: list[str],
        required_trust_boundary_crossings: list[str],
        public_terminal_predicate_ids: list[str],
        safety_constraint_ids: list[str],
        model_hash: str,
    ) -> None:
        self.client = client
        self.prompt: PromptAsset = load_prompt(prompt_path)
        self.objective_id = objective_id
        self.public_attack_goal = public_attack_goal
        self.allowed_delivery_surfaces = allowed_delivery_surfaces
        self.required_trust_boundary_crossings = required_trust_boundary_crossings
        self.public_terminal_predicate_ids = public_terminal_predicate_ids
        self.safety_constraint_ids = safety_constraint_ids
        self.model_hash = model_hash

    def prepare(self, task: SourceInteractionTask, *, seed: int) -> ConstructionManifest:
        del seed
        return ConstructionManifest(
            acquisition_mode="adversarial_trace",
            construction_objective_id=f"{self.objective_id}:{task.source_task_id}",
            public_attack_goal=self.public_attack_goal,
            allowed_delivery_surfaces=self.allowed_delivery_surfaces,
            required_trust_boundary_crossings=self.required_trust_boundary_crossings,
            public_terminal_predicate_ids=self.public_terminal_predicate_ids,
            safety_constraint_ids=self.safety_constraint_ids,
            construction_attacker_model_hash=self.model_hash,
            construction_prompt_hash=self.prompt.hash,
        )

    def next_action(
        self,
        task: SourceInteractionTask,
        manifest: ConstructionManifest,
        observation: ConstructionObservation,
        *,
        seed: int,
    ) -> ConstructionAttackerAction:
        payload = {
            "construction_task": task.model_dump(mode="json"),
            "construction_manifest": manifest.model_dump(mode="json"),
            "public_observation": observation.model_dump(mode="json"),
        }
        try:
            value = self.client.generate(
                [
                    {"role": "system", "content": self.prompt.body},
                    {"role": "user", "content": json.dumps(payload, sort_keys=True)},
                ],
                ConstructionAttackerAction,
                seed=seed + observation.action_index,
                timeout=60,
            )
        except ModelCallError:
            return ConstructionAttackerAction(
                action_id=f"model-error-stop-{observation.session_index}",
                action_type="stop",
                rationale_summary="The attacker model call failed; collection stops fail closed.",
            )
        if not isinstance(value, ConstructionAttackerAction):
            raise TypeError("construction_attacker_response_type_mismatch")
        if (
            value.delivery_surface is not None
            and value.delivery_surface not in manifest.allowed_delivery_surfaces
        ):
            raise ValueError("construction_attacker_used_disallowed_surface")
        if value.retry_id is not None and value.retry_id not in observation.legal_retry_ids:
            raise ValueError("construction_attacker_used_illegal_retry")
        if value.reroute_id is not None and value.reroute_id not in observation.legal_reroute_ids:
            raise ValueError("construction_attacker_used_illegal_reroute")
        if (
            value.expected_public_predicate_id is not None
            and value.expected_public_predicate_id not in manifest.public_terminal_predicate_ids
        ):
            raise ValueError("construction_attacker_referenced_unknown_public_predicate")
        return value
