from __future__ import annotations

from typing import TYPE_CHECKING, Any, Literal, Protocol

from pydantic import Field, PositiveInt, model_validator

from stac_attack_lab.contracts import StrictModel
from stac_attack_lab.interactions.models import InteractionGraph, RawInteractionTrajectory

if TYPE_CHECKING:
    from stac_attack_lab.interactions.construction import ConstructionAttacker
    from stac_attack_lab.interactions.models import ConstructionManifest


class SourceInteractionTask(StrictModel):
    source_task_id: str
    source_split: Literal["train", "dev", "test", "synthetic"]
    public_summary: str
    environment_family: str
    metadata: dict[str, str] = Field(default_factory=dict)


class CollectionBudget(StrictModel):
    max_sessions: PositiveInt = 4
    max_turns: PositiveInt = 8
    max_actions: PositiveInt = 12
    max_tool_calls: PositiveInt = 16
    max_tokens: PositiveInt = 8192
    max_wall_time_seconds: PositiveInt = 1200
    max_events: PositiveInt = 200
    timeout_seconds: PositiveInt = 300

    @model_validator(mode="after")
    def validate_independent_limits(self) -> CollectionBudget:
        if self.max_turns < self.max_sessions:
            raise ValueError("collection_turn_budget_below_session_budget")
        if self.max_actions < self.max_turns:
            raise ValueError("collection_action_budget_below_turn_budget")
        if self.timeout_seconds > self.max_wall_time_seconds:
            raise ValueError("collection_request_timeout_exceeds_wall_time_budget")
        return self


class CollectedInteraction(StrictModel):
    source_task: SourceInteractionTask
    episode_id: str
    session_ids: list[str]
    source_events: list[dict[str, Any]]
    checkpoints: list[dict[str, Any]]
    model_hashes: dict[str, str]
    config_hash: str
    status: Literal["complete", "partial", "blocked", "error"]
    failure_category: str | None = None
    provenance: dict[str, str]


class InteractionSourceAdapter(Protocol):
    adapter_id: str
    adapter_version: str
    environment_version: str

    def inventory(self) -> list[SourceInteractionTask]: ...

    def collect(
        self, task: SourceInteractionTask, *, seed: int, budget: CollectionBudget
    ) -> CollectedInteraction: ...

    def normalize(
        self, trajectory: RawInteractionTrajectory, artifact_root: str
    ) -> InteractionGraph: ...


class AdversarialInteractionSourceAdapter(InteractionSourceAdapter, Protocol):
    def collect_adversarial(
        self,
        task: SourceInteractionTask,
        manifest: ConstructionManifest,
        attacker: ConstructionAttacker,
        *,
        seed: int,
        budget: CollectionBudget,
    ) -> CollectedInteraction: ...
