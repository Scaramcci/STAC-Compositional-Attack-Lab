from __future__ import annotations

from typing import TYPE_CHECKING, Any, Literal, Protocol

from pydantic import Field, PositiveInt

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
    max_events: PositiveInt = 200
    timeout_seconds: PositiveInt = 300


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
