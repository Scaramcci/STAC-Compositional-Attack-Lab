from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any, cast

from pydantic import Field, model_validator

from stac_attack_lab.contracts import StrictModel
from stac_attack_lab.hashing import file_hash, stable_hash
from stac_attack_lab.interactions.base import (
    AdversarialInteractionSourceAdapter,
    CollectedInteraction,
    CollectionBudget,
    InteractionSourceAdapter,
    SourceInteractionTask,
)
from stac_attack_lab.interactions.construction import ConstructionAttacker
from stac_attack_lab.interactions.models import (
    ConstructionManifest,
    RawInteractionTrajectory,
    SourceReference,
)


class InteractionCollectionPlan(StrictModel):
    collection_id: str
    source_task_ids: list[str]
    allowed_source_splits: list[str] = Field(default_factory=lambda: ["train", "dev", "synthetic"])
    formal_excluded_task_ids: list[str] = Field(default_factory=list)
    seed: int
    budget: CollectionBudget = Field(default_factory=CollectionBudget)

    @model_validator(mode="after")
    def validate_split_policy(self) -> InteractionCollectionPlan:
        if "test" in self.allowed_source_splits:
            raise ValueError("formal_test_split_cannot_be_a_construction_source")
        overlap = set(self.source_task_ids) & set(self.formal_excluded_task_ids)
        if overlap:
            raise ValueError("formal_excluded_task_requested:" + ",".join(sorted(overlap)))
        if len(self.source_task_ids) != len(set(self.source_task_ids)):
            raise ValueError("duplicate_source_task_id")
        return self


@dataclass(frozen=True)
class CollectionSummary:
    collection_root: Path
    trajectory_paths: tuple[Path, ...]
    skipped_trajectory_ids: tuple[str, ...]
    failure_count: int


def _atomic_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(json.dumps(value, indent=2, sort_keys=True), encoding="utf-8")
    temporary.replace(path)


def _atomic_jsonl(path: Path, values: list[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".tmp")
    payload = "".join(json.dumps(value, sort_keys=True) + "\n" for value in values)
    temporary.write_text(payload, encoding="utf-8")
    temporary.replace(path)


def _trajectory_id(
    adapter: InteractionSourceAdapter,
    task: SourceInteractionTask,
    seed: int,
    construction_manifest: ConstructionManifest | None,
) -> str:
    digest = stable_hash(
        {
            "adapter": adapter.adapter_id,
            "adapter_version": adapter.adapter_version,
            "task": task.source_task_id,
            "split": task.source_split,
            "seed": seed,
            "construction_manifest": (
                construction_manifest.model_dump(mode="json")
                if construction_manifest is not None
                else None
            ),
        }
    )[:16]
    return f"trajectory-{task.source_task_id}-{digest}"


def _write_collected(
    root: Path,
    adapter: InteractionSourceAdapter,
    collected: CollectedInteraction,
    trajectory_id: str,
    seed: int,
    construction_manifest: ConstructionManifest | None,
) -> Path:
    trajectory_root = root / "trajectories" / trajectory_id
    events_path = trajectory_root / "source_events.jsonl"
    checkpoints_path = trajectory_root / "checkpoints.jsonl"
    _atomic_jsonl(events_path, collected.source_events)
    _atomic_jsonl(checkpoints_path, collected.checkpoints)

    event_ref = SourceReference(
        ref_id=f"{trajectory_id}:events",
        kind="source_events",
        relative_path=str(events_path.relative_to(root)),
        content_hash=file_hash(events_path),
    )
    checkpoint_refs = []
    if collected.checkpoints:
        checkpoint_refs.append(
            SourceReference(
                ref_id=f"{trajectory_id}:checkpoints",
                kind="state_checkpoints",
                relative_path=str(checkpoints_path.relative_to(root)),
                content_hash=file_hash(checkpoints_path),
            )
        )
    outcome_by_status = {
        "complete": "completed",
        "partial": "partial",
        "blocked": "blocked",
        "error": "error",
    }
    finalized_manifest = (
        construction_manifest.model_copy(
            update={"attempt_outcome": outcome_by_status[collected.status]}
        )
        if construction_manifest is not None
        else None
    )
    trajectory = RawInteractionTrajectory(
        trajectory_id=trajectory_id,
        source_adapter_id=adapter.adapter_id,
        source_adapter_version=adapter.adapter_version,
        source_environment_family=collected.source_task.environment_family,
        source_environment_version=adapter.environment_version,
        source_task_id=collected.source_task.source_task_id,
        source_split=collected.source_task.source_split,
        episode_id=collected.episode_id,
        session_ids=collected.session_ids,
        event_refs=[event_ref],
        checkpoint_refs=checkpoint_refs,
        model_hashes=collected.model_hashes,
        config_hash=collected.config_hash,
        collection_seed=seed,
        collection_status=collected.status,
        failure_category=collected.failure_category,
        construction_manifest=finalized_manifest,
        provenance=collected.provenance,
    )
    target = trajectory_root / "raw_trajectory.json"
    _atomic_json(target, trajectory.model_dump(mode="json"))
    return target


def collect_interactions(
    plan: InteractionCollectionPlan,
    adapter: InteractionSourceAdapter,
    output_root: Path,
    construction_attacker: ConstructionAttacker | None = None,
) -> CollectionSummary:
    inventory = {task.source_task_id: task for task in adapter.inventory()}
    unknown = set(plan.source_task_ids) - set(inventory)
    if unknown:
        raise ValueError("unknown_source_tasks:" + ",".join(sorted(unknown)))
    root = output_root / plan.collection_id
    root.mkdir(parents=True, exist_ok=True)
    trajectory_paths: list[Path] = []
    skipped: list[str] = []
    failures: list[dict[str, str]] = []
    for source_task_id in plan.source_task_ids:
        task = inventory[source_task_id]
        if task.source_split not in plan.allowed_source_splits:
            raise ValueError(f"source_split_not_allowed:{task.source_task_id}:{task.source_split}")
        construction_manifest = (
            construction_attacker.prepare(task, seed=plan.seed)
            if construction_attacker is not None
            else None
        )
        trajectory_id = _trajectory_id(adapter, task, plan.seed, construction_manifest)
        existing = root / "trajectories" / trajectory_id / "raw_trajectory.json"
        if existing.is_file():
            RawInteractionTrajectory.model_validate_json(existing.read_text(encoding="utf-8"))
            trajectory_paths.append(existing)
            skipped.append(trajectory_id)
            continue
        try:
            if construction_attacker is not None and hasattr(adapter, "collect_adversarial"):
                adversarial_adapter = cast(AdversarialInteractionSourceAdapter, adapter)
                if construction_manifest is None:
                    raise ValueError("adversarial_collection_manifest_missing")
                collected = adversarial_adapter.collect_adversarial(
                    task,
                    construction_manifest,
                    construction_attacker,
                    seed=plan.seed,
                    budget=plan.budget,
                )
            else:
                collected = adapter.collect(task, seed=plan.seed, budget=plan.budget)
            if len(collected.source_events) > plan.budget.max_events:
                raise ValueError("source_event_budget_exceeded")
            path = _write_collected(
                root,
                adapter,
                collected,
                trajectory_id,
                plan.seed,
                construction_manifest,
            )
            trajectory_paths.append(path)
            if collected.status == "error":
                failures.append(
                    {
                        "trajectory_id": trajectory_id,
                        "reason": collected.failure_category or "error",
                    }
                )
        except Exception as exc:
            failures.append({"trajectory_id": trajectory_id, "reason": type(exc).__name__})
            error_event = {
                "event_id": f"collection-error-{trajectory_id}",
                "session_id": "collection-error",
                "sequence_no": 1,
                "actor_role": "collector",
                "event_type": "lifecycle",
                "component_role": "session_lifecycle",
                "operation": "stop_collection_error",
                "status": "error",
                "lifecycle_id": trajectory_id,
                "public_payload": {"failure_category": type(exc).__name__},
                "evidence_ref_ids": [f"collection_failure:{trajectory_id}"],
            }
            error_collected = CollectedInteraction(
                source_task=task,
                episode_id=f"error-{trajectory_id}",
                session_ids=["collection-error"],
                source_events=[error_event],
                checkpoints=[],
                model_hashes={},
                config_hash=stable_hash(
                    {"plan": plan.model_dump(mode="json"), "trajectory_id": trajectory_id}
                ),
                status="error",
                failure_category=type(exc).__name__,
                provenance={
                    "collector_error_record": "true",
                    "exception_message_recorded": "false",
                },
            )
            path = _write_collected(
                root,
                adapter,
                error_collected,
                trajectory_id,
                plan.seed,
                construction_manifest,
            )
            trajectory_paths.append(path)
            _atomic_jsonl(root / "collection_failures.jsonl", failures)
    manifest = {
        "schema_version": "2.0",
        "collection_id": plan.collection_id,
        "adapter_id": adapter.adapter_id,
        "adapter_version": adapter.adapter_version,
        "acquisition_mode": (
            "adversarial_trace" if construction_attacker is not None else "ordinary_trace"
        ),
        "construction_attacker_id": (
            construction_attacker.attacker_id if construction_attacker is not None else None
        ),
        "plan_hash": stable_hash(plan.model_dump(mode="json")),
        "trajectory_count": len(trajectory_paths),
        "failure_count": len(failures),
        "formal_exclusion_hash": stable_hash(sorted(plan.formal_excluded_task_ids)),
        "trajectory_hashes": {
            path.parent.name: file_hash(path) for path in sorted(trajectory_paths)
        },
    }
    _atomic_json(root / "collection_manifest.json", manifest)
    return CollectionSummary(root, tuple(trajectory_paths), tuple(skipped), len(failures))
