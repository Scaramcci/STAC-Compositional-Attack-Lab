from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Literal, cast

from stac_attack_lab.hashing import file_hash, stable_hash
from stac_attack_lab.interactions.base import (
    CollectedInteraction,
    CollectionBudget,
    SourceInteractionTask,
)
from stac_attack_lab.interactions.models import InteractionGraph, RawInteractionTrajectory
from stac_attack_lab.interactions.normalizer import normalize_source_events


class JsonlFixtureInteractionAdapter:
    adapter_id = "jsonl_authorized_fixture"
    adapter_version = "1.0.0"
    environment_version = "synthetic-construction-v1"

    def __init__(self, fixture_path: Path) -> None:
        self.fixture_path = fixture_path
        self._rows = self._load_rows()

    def _load_rows(self) -> dict[str, dict[str, Any]]:
        rows: dict[str, dict[str, Any]] = {}
        for line_number, line in enumerate(
            self.fixture_path.read_text(encoding="utf-8").splitlines(), start=1
        ):
            if not line.strip():
                continue
            value = json.loads(line)
            if not isinstance(value, dict):
                raise ValueError(f"fixture_row_not_object:{line_number}")
            task_id = str(value["source_task_id"])
            if task_id in rows:
                raise ValueError(f"duplicate_fixture_task_id:{task_id}")
            rows[task_id] = value
        return rows

    def inventory(self) -> list[SourceInteractionTask]:
        return [
            SourceInteractionTask(
                source_task_id=task_id,
                source_split=cast(
                    Literal["train", "dev", "test", "synthetic"],
                    str(row.get("source_split", "synthetic")),
                ),
                public_summary=str(row["public_summary"]),
                environment_family=str(row.get("environment_family", "synthetic")),
                metadata={str(key): str(value) for key, value in row.get("metadata", {}).items()},
            )
            for task_id, row in sorted(self._rows.items())
        ]

    def collect(
        self, task: SourceInteractionTask, *, seed: int, budget: CollectionBudget
    ) -> CollectedInteraction:
        row = self._rows[task.source_task_id]
        events = list(row.get("source_events", []))
        if len(events) > budget.max_events:
            raise ValueError("fixture_event_budget_exceeded")
        return CollectedInteraction(
            source_task=task,
            episode_id=str(row.get("episode_id", f"episode-{task.source_task_id}-{seed}")),
            session_ids=[str(item) for item in row.get("session_ids", ["session-1"])],
            source_events=events,
            checkpoints=list(row.get("checkpoints", [])),
            model_hashes={
                str(key): str(value) for key, value in row.get("model_hashes", {}).items()
            },
            config_hash=stable_hash(
                {
                    "fixture_hash": file_hash(self.fixture_path),
                    "task_id": task.source_task_id,
                    "seed": seed,
                }
            ),
            status=cast(
                Literal["complete", "partial", "blocked", "error"],
                str(row.get("status", "complete")),
            ),
            failure_category=row.get("failure_category"),
            provenance={
                "fixture_path": str(self.fixture_path),
                "fixture_hash": file_hash(self.fixture_path),
                "authorization_scope": "project_synthetic_fixture",
            },
        )

    def normalize(
        self, trajectory: RawInteractionTrajectory, artifact_root: str
    ) -> InteractionGraph:
        row = self._rows[trajectory.source_task_id]
        graph, _ = normalize_source_events(
            trajectory,
            list(row.get("source_events", [])),
            audit_ref=f"{artifact_root}/normalization_audit.json",
        )
        return graph
