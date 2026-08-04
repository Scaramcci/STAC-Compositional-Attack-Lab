from __future__ import annotations

import json
import os
from datetime import UTC, datetime
from enum import StrEnum
from pathlib import Path
from tempfile import NamedTemporaryFile
from typing import Any, Literal

from pydantic import NonNegativeInt

from stac_attack_lab.contracts import StrictModel
from stac_attack_lab.hashing import stable_hash
from stac_attack_lab.recording.events import append_jsonl


class AttackProgressStatus(StrEnum):
    pending = "pending"
    running = "running"
    completed = "completed"
    failed_retryable = "failed_retryable"
    failed_terminal = "failed_terminal"
    paused_quota = "paused_quota"


class AttackCaseProgress(StrictModel):
    attack_id: str
    idempotency_key: str
    condition: str
    seed: int
    status: AttackProgressStatus = AttackProgressStatus.pending
    attempts: NonNegativeInt = 0
    last_error_category: str | None = None
    result_ref: str | None = None
    updated_at: datetime


class ExperimentProgress(StrictModel):
    schema_version: Literal["1.0"] = "1.0"
    run_id: str
    profile: str
    dataset_version: str
    config_hash: str
    started_at: datetime
    updated_at: datetime
    total: NonNegativeInt
    completed: NonNegativeInt
    failed: NonNegativeInt
    pending: NonNegativeInt
    last_completed_attack_id: str | None = None
    pause_reason: str | None = None
    attacks: list[AttackCaseProgress]


class ProgressTransition(StrictModel):
    schema_version: Literal["1.0"] = "1.0"
    run_id: str
    attack_id: str
    idempotency_key: str
    previous_status: AttackProgressStatus
    status: AttackProgressStatus
    attempt: NonNegativeInt
    timestamp: datetime
    error_category: str | None = None
    result_ref: str | None = None


def attack_idempotency_key(
    *,
    run_id: str,
    config_hash: str,
    dataset_version: str,
    attack_id: str,
    condition: str,
    seed: int,
) -> str:
    return stable_hash(
        {
            "run_id": run_id,
            "config_hash": config_hash,
            "dataset_version": dataset_version,
            "attack_id": attack_id,
            "condition": condition,
            "seed": seed,
        }
    )


def _atomic_json(path: Path, value: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with NamedTemporaryFile("w", encoding="utf-8", dir=path.parent, delete=False) as handle:
        json.dump(value, handle, indent=2, sort_keys=True)
        handle.write("\n")
        handle.flush()
        os.fsync(handle.fileno())
        temporary = Path(handle.name)
    os.replace(temporary, path)
    directory_fd = os.open(path.parent, os.O_RDONLY)
    try:
        os.fsync(directory_fd)
    finally:
        os.close(directory_fd)


class ProgressManager:
    def __init__(self, run_dir: Path, project_root: Path) -> None:
        self.run_dir = run_dir
        self.project_root = project_root
        self.progress_path = run_dir / "progress.json"
        self.transitions_path = run_dir / "attack_progress.jsonl"
        self.ledger_path = project_root / "EXPERIMENT_PROGRESS.md"

    def initialize(
        self,
        *,
        run_id: str,
        profile: str,
        dataset_version: str,
        config_hash: str,
        cases: list[tuple[str, str, int]],
    ) -> ExperimentProgress:
        if self.progress_path.exists():
            progress = self.load()
            expected = (run_id, profile, dataset_version, config_hash)
            actual = (
                progress.run_id,
                progress.profile,
                progress.dataset_version,
                progress.config_hash,
            )
            if actual != expected:
                raise ValueError("resume_configuration_mismatch")
            return progress
        now = datetime.now(UTC)
        attacks = [
            AttackCaseProgress(
                attack_id=attack_id,
                idempotency_key=attack_idempotency_key(
                    run_id=run_id,
                    config_hash=config_hash,
                    dataset_version=dataset_version,
                    attack_id=attack_id,
                    condition=condition,
                    seed=seed,
                ),
                condition=condition,
                seed=seed,
                updated_at=now,
            )
            for attack_id, condition, seed in cases
        ]
        progress = ExperimentProgress(
            run_id=run_id,
            profile=profile,
            dataset_version=dataset_version,
            config_hash=config_hash,
            started_at=now,
            updated_at=now,
            total=len(attacks),
            completed=0,
            failed=0,
            pending=len(attacks),
            attacks=attacks,
        )
        self._persist(progress)
        return progress

    def load(self) -> ExperimentProgress:
        return ExperimentProgress.model_validate_json(
            self.progress_path.read_text(encoding="utf-8")
        )

    def get(self, idempotency_key: str) -> AttackCaseProgress:
        return next(
            attack for attack in self.load().attacks if attack.idempotency_key == idempotency_key
        )

    def incomplete(self) -> list[AttackCaseProgress]:
        terminal = {AttackProgressStatus.completed, AttackProgressStatus.failed_terminal}
        return [attack for attack in self.load().attacks if attack.status not in terminal]

    def transition(
        self,
        idempotency_key: str,
        status: AttackProgressStatus,
        *,
        error_category: str | None = None,
        result_ref: str | None = None,
        pause_reason: str | None = None,
    ) -> ExperimentProgress:
        progress = self.load()
        index = next(
            i
            for i, attack in enumerate(progress.attacks)
            if attack.idempotency_key == idempotency_key
        )
        current = progress.attacks[index]
        if current.status == AttackProgressStatus.completed and status != current.status:
            raise ValueError("completed_attack_is_immutable")
        now = datetime.now(UTC)
        attempts = current.attempts + (1 if status == AttackProgressStatus.running else 0)
        updated = current.model_copy(
            update={
                "status": status,
                "attempts": attempts,
                "last_error_category": error_category,
                "result_ref": result_ref or current.result_ref,
                "updated_at": now,
            }
        )
        attacks = list(progress.attacks)
        attacks[index] = updated
        completed = sum(item.status == AttackProgressStatus.completed for item in attacks)
        failed = sum(
            item.status
            in {AttackProgressStatus.failed_retryable, AttackProgressStatus.failed_terminal}
            for item in attacks
        )
        pending = (
            len(attacks)
            - completed
            - sum(item.status == AttackProgressStatus.failed_terminal for item in attacks)
        )
        progress = progress.model_copy(
            update={
                "attacks": attacks,
                "updated_at": now,
                "completed": completed,
                "failed": failed,
                "pending": pending,
                "last_completed_attack_id": (
                    current.attack_id
                    if status == AttackProgressStatus.completed
                    else progress.last_completed_attack_id
                ),
                "pause_reason": pause_reason,
            }
        )
        transition = ProgressTransition(
            run_id=progress.run_id,
            attack_id=current.attack_id,
            idempotency_key=idempotency_key,
            previous_status=current.status,
            status=status,
            attempt=attempts,
            timestamp=now,
            error_category=error_category,
            result_ref=result_ref,
        )
        append_jsonl(self.transitions_path, transition.model_dump(mode="json"))
        self._persist(progress)
        return progress

    def _persist(self, progress: ExperimentProgress) -> None:
        _atomic_json(self.progress_path, progress.model_dump(mode="json"))
        self._write_ledger(progress)

    def _write_ledger(self, progress: ExperimentProgress) -> None:
        lines = [
            "# Experiment Progress",
            "",
            f"- Run id: `{progress.run_id}`",
            f"- Profile: `{progress.profile}`",
            f"- Dataset version: `{progress.dataset_version}`",
            f"- Config hash: `{progress.config_hash}`",
            f"- Started: `{progress.started_at.isoformat()}`",
            f"- Updated: `{progress.updated_at.isoformat()}`",
            (
                f"- Counts: total={progress.total}, completed={progress.completed}, "
                f"failed={progress.failed}, pending={progress.pending}"
            ),
            f"- Last completed attack: `{progress.last_completed_attack_id or 'none'}`",
            f"- Pause reason: `{progress.pause_reason or 'none'}`",
            "",
            "| Attack | Condition | Seed | Status | Attempts | Error category |",
            "|---|---|---:|---|---:|---|",
        ]
        lines.extend(
            (
                f"| {item.attack_id} | {item.condition} | {item.seed} | {item.status.value} | "
                f"{item.attempts} | {item.last_error_category or ''} |"
            )
            for item in progress.attacks
        )
        ledger_text = "\n".join(lines) + "\n"
        temporary = self.ledger_path.with_suffix(".tmp")
        temporary.write_text(ledger_text, encoding="utf-8")
        with temporary.open("r+", encoding="utf-8") as handle:
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, self.ledger_path)
