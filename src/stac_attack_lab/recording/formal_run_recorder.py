from __future__ import annotations

import json
import os
from datetime import UTC, datetime
from enum import StrEnum
from pathlib import Path
from tempfile import NamedTemporaryFile
from typing import Any, Literal

from pydantic import Field, NonNegativeInt

from stac_attack_lab.contracts import StrictModel
from stac_attack_lab.environments.safeclaw.redaction import scan_for_secrets, scan_tree
from stac_attack_lab.hashing import file_hash
from stac_attack_lab.recording.events import append_jsonl, read_jsonl
from stac_attack_lab.verification.formal_models import FormalRunResult


class FormalStage(StrEnum):
    pending = "pending"
    planned = "planned"
    materialized = "materialized"
    executed = "executed"
    normalized = "normalized"
    verified = "verified"
    recorded = "recorded"


STAGE_ORDER = {stage: index for index, stage in enumerate(FormalStage)}


class FormalArtifactRecord(StrictModel):
    artifact_name: str
    stage: FormalStage
    relative_path: str
    content_hash: str


class FormalCaseProgress(StrictModel):
    case_id: str
    pair_id: str
    task_id: str
    condition: str
    seed: int
    stage: FormalStage = FormalStage.pending
    attempt_count: NonNegativeInt = 0
    artifacts: dict[str, FormalArtifactRecord] = Field(default_factory=dict)
    result_ref: str | None = None
    last_error_category: str | None = None
    updated_at: str


class FormalProgressSnapshot(StrictModel):
    schema_version: Literal["2.0"] = "2.0"
    run_id: str
    config_hash: str
    cases: list[FormalCaseProgress]
    updated_at: str


class FormalStageTransition(StrictModel):
    schema_version: Literal["2.0"] = "2.0"
    run_id: str
    case_id: str
    previous_stage: FormalStage
    stage: FormalStage
    timestamp: str
    artifact_names: list[str]
    error_category: str | None = None


class FormalRunManifest(StrictModel):
    schema_version: Literal["2.0"] = "2.0"
    run_id: str
    experiment_id: str
    track: str
    config_hash: str
    library_version: str
    library_hash: str
    registry_hash: str
    upstream_commit: str
    safety_patch_hash: str
    target_model_id: str
    environment_variable_names: list[str]
    case_ids: list[str]
    created_at: str


class FormalRecorderAudit(StrictModel):
    passed: bool
    finding_codes: list[str]
    checked_artifact_count: NonNegativeInt
    result_count: NonNegativeInt


def _now() -> str:
    return datetime.now(UTC).isoformat()


def _atomic_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with NamedTemporaryFile("w", encoding="utf-8", dir=path.parent, delete=False) as handle:
        json.dump(value, handle, indent=2, sort_keys=True)
        handle.write("\n")
        handle.flush()
        os.fsync(handle.fileno())
        temporary = Path(handle.name)
    os.replace(temporary, path)


class FormalRunRecorder:
    def __init__(self, run_root: Path, exact_secrets: list[str] | None = None) -> None:
        self.run_root = run_root
        self.exact_secrets = [item for item in (exact_secrets or []) if item]
        self.manifest_path = run_root / "formal_run_manifest.json"
        self.progress_path = run_root / "formal_progress.json"
        self.transitions_path = run_root / "formal_transitions.jsonl"
        self.results_path = run_root / "results.jsonl"

    def initialize(
        self,
        manifest: FormalRunManifest,
        cases: list[tuple[str, str, str, str, int]],
    ) -> FormalProgressSnapshot:
        self.run_root.mkdir(parents=True, exist_ok=True)
        if self.manifest_path.exists():
            existing = FormalRunManifest.model_validate_json(
                self.manifest_path.read_text(encoding="utf-8")
            )
            immutable = (
                existing.run_id,
                existing.config_hash,
                existing.library_hash,
                existing.registry_hash,
                existing.case_ids,
            )
            expected = (
                manifest.run_id,
                manifest.config_hash,
                manifest.library_hash,
                manifest.registry_hash,
                manifest.case_ids,
            )
            if immutable != expected:
                raise ValueError("formal_resume_manifest_mismatch")
            return self.load_progress()
        if manifest.case_ids != [case_id for case_id, *_ in cases]:
            raise ValueError("formal_manifest_case_order_mismatch")
        if scan_for_secrets(manifest.model_dump(mode="json"), self.exact_secrets):
            raise ValueError("formal_manifest_secret_gate_failed")
        now = _now()
        progress = FormalProgressSnapshot(
            run_id=manifest.run_id,
            config_hash=manifest.config_hash,
            cases=[
                FormalCaseProgress(
                    case_id=case_id,
                    pair_id=pair_id,
                    task_id=task_id,
                    condition=condition,
                    seed=seed,
                    updated_at=now,
                )
                for case_id, pair_id, task_id, condition, seed in cases
            ],
            updated_at=now,
        )
        _atomic_json(self.manifest_path, manifest.model_dump(mode="json"))
        _atomic_json(self.progress_path, progress.model_dump(mode="json"))
        return progress

    def load_progress(self) -> FormalProgressSnapshot:
        return FormalProgressSnapshot.model_validate_json(
            self.progress_path.read_text(encoding="utf-8")
        )

    def incomplete_cases(self) -> list[FormalCaseProgress]:
        return [case for case in self.load_progress().cases if case.stage != FormalStage.recorded]

    def _case(self, progress: FormalProgressSnapshot, case_id: str) -> FormalCaseProgress:
        try:
            return next(case for case in progress.cases if case.case_id == case_id)
        except StopIteration as exc:
            raise KeyError(f"unknown_formal_case:{case_id}") from exc

    def record_artifact(
        self,
        case_id: str,
        stage: FormalStage,
        artifact_name: str,
        value: StrictModel | dict[str, Any] | list[Any],
    ) -> FormalArtifactRecord:
        payload = value.model_dump(mode="json") if isinstance(value, StrictModel) else value
        if scan_for_secrets(payload, self.exact_secrets):
            raise ValueError(f"formal_artifact_secret_gate_failed:{artifact_name}")
        progress = self.load_progress()
        current = self._case(progress, case_id)
        if STAGE_ORDER[stage] < STAGE_ORDER[current.stage]:
            existing = current.artifacts.get(artifact_name)
            if existing is not None:
                path = self.run_root / existing.relative_path
                candidate = json.dumps(payload, indent=2, sort_keys=True) + "\n"
                if path.is_file() and path.read_text(encoding="utf-8") == candidate:
                    return existing
            raise ValueError("formal_stage_regression")
        target = self.run_root / "cases" / case_id / f"{artifact_name}.json"
        artifacts = dict(current.artifacts)
        existing = artifacts.get(artifact_name)
        candidate = json.dumps(payload, indent=2, sort_keys=True) + "\n"
        if existing is not None:
            existing_path = self.run_root / existing.relative_path
            if existing_path.is_file() and existing_path.read_text(encoding="utf-8") == candidate:
                return existing
            raise ValueError(f"formal_artifact_immutable:{artifact_name}")
        _atomic_json(target, payload)
        record = FormalArtifactRecord(
            artifact_name=artifact_name,
            stage=stage,
            relative_path=str(target.relative_to(self.run_root)),
            content_hash=file_hash(target),
        )
        artifacts[artifact_name] = record
        self._advance(progress, current, stage, artifacts=artifacts)
        return record

    def mark_error(self, case_id: str, category: str) -> FormalProgressSnapshot:
        progress = self.load_progress()
        current = self._case(progress, case_id)
        return self._advance(
            progress,
            current,
            current.stage,
            artifacts=current.artifacts,
            error_category=category,
            increment_attempt=True,
        )

    def finalize_result(self, result: FormalRunResult) -> FormalProgressSnapshot:
        record = self.record_artifact(result.case_id, FormalStage.verified, "formal_result", result)
        existing_results = [
            FormalRunResult.model_validate(item) for item in read_jsonl(self.results_path)
        ]
        by_case = {item.case_id: item for item in existing_results}
        existing = by_case.get(result.case_id)
        if existing is not None and existing != result:
            raise ValueError("formal_result_immutable")
        if existing is None:
            append_jsonl(self.results_path, result.model_dump(mode="json"))
        progress = self.load_progress()
        current = self._case(progress, result.case_id)
        return self._advance(
            progress,
            current,
            FormalStage.recorded,
            artifacts=current.artifacts,
            result_ref=record.relative_path,
        )

    def _advance(
        self,
        progress: FormalProgressSnapshot,
        current: FormalCaseProgress,
        stage: FormalStage,
        *,
        artifacts: dict[str, FormalArtifactRecord],
        result_ref: str | None = None,
        error_category: str | None = None,
        increment_attempt: bool = False,
    ) -> FormalProgressSnapshot:
        if STAGE_ORDER[stage] < STAGE_ORDER[current.stage]:
            raise ValueError("formal_stage_regression")
        now = _now()
        updated_case = current.model_copy(
            update={
                "stage": stage,
                "attempt_count": current.attempt_count + int(increment_attempt),
                "artifacts": artifacts,
                "result_ref": result_ref or current.result_ref,
                "last_error_category": error_category,
                "updated_at": now,
            }
        )
        cases = [
            updated_case if case.case_id == current.case_id else case for case in progress.cases
        ]
        updated = progress.model_copy(update={"cases": cases, "updated_at": now})
        transition = FormalStageTransition(
            run_id=progress.run_id,
            case_id=current.case_id,
            previous_stage=current.stage,
            stage=stage,
            timestamp=now,
            artifact_names=sorted(artifacts),
            error_category=error_category,
        )
        append_jsonl(self.transitions_path, transition.model_dump(mode="json"))
        _atomic_json(self.progress_path, updated.model_dump(mode="json"))
        return updated

    def audit(self) -> FormalRecorderAudit:
        findings: list[str] = []
        checked = 0
        try:
            progress = self.load_progress()
            FormalRunManifest.model_validate_json(self.manifest_path.read_text(encoding="utf-8"))
        except Exception:
            return FormalRecorderAudit(
                passed=False,
                finding_codes=["formal_manifest_or_progress_invalid"],
                checked_artifact_count=0,
                result_count=0,
            )
        root = self.run_root.resolve()
        for case in progress.cases:
            for artifact in case.artifacts.values():
                path = (self.run_root / artifact.relative_path).resolve()
                if path != root and root not in path.parents:
                    findings.append(f"artifact_path_escape:{case.case_id}:{artifact.artifact_name}")
                    continue
                if not path.is_file():
                    findings.append(f"artifact_missing:{case.case_id}:{artifact.artifact_name}")
                    continue
                checked += 1
                if file_hash(path) != artifact.content_hash:
                    findings.append(
                        f"artifact_hash_mismatch:{case.case_id}:{artifact.artifact_name}"
                    )
        results: list[FormalRunResult] = []
        try:
            results = [
                FormalRunResult.model_validate(item) for item in read_jsonl(self.results_path)
            ]
        except Exception:
            findings.append("formal_results_schema_invalid")
        result_cases = [result.case_id for result in results]
        if len(result_cases) != len(set(result_cases)):
            findings.append("duplicate_formal_result_case")
        findings.extend(f"secret_scan:{item}" for item in scan_tree(root, self.exact_secrets))
        return FormalRecorderAudit(
            passed=not findings,
            finding_codes=sorted(findings),
            checked_artifact_count=checked,
            result_count=len(results),
        )
