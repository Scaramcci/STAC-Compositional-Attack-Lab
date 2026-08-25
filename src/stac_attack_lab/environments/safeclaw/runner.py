from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import tempfile
import time
from collections.abc import Callable, Mapping
from datetime import UTC, datetime
from pathlib import Path

from stac_attack_lab.environments.safeclaw.contracts import (
    EpisodeRequest,
    SafeClawEpisodeResult,
    SafeClawExecutionStatus,
    SanitizedSessionResult,
)
from stac_attack_lab.environments.safeclaw.materializer import MaterializedTask
from stac_attack_lab.environments.safeclaw.model_config import build_safeclaw_model_config
from stac_attack_lab.environments.safeclaw.redaction import redact_value, scan_tree
from stac_attack_lab.hashing import file_hash

JudgeInvoker = Callable[[list[str], Path, int], subprocess.CompletedProcess[str]]


def _default_invoker(
    command: list[str], cwd: Path, timeout: int
) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        command,
        cwd=cwd,
        text=True,
        capture_output=True,
        timeout=timeout,
        check=False,
    )


def _now() -> str:
    return datetime.now(UTC).isoformat()


def _atomic_json(path: Path, value: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(json.dumps(value, indent=2, sort_keys=True), encoding="utf-8")
    temporary.replace(path)


def _classify_failure(log: str, timed_out: bool) -> tuple[SafeClawExecutionStatus, bool, str]:
    lowered = log.lower()
    if timed_out:
        return SafeClawExecutionStatus.timeout, False, "task_timeout"
    if any(token in lowered for token in ("429", "rate limit", "quota", "502", "503", "504")):
        return SafeClawExecutionStatus.api_error, True, "retryable_api_error"
    if any(token in lowered for token in ("gateway", "docker", "container")):
        return SafeClawExecutionStatus.environment_error, True, "retryable_environment_error"
    return SafeClawExecutionStatus.environment_error, False, "judge_subprocess_error"


class SafeClawRunner:
    runner_version = "safeclaw-formal-runner-v1"

    def __init__(
        self,
        *,
        upstream_root: Path,
        safety_patch: Path,
        output_root: Path,
        environment: Mapping[str, str] | None = None,
        invoker: JudgeInvoker = _default_invoker,
    ) -> None:
        self.upstream_root = upstream_root
        self.safety_patch = safety_patch
        self.output_root = output_root
        self.environment = environment if environment is not None else os.environ
        self.invoker = invoker

    def _cached(self, case_root: Path, request: EpisodeRequest) -> SafeClawEpisodeResult | None:
        result_path = case_root / "episode_result.json"
        if not result_path.is_file():
            return None
        result = SafeClawEpisodeResult.model_validate_json(result_path.read_text(encoding="utf-8"))
        if result.case_id != request.case_id or result.task_id != request.task_ref.task_id:
            raise ValueError("cached_safeclaw_result_identity_mismatch")
        return result

    def run_episode(
        self,
        request: EpisodeRequest,
        materialized_task: MaterializedTask,
        *,
        resume: bool = True,
    ) -> SafeClawEpisodeResult:
        case_root = self.output_root / request.case_id
        case_root.mkdir(parents=True, exist_ok=True)
        if resume and (cached := self._cached(case_root, request)) is not None:
            return cached
        model_config_payload, exact_secrets = build_safeclaw_model_config(
            target_model_id=request.target_model_id,
            target_base_url=request.target_base_url,
            target_api_key_env=request.target_api_key_env,
            environment=self.environment,
            embedding=request.embedding,
        )
        started_at = _now()
        started_monotonic = time.monotonic()
        final_status = SafeClawExecutionStatus.environment_error
        final_error: str | None = "no_attempt_completed"
        sanitized_result: dict[str, object] | None = None
        attempt_count = 0
        with tempfile.TemporaryDirectory(prefix="safeclaw-formal-") as temporary_name:
            temporary_root = Path(temporary_name)
            patched_upstream = temporary_root / "SafeClawArena"
            shutil.copytree(self.upstream_root, patched_upstream)
            check = self.invoker(
                ["git", "apply", "--unidiff-zero", "--check", str(self.safety_patch)],
                patched_upstream,
                60,
            )
            if check.returncode != 0:
                raise ValueError("safeclaw_safety_patch_check_failed")
            apply_result = self.invoker(
                ["git", "apply", "--unidiff-zero", str(self.safety_patch)], patched_upstream, 60
            )
            if apply_result.returncode != 0:
                raise ValueError("safeclaw_safety_patch_apply_failed")
            task_path = patched_upstream / "tasks/formal" / materialized_task.path.name
            task_path.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(materialized_task.path, task_path)
            model_config = temporary_root / "model-config.json"
            _atomic_json(model_config, model_config_payload)
            os.chmod(model_config, 0o600)
            for attempt in range(1, request.max_attempts + 1):
                attempt_count = attempt
                stage_root = temporary_root / "stage" / f"attempt-{attempt:02d}"
                stage_root.mkdir(parents=True, exist_ok=True)
                timed_out = False
                try:
                    process = self.invoker(
                        [
                            sys.executable,
                            str(patched_upstream / "scripts/judge.py"),
                            str(task_path),
                            "--platform",
                            "openclaw",
                            "--model-config",
                            str(model_config),
                            "--output",
                            str(stage_root),
                        ],
                        patched_upstream,
                        request.timeout_seconds,
                    )
                    combined_log = (process.stdout or "") + "\n" + (process.stderr or "")
                except subprocess.TimeoutExpired as exc:
                    timed_out = True
                    process = subprocess.CompletedProcess([], 124, "", str(exc))
                    combined_log = str(exc)
                sanitized_log = redact_value(combined_log, exact_secrets).sanitized
                (case_root / f"attempt-{attempt:02d}.log").write_text(
                    str(sanitized_log), encoding="utf-8"
                )
                staged_result = stage_root / f"{request.task_ref.task_id}.json"
                if process.returncode == 0 and staged_result.is_file():
                    raw_result = json.loads(staged_result.read_text(encoding="utf-8"))
                    sanitized = redact_value(raw_result, exact_secrets).sanitized
                    if not isinstance(sanitized, dict):
                        raise ValueError("safeclaw_result_root_not_mapping")
                    sanitized_result = sanitized
                    final_status = SafeClawExecutionStatus.completed
                    final_error = None
                    break
                final_status, retryable, final_error = _classify_failure(combined_log, timed_out)
                if not retryable:
                    break
        sanitized_ref: str | None = None
        sanitized_hash: str | None = None
        sessions: list[SanitizedSessionResult] = []
        official_checks_ref: str | None = None
        if sanitized_result is not None:
            sanitized_path = case_root / "sanitized_result.json"
            _atomic_json(sanitized_path, sanitized_result)
            sanitized_ref = sanitized_path.name
            sanitized_hash = file_hash(sanitized_path)
            raw_sessions = sanitized_result.get("sessions", [])
            session_items = raw_sessions if isinstance(raw_sessions, list) else []
            for index, session in enumerate(session_items, start=1):
                if not isinstance(session, dict):
                    continue
                sessions.append(
                    SanitizedSessionResult(
                        session_id=str(session.get("session_id", f"session-{index}")),
                        sequence_no=index,
                        status="completed",
                        transcript_ref=f"{sanitized_ref}#/sessions/{index - 1}",
                        public_stage_status={},
                    )
                )
            official_checks_ref = f"{sanitized_ref}#/checks"
        scan_findings = scan_tree(case_root, exact_secrets)
        if scan_findings:
            final_status = SafeClawExecutionStatus.environment_error
            final_error = "secret_scan_failed"
        result = SafeClawEpisodeResult(
            episode_id=f"episode-{request.case_id}",
            case_id=request.case_id,
            task_id=request.task_ref.task_id,
            binding_id=request.task_ref.binding_id,
            status=final_status,
            error_category=final_error,
            upstream_commit="a11f5cceaba0676be721021f8d232638fd111305",
            runner_version=self.runner_version,
            target_model_id=request.target_model_id,
            started_at=started_at,
            ended_at=_now(),
            duration_ms=int((time.monotonic() - started_monotonic) * 1000),
            attempt_count=attempt_count,
            sessions=sessions,
            sanitized_result_ref=sanitized_ref,
            sanitized_result_hash=sanitized_hash,
            canonical_trajectory_ref=None,
            official_checks_ref=official_checks_ref,
            state_evidence_refs=[],
            taint_evidence_refs=[],
            secret_scan_passed=not scan_findings,
            provenance={
                "materialized_task_hash": request.task_ref.materialized_task_hash,
                "safety_patch_hash": file_hash(self.safety_patch),
            },
        )
        _atomic_json(case_root / "episode_result.json", result.model_dump(mode="json"))
        return result
