from __future__ import annotations

import json
import os
import re
import sys
from collections.abc import Mapping
from pathlib import Path
from typing import Any, Literal

import yaml  # type: ignore[import-untyped]
from pydantic import Field

from stac_attack_lab.contracts import StrictModel
from stac_attack_lab.execution.benign_collection import validate_benign_collection_config
from stac_attack_lab.execution.sample_generation import load_sample_generation_config
from stac_attack_lab.execution.sample_preflight import (
    CommandRunner,
    SampleCollectionPreflightReport,
    _default_runner,
    run_bounded_external_check,
    run_sample_collection_preflight,
)
from stac_attack_lab.hashing import file_hash, stable_hash

WorkflowKind = Literal[
    "fixture",
    "compatibility_probe",
    "benign_collection",
    "legacy_attack_collection",
    "formal",
]

_RUN_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_-]*$")


class WorkflowReadinessReport(StrictModel):
    schema_version: Literal["1.0"] = "1.0"
    inspected_head: str
    source_hash: str
    config_path: str
    config_hash: str | None
    interpreter: str
    workflow_kind: WorkflowKind
    implementation_ready: bool
    config_valid: bool
    environment_ready: bool | None
    execution_enabled: bool
    authorization_state: Literal["absent"] = "absent"
    existing_run_state: str
    launch_reservation_state: str
    failed_checks: list[str] = Field(default_factory=list)
    pending_checks: list[str] = Field(default_factory=list)
    blocked_checks: list[str] = Field(default_factory=list)
    first_actionable_blocker: str | None
    all_independent_blockers: list[str] = Field(default_factory=list)
    can_prepare: bool
    can_collect: bool
    can_analyze: bool
    can_evaluate: bool
    recommended_next_command: str
    preflight: SampleCollectionPreflightReport | None = None


class CompatibilityProbeAssessment(StrictModel):
    schema_version: Literal["1.0"] = "1.0"
    status: Literal["passed", "failed", "incomplete"]
    request_attempt_count: int
    response_observed: bool
    accepted_sample_required: Literal[False] = False
    cross_session_required: Literal[False] = False
    reason_codes: list[str]


def assess_compatibility_probe(records: list[Mapping[str, Any]]) -> CompatibilityProbeAssessment:
    attempts = [item for item in records if item.get("state") == "attempted"]
    responses = [item for item in records if item.get("state") == "response_received"]
    errors = [item for item in records if item.get("state") == "transport_error"]
    reasons: list[str] = []
    if len(attempts) != 1:
        reasons.append("compatibility_probe_attempt_count_invalid")
    if len(responses) > 1 or (responses and errors):
        reasons.append("compatibility_probe_terminal_state_ambiguous")
    if errors:
        reasons.append("compatibility_probe_transport_error")
    response_observed = len(responses) == 1
    status: Literal["passed", "failed", "incomplete"]
    if reasons:
        status = "failed"
    elif not response_observed:
        status = "incomplete"
        reasons.append("compatibility_probe_response_not_observed")
    else:
        status = "passed"
        reasons.append("compatibility_probe_single_response_observed")
    return CompatibilityProbeAssessment(
        status=status,
        request_attempt_count=len(attempts),
        response_observed=response_observed,
        reason_codes=reasons,
    )


def validate_run_id(value: str) -> str:
    if value in {".", ".."} or not _RUN_ID.fullmatch(value):
        raise ValueError("run_id_invalid")
    return value


def resolve_config_path(project_root: Path, value: str | Path) -> Path:
    path = Path(value).expanduser()
    resolved = path.resolve() if path.is_absolute() else (project_root / path).resolve()
    if not resolved.is_file():
        raise ValueError("workflow_config_missing")
    return resolved


def load_config_document(path: Path) -> dict[str, Any]:
    try:
        value = yaml.safe_load(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, yaml.YAMLError) as exc:
        raise ValueError("workflow_config_parse_failed") from exc
    if not isinstance(value, dict) or not all(isinstance(key, str) for key in value):
        raise ValueError("workflow_config_root_invalid")
    return value


def infer_workflow_kind(value: Mapping[str, Any], path: Path) -> WorkflowKind:
    if value.get("collection_mode") == "benign_interaction":
        return "fixture" if value.get("source_mode") == "synthetic_fixture" else "benign_collection"
    pipeline = str(value.get("pipeline_id", "")).casefold()
    if "compatibility" in pipeline or "compatibility" in path.name.casefold():
        return "compatibility_probe"
    if "formal_conditions" in value or "library_path" in value:
        return "formal"
    return "legacy_attack_collection"


def _head(project_root: Path) -> str:
    head = project_root / ".git" / "HEAD"
    if not head.is_file():
        return "unavailable"
    raw = head.read_text(encoding="utf-8").strip()
    if raw.startswith("ref: "):
        ref = project_root / ".git" / raw[5:]
        return ref.read_text(encoding="utf-8").strip() if ref.is_file() else raw
    return raw


def _existing_run_state(run_root: Path) -> str:
    if not run_root.exists():
        return "missing"
    for name in ("live_summary.json", "result_summary.json"):
        path = run_root / name
        if not path.is_file():
            continue
        try:
            summary = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return "summary_invalid"
        execution = summary.get("execution_status", summary.get("status", "unknown"))
        admission_failed = False
        exit_codes = run_root / "exit_codes.tsv"
        if exit_codes.is_file():
            admission_failed = any(
                line.startswith("admission\t") and not line.rstrip().endswith("\t0")
                for line in exit_codes.read_text(encoding="utf-8").splitlines()
            )
        structural = summary.get("structural_admission")
        if isinstance(structural, dict):
            admission_failed = admission_failed or structural.get("status") == "failed"
        if execution in {"complete", "completed", "completed_with_stage_failures"}:
            return (
                "execution_complete_admission_failed" if admission_failed else "execution_complete"
            )
        return f"execution_{execution}"
    return "exists_without_summary"


def diagnose_workflow(
    project_root: Path,
    config_path: Path,
    *,
    workflow_kind: WorkflowKind | None = None,
    run_root: Path | None = None,
    environment: Mapping[str, str] | None = None,
    command_runner: CommandRunner | None = None,
) -> WorkflowReadinessReport:
    resolved = resolve_config_path(project_root, config_path)
    document = load_config_document(resolved)
    kind = workflow_kind or infer_workflow_kind(document, resolved)
    config_valid = False
    implementation_ready = kind != "formal"
    environment_ready: bool | None = None
    execution_enabled = document.get("execution_enabled") is True
    failed: list[str] = []
    pending: list[str] = []
    blocked: list[str] = []
    preflight: SampleCollectionPreflightReport | None = None
    try:
        if kind in {"fixture", "benign_collection"}:
            benign_config, _ = validate_benign_collection_config(project_root, resolved)
            config_valid = True
            implementation_ready = benign_config.source_mode in {
                "synthetic_fixture",
                "safeclaw_derived",
            }
            environment_ready = True if kind == "fixture" else None
            if kind == "benign_collection":
                pending.append("real_provider_compatibility_not_observed")
                env = environment if environment is not None else os.environ
                required_env = [
                    name
                    for name in (
                        benign_config.victim_model_env,
                        benign_config.victim_base_url_env,
                        benign_config.victim_api_key_env,
                        benign_config.embedding_model_env,
                        benign_config.embedding_base_url_env,
                        benign_config.embedding_api_key_env,
                    )
                    if name
                ]
                missing_env = [name for name in required_env if not env.get(name)]
                if missing_env:
                    failed.append("benign_live_model_environment_missing")
                runner = command_runner or _default_runner
                upstream = project_root / str(benign_config.upstream_dir)
                task_set = load_config_document(
                    project_root / str(benign_config.safeclaw_task_set_path)
                )
                commit, commit_error = run_bounded_external_check(
                    ["git", "rev-parse", "HEAD"], upstream, runner
                )
                if (
                    commit_error is not None
                    or commit is None
                    or commit.stdout.strip() != task_set.get("upstream_commit")
                ):
                    failed.append(f"benign_live_upstream_{commit_error or 'commit_mismatch'}")
                docker, docker_error = run_bounded_external_check(
                    ["docker", "info", "--format", "{{json .ServerVersion}}"], None, runner
                )
                if docker is None or docker_error is not None:
                    failed.append(f"docker_{docker_error or 'unavailable'}")
                image, image_error = run_bounded_external_check(
                    [
                        "docker",
                        "image",
                        "inspect",
                        benign_config.image_tag,
                        "--format",
                        "{{json .Id}}",
                    ],
                    None,
                    runner,
                )
                if image is None or image_error is not None:
                    failed.append(
                        "safeclaw_image_missing"
                        if image is not None and image_error == "command_failed"
                        else f"docker_image_{image_error or 'unavailable'}"
                    )
                environment_ready = not missing_env and not any(
                    item.startswith(("benign_live_upstream_", "docker_", "safeclaw_image_"))
                    for item in failed
                )
        elif kind in {"legacy_attack_collection", "compatibility_probe"}:
            sample_config = load_sample_generation_config(resolved)
            kwargs: dict[str, object] = {"environment": environment, "readiness_mode": "prepare"}
            if command_runner is not None:
                kwargs["command_runner"] = command_runner
            preflight = run_sample_collection_preflight(
                project_root,
                sample_config,
                **kwargs,  # type: ignore[arg-type]
            )
            config_valid = preflight.config_valid
            implementation_ready = preflight.implementation_ready
            environment_ready = preflight.environment_ready
            failed.extend(item.reason_code for item in preflight.checks if not item.passed)
        else:
            config_valid = True
            implementation_ready = False
            blocked.append("formal_readiness_not_implemented_by_collection_doctor")
    except (ValueError, OSError, json.JSONDecodeError) as exc:
        failed.append(str(exc).splitlines()[0][:200] or type(exc).__name__)

    if not implementation_ready:
        blocked.append("implementation_missing")
    if not config_valid:
        blocked.append("config_invalid")
    if environment_ready is False:
        blocked.append("environment_not_ready")
    if not execution_enabled:
        pending.append("execution_disabled")
    pending.append("execution_authorization_absent")
    existing = "not_supplied"
    reservation = "not_checked"
    if run_root is not None:
        existing = _existing_run_state(run_root)
        reservation = "present" if (run_root / "launch.marker").is_file() else "absent"
    blockers = list(dict.fromkeys([*blocked, *failed]))
    can_prepare = config_valid and implementation_ready
    can_collect = can_prepare and environment_ready is True and execution_enabled and not blockers
    recommended = (
        "review failed_checks and keep execution disabled"
        if blockers
        else (
            "prepare the disabled workflow snapshot; live execution requires separate authorization"
        )
    )
    return WorkflowReadinessReport(
        inspected_head=_head(project_root),
        source_hash=stable_hash(
            {
                "readiness": file_hash(Path(__file__)),
                "python": sys.version.split()[0],
            }
        ),
        config_path=str(resolved),
        config_hash=file_hash(resolved),
        interpreter=sys.executable,
        workflow_kind=kind,
        implementation_ready=implementation_ready,
        config_valid=config_valid,
        environment_ready=environment_ready,
        execution_enabled=execution_enabled,
        existing_run_state=existing,
        launch_reservation_state=reservation,
        failed_checks=sorted(set(failed)),
        pending_checks=sorted(set(pending)),
        blocked_checks=sorted(set(blocked)),
        first_actionable_blocker=blockers[0] if blockers else None,
        all_independent_blockers=blockers,
        can_prepare=can_prepare,
        can_collect=can_collect,
        can_analyze=True,
        can_evaluate=False,
        recommended_next_command=recommended,
        preflight=preflight,
    )
