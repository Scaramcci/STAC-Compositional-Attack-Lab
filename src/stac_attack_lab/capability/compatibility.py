from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import uuid
from collections.abc import Mapping
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Literal, cast
from urllib.parse import urlsplit

from stac_attack_lab.capability.compiler import (
    compile_cases,
    validate_compatibility_config,
    validate_compilation,
)
from stac_attack_lab.capability.models import (
    CapabilityDoctorReport,
    CompatibilityPreparationManifest,
    CompatibilityStageStatus,
    RuntimeTask,
)
from stac_attack_lab.capability.runner import run_safeclaw_capability_episode
from stac_attack_lab.environments.safeclaw.capability_runtime import (
    SafeClawCapabilityRuntimeAdapter,
)
from stac_attack_lab.environments.safeclaw.provider_relay import chat_completions_url
from stac_attack_lab.environments.safeclaw.redaction import scan_tree
from stac_attack_lab.execution.sample_preflight import run_bounded_external_check
from stac_attack_lab.hashing import file_hash, stable_hash
from stac_attack_lab.interactions.base import CollectionBudget
from stac_attack_lab.interactions.safeclaw_collection import (
    SAFECLAW_CONSTRUCTION_TOOLS,
    SafeClawConstructionTaskSet,
    SafeClawSubprocessVictimDriver,
)

RUN_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_-]{7,127}$")
STAGE_ORDER = ("P0", "P1", "P2")


def _run(command: list[str], cwd: Path | None) -> subprocess.CompletedProcess[str]:
    return subprocess.run(command, cwd=cwd, text=True, capture_output=True, check=False, timeout=10)


def _project_path(project_root: Path, raw: str) -> Path:
    path = Path(raw)
    resolved = (path if path.is_absolute() else project_root / path).resolve()
    if resolved != project_root.resolve() and project_root.resolve() not in resolved.parents:
        raise ValueError("capability_path_outside_project")
    return resolved


def _endpoint_identity(value: str | None) -> tuple[str | None, str | None]:
    if not value:
        return None, None
    parsed = urlsplit(chat_completions_url(value))
    return parsed.hostname, parsed.path or "/"


def diagnose_capability_compatibility(
    project_root: Path,
    config_path: Path,
    *,
    environment: Mapping[str, str] | None = None,
) -> CapabilityDoctorReport:
    env = environment if environment is not None else os.environ
    blockers: list[str] = []
    checks: dict[str, str] = {}
    try:
        config = validate_compatibility_config(config_path)
    except Exception as exc:
        return CapabilityDoctorReport(
            config_valid=False,
            implementation_ready=False,
            environment_ready=False,
            execution_enabled=False,
            authorization_state="absent",
            model_id_configured="unknown",
            model_id_environment=None,
            model_identity_match=None,
            endpoint_host=None,
            endpoint_path=None,
            environment_variable_presence={},
            checks={"config": f"configuration_invalid:{type(exc).__name__}"},
            blockers=["configuration_invalid"],
        )
    paths = {
        "task_config": _project_path(project_root, config.task_config),
        "task_set": _project_path(project_root, config.task_set_path),
        "upstream": project_root / "integrations/safeclaw/upstream/SafeClawArena",
        "patch": project_root / "integrations/safeclaw/patches/a11f5cce-safety.patch",
        "bridge": project_root / "integrations/safeclaw/construction_bridge.py",
    }
    for name, path in paths.items():
        present = path.exists()
        checks[f"path_{name}"] = "present" if present else "missing"
        if not present:
            blockers.append(f"{name}_missing")
    actual_model = env.get(config.provider_model_env)
    model_match = actual_model == config.model_id if actual_model else None
    if model_match is False:
        blockers.append("configured_model_environment_mismatch")
    endpoint_value = env.get(config.provider_base_url_env)
    endpoint_host, endpoint_path = _endpoint_identity(endpoint_value)
    presence = {
        config.provider_model_env: bool(actual_model),
        config.provider_base_url_env: bool(endpoint_value),
        config.provider_api_key_env: bool(env.get(config.provider_api_key_env)),
    }
    if not all(presence.values()):
        blockers.append("provider_environment_incomplete")

    commit, commit_error = run_bounded_external_check(
        ["git", "rev-parse", "HEAD"], paths["upstream"], _run
    )
    commit_ok = (
        commit_error is None
        and commit is not None
        and commit.stdout.strip() == config.upstream_commit
    )
    checks["pinned_upstream"] = "matched" if commit_ok else commit_error or "mismatch"
    if not commit_ok:
        blockers.append("pinned_upstream_mismatch")
    dirty, dirty_error = run_bounded_external_check(
        ["git", "status", "--porcelain"], paths["upstream"], _run
    )
    clean = dirty_error is None and dirty is not None and not dirty.stdout.strip()
    checks["upstream_worktree"] = "clean" if clean else dirty_error or "dirty"
    if not clean:
        blockers.append("upstream_worktree_not_clean")
    patch, patch_error = run_bounded_external_check(
        ["git", "apply", "--unidiff-zero", "--check", str(paths["patch"])],
        paths["upstream"],
        _run,
    )
    patch_ok = patch_error is None and patch is not None
    checks["safety_patch"] = "applicable" if patch_ok else patch_error or "not_applicable"
    if not patch_ok:
        blockers.append("safety_patch_not_applicable")
    docker, docker_error = run_bounded_external_check(
        ["docker", "info", "--format", "{{json .ServerVersion}}"], None, _run
    )
    checks["docker"] = "available" if docker_error is None and docker else docker_error or "failed"
    if docker_error:
        blockers.append(f"docker_{docker_error}")
    image, image_error = run_bounded_external_check(
        ["docker", "image", "inspect", "openclaw-env:2026.3.12"], None, _run
    )
    checks["image"] = "present" if image_error is None and image else image_error or "missing"
    if image_error:
        blockers.append(f"docker_image_{image_error}")
    free_gb = shutil.disk_usage(project_root).free // (1024**3)
    checks["disk"] = f"free_gb={free_gb}"
    if free_gb < 20:
        blockers.append("insufficient_free_disk")
    configured_tools = set(config.provider_allowed_tools)
    if not configured_tools <= SAFECLAW_CONSTRUCTION_TOOLS:
        blockers.append("unsupported_capability")
        checks["tool_schema"] = "unsupported"
    else:
        checks["tool_schema"] = "declared_supported_by_bridge"
    checks["embedding"] = "disabled_zero_budget"
    checks["cash_cost_control"] = config.cost_control_mode
    implementation_blockers = {
        item
        for item in blockers
        if item.endswith("_missing")
        or item
        in {"pinned_upstream_mismatch", "safety_patch_not_applicable", "unsupported_capability"}
    }
    environment_blockers = set(blockers) - implementation_blockers
    return CapabilityDoctorReport(
        config_valid=True,
        implementation_ready=not implementation_blockers,
        environment_ready=not environment_blockers,
        execution_enabled=config.execution_enabled,
        authorization_state=(
            "configured_not_session_authorized" if config.authorization_reference else "absent"
        ),
        model_id_configured=config.model_id,
        model_id_environment=actual_model,
        model_identity_match=model_match,
        endpoint_host=endpoint_host,
        endpoint_path=endpoint_path,
        environment_variable_presence=presence,
        checks=checks,
        blockers=sorted(set(blockers)),
    )


def _new_run_id() -> str:
    timestamp = datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")
    return f"cap-compat-{timestamp}-{uuid.uuid4().hex[:8]}"


def prepare_capability_compatibility(
    project_root: Path,
    config_path: Path,
    *,
    run_id: str | None = None,
    environment: Mapping[str, str] | None = None,
) -> Path:
    config = validate_compatibility_config(config_path)
    selected_run = run_id or config.run_id or _new_run_id()
    if not RUN_ID.fullmatch(selected_run):
        raise ValueError("capability_run_id_invalid")
    base = _project_path(project_root, config.output_root)
    run_root = (
        base if config.run_id == selected_run and base.name == selected_run else base / selected_run
    )
    allowed_root = (project_root / "experiments/runs/capability").resolve()
    if allowed_root not in run_root.resolve().parents:
        raise ValueError("capability_output_outside_allowed_root")
    run_root.mkdir(parents=True, exist_ok=False)
    os.chmod(run_root, 0o700)
    prepared = config.model_copy(update={"run_id": selected_run, "output_root": str(run_root)})
    snapshot = run_root / "compatibility_config.snapshot.json"
    snapshot.write_text(prepared.model_dump_json(indent=2) + "\n", encoding="utf-8")
    os.chmod(snapshot, 0o600)
    compile_root = compile_cases(
        _project_path(project_root, config.task_config), run_root / "compiled"
    )
    compilation = validate_compilation(compile_root)
    task_set = SafeClawConstructionTaskSet.model_validate_json(
        _project_path(project_root, config.task_set_path).read_text(encoding="utf-8")
    )
    runtime_task = next(
        item for item in task_set.tasks if item.source_task_id == "capability-f1-benign-runtime-001"
    )
    doctor = diagnose_capability_compatibility(project_root, config_path, environment=environment)
    (run_root / "doctor.json").write_text(doctor.model_dump_json(indent=2) + "\n", encoding="utf-8")
    endpoint_host, endpoint_path = _endpoint_identity(
        (environment if environment is not None else os.environ).get(config.provider_base_url_env)
    )
    payload = {
        "schema_version": "capability-compatibility-preparation/1.0",
        "batch_id": selected_run,
        "run_root": str(run_root),
        "config_hash": file_hash(snapshot),
        "source_config_hash": file_hash(config_path),
        "compilation_manifest_hash": compilation.manifest_hash,
        "task_hash": runtime_task.template_hash,
        "patch_hash": file_hash(
            project_root / "integrations/safeclaw/patches/a11f5cce-safety.patch"
        ),
        "bridge_hash": file_hash(project_root / "integrations/safeclaw/construction_bridge.py"),
        "model_id": config.model_id,
        "endpoint_host": endpoint_host,
        "endpoint_path": endpoint_path,
        "stages": [item.model_dump(mode="json") for item in config.stages],
        "execution_enabled": config.execution_enabled,
        "authorization_needed": True,
        "network_requests_performed": False,
    }
    manifest = CompatibilityPreparationManifest.model_validate(
        {**payload, "manifest_hash": stable_hash(payload)}
    )
    (run_root / "preparation_manifest.json").write_text(
        manifest.model_dump_json(indent=2) + "\n", encoding="utf-8"
    )
    (run_root / "provider_attempt_ledger.jsonl").touch(mode=0o600)
    (run_root / "stage_status").mkdir()
    for stage in STAGE_ORDER:
        status = CompatibilityStageStatus(
            batch_id=selected_run,
            stage_id=cast(Literal["P0", "P1", "P2"], stage),
            execution_status="not_started",
            verdict="not_evaluated",
            reason_codes=["stage_not_started"],
            provider_attempts_before=0,
            provider_attempts_after=0,
            provider_attempts_stage=0,
            embedding_attempts=0,
            result_ref=None,
            cleanup_status="not_applicable",
        )
        (run_root / f"stage_status/{stage}.json").write_text(
            status.model_dump_json(indent=2) + "\n", encoding="utf-8"
        )
    findings = scan_tree(run_root)
    if findings:
        raise ValueError("capability_prepare_secret_scan_failed:" + ",".join(findings))
    return run_root


def read_compatibility_status(run_root: Path) -> dict[str, Any]:
    manifest = CompatibilityPreparationManifest.model_validate_json(
        (run_root / "preparation_manifest.json").read_text(encoding="utf-8")
    )
    statuses = [
        CompatibilityStageStatus.model_validate_json(
            (run_root / f"stage_status/{stage}.json").read_text(encoding="utf-8")
        )
        for stage in STAGE_ORDER
    ]
    attempts = sum(item.provider_attempts_stage for item in statuses)
    maximum = max(item.cumulative_victim_http_limit for item in manifest.stages)
    next_stage = next((item.stage_id for item in statuses if item.verdict == "not_evaluated"), None)
    return {
        "batch_id": manifest.batch_id,
        "execution_enabled": manifest.execution_enabled,
        "authorization_needed": manifest.authorization_needed,
        "provider_attempts_used": attempts,
        "provider_attempts_remaining": max(0, maximum - attempts),
        "embedding_attempts": sum(item.embedding_attempts for item in statuses),
        "stages": [item.model_dump(mode="json") for item in statuses],
        "next_stage": next_stage,
        "network_requests_performed": attempts > 0,
    }


def build_compatibility_report(run_root: Path, output_root: Path) -> Path:
    """Render a read-only report even when no probe, or only a partial probe, exists."""
    status = read_compatibility_status(run_root)
    manifest = CompatibilityPreparationManifest.model_validate_json(
        (run_root / "preparation_manifest.json").read_text(encoding="utf-8")
    )
    output_root.mkdir(parents=True, exist_ok=False)
    payload = {
        "schema_version": "capability-compatibility-report/1.0",
        "batch_id": manifest.batch_id,
        "model_id": manifest.model_id,
        "endpoint_host": manifest.endpoint_host,
        "endpoint_path": manifest.endpoint_path,
        "status": status,
        "official_outcome": "not_evaluated",
        "research_claim": "provider_compatibility_only",
    }
    (output_root / "report.json").write_text(
        json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    lines = [
        "# Capability compatibility report",
        "",
        f"- Batch: `{manifest.batch_id}`",
        f"- Model: `{manifest.model_id}`",
        f"- Endpoint: `{manifest.endpoint_host or 'unknown'}{manifest.endpoint_path or ''}`",
        f"- Provider attempts: `{status['provider_attempts_used']}`",
        "- Official outcome: `not_evaluated`",
        "",
        "| Stage | Execution | Verdict | Attempts |",
        "|---|---|---|---:|",
    ]
    for item in status["stages"]:
        lines.append(
            f"| {item['stage_id']} | {item['execution_status']} | {item['verdict']} | "
            f"{item['provider_attempts_stage']} |"
        )
    (output_root / "report.md").write_text("\n".join(lines) + "\n", encoding="utf-8")
    return output_root


def _classify_exception(exc: Exception) -> str:
    text = str(exc).casefold()
    if "authentication" in text or "401" in text or "403" in text:
        return "provider_auth_error"
    if "not found" in text or "404" in text:
        return "model_not_found"
    if "rate" in text or "429" in text:
        return "provider_rate_limited"
    if any(code in text for code in ("500", "502", "503", "504", "provider_5xx")):
        return "provider_5xx"
    if "timeout" in text:
        return "provider_timeout"
    if "budget" in text:
        return "budget_exhausted"
    if "parse" in text or "json" in text:
        return "response_unparseable"
    if "tool" in text and ("reject" in text or "blocked" in text):
        return "tool_rejected"
    if "state" in text and ("unobserv" in text or "snapshot" in text):
        return "state_unobservable"
    if "cleanup" in text:
        return "cleanup_failed"
    return "evidence_incomplete"


def run_compatibility_stage(
    project_root: Path,
    run_root: Path,
    stage_id: Literal["P0", "P1", "P2"],
    *,
    authorized: bool,
    dry_run: bool = False,
    environment: Mapping[str, str] | None = None,
) -> CompatibilityStageStatus:
    config_path = run_root / "compatibility_config.snapshot.json"
    config = validate_compatibility_config(config_path)
    manifest = CompatibilityPreparationManifest.model_validate_json(
        (run_root / "preparation_manifest.json").read_text(encoding="utf-8")
    )
    if manifest.config_hash != file_hash(config_path):
        raise ValueError("capability_prepared_config_hash_mismatch")
    stage = next(item for item in config.stages if item.stage_id == stage_id)
    if dry_run:
        return CompatibilityStageStatus(
            batch_id=manifest.batch_id,
            stage_id=stage_id,
            execution_status="not_started",
            verdict="not_evaluated",
            reason_codes=["dry_run_no_request"],
            provider_attempts_before=0,
            provider_attempts_after=0,
            provider_attempts_stage=0,
            embedding_attempts=0,
            result_ref=None,
            cleanup_status="not_applicable",
        )
    if not config.execution_enabled or not authorized or not config.authorization_reference:
        raise PermissionError("capability_live_authorization_missing")
    stage_index = STAGE_ORDER.index(stage_id)
    for previous in STAGE_ORDER[:stage_index]:
        previous_status = CompatibilityStageStatus.model_validate_json(
            (run_root / f"stage_status/{previous}.json").read_text(encoding="utf-8")
        )
        if previous_status.verdict != "passed":
            raise ValueError(f"capability_predecessor_stage_not_passed:{previous}")
    before = sum(
        CompatibilityStageStatus.model_validate_json(
            path.read_text(encoding="utf-8")
        ).provider_attempts_stage
        for path in (run_root / "stage_status").glob("*.json")
    )
    if before + stage.victim_http_limit > stage.cumulative_victim_http_limit:
        raise ValueError("capability_cumulative_stage_budget_invalid")
    if before + stage.victim_http_limit > config.max_batch_http_attempts:
        raise ValueError("capability_batch_budget_exhausted")
    marker = run_root / f"launch-{stage_id}.reserved"
    descriptor = os.open(marker, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    os.write(descriptor, manifest.batch_id.encode())
    os.close(descriptor)
    env = environment if environment is not None else os.environ
    try:
        compilation = validate_compilation(run_root / "compiled")
        task = RuntimeTask.model_validate_json(
            (run_root / f"compiled/cases/{config.case_id}/runtime_task.json").read_text(
                encoding="utf-8"
            )
        )
        task_set = SafeClawConstructionTaskSet.model_validate_json(
            _project_path(project_root, config.task_set_path).read_text(encoding="utf-8")
        )
        runtime_task = next(
            item
            for item in task_set.tasks
            if item.source_task_id == "capability-f1-benign-runtime-001"
        )
        driver = SafeClawSubprocessVictimDriver(
            project_root=project_root,
            upstream_root=project_root / "integrations/safeclaw/upstream/SafeClawArena",
            safety_patch=project_root / "integrations/safeclaw/patches/a11f5cce-safety.patch",
            bridge_path=project_root / "integrations/safeclaw/construction_bridge.py",
            target_model_id=config.model_id,
            target_base_url=str(env[config.provider_base_url_env]),
            target_api_key_env=config.provider_api_key_env,
            embedding=None,
            model_hash=stable_hash({"model": config.model_id}),
            provider_request_budget=stage.victim_http_limit,
            provider_timeout_seconds=config.provider_timeout_seconds,
            provider_max_output_tokens=stage.max_output_tokens_per_request,
            provider_allowed_tools=list(config.provider_allowed_tools),
            embedding_request_budget=0,
            provider_evidence_policy=config.provider_evidence_policy,
            environment=env,
            batch_id=manifest.batch_id,
        )
        adapter = SafeClawCapabilityRuntimeAdapter(
            driver, runtime_task, reviewed_message=stage.reviewed_message
        )
        result = run_safeclaw_capability_episode(
            task,
            adapter,
            run_root / f"stages/{stage_id}",
            batch_id=manifest.batch_id,
            source_compilation_manifest_hash=compilation.manifest_hash,
            budget=CollectionBudget(
                max_sessions=1,
                max_turns=1,
                max_actions=1,
                max_tool_calls=4,
                max_tokens=stage.max_output_tokens_per_request,
                max_wall_time_seconds=stage.wallclock_seconds,
                max_events=100,
                timeout_seconds=min(config.provider_timeout_seconds, stage.wallclock_seconds),
            ),
        )
        ledger = run_root / f"stages/{stage_id}/{config.case_id}/provider_attempt_ledger.jsonl"
        records = [
            json.loads(line) for line in ledger.read_text(encoding="utf-8").splitlines() if line
        ]
        used = sum(
            item.get("upstream_attempt_count", 1 if item.get("accepted") is True else 0)
            for item in records
        )
        after = before + used
        events_path = run_root / f"stages/{stage_id}/{config.case_id}/runtime_events.jsonl"
        event_types = {
            item.get("event_type")
            for line in events_path.read_text(encoding="utf-8").splitlines()
            if line.strip()
            for item in [json.loads(line)]
            if isinstance(item, dict)
        }
        if stage_id == "P0":
            passed = "response" in event_types and used <= stage.victim_http_limit
        elif stage_id == "P1":
            passed = "state_read" in event_types and used <= stage.victim_http_limit
        else:
            passed = result.benign_utility.value == "true" and used <= stage.victim_http_limit
        status = CompatibilityStageStatus(
            batch_id=manifest.batch_id,
            stage_id=stage_id,
            execution_status=result.execution_status,
            verdict="passed" if passed else "unknown",
            reason_codes=[
                f"{stage_id.lower()}_compatibility_verified"
                if passed
                else "stage_evidence_incomplete"
            ],
            provider_attempts_before=before,
            provider_attempts_after=after,
            provider_attempts_stage=used,
            embedding_attempts=0,
            result_ref=f"stages/{stage_id}/{config.case_id}/episode_result.json",
            cleanup_status="completed",
        )
    except Exception as exc:
        ledger = run_root / f"stages/{stage_id}/{config.case_id}/provider_attempt_ledger.jsonl"
        observed = 0
        if ledger.is_file():
            for line in ledger.read_text(encoding="utf-8").splitlines():
                try:
                    record = json.loads(line)
                except json.JSONDecodeError:
                    continue
                count = record.get("upstream_attempt_count")
                if isinstance(count, int):
                    observed += count
                elif record.get("accepted") is True:
                    observed += 1
        after = before + observed
        status = CompatibilityStageStatus(
            batch_id=manifest.batch_id,
            stage_id=stage_id,
            execution_status="error",
            verdict="unknown",
            reason_codes=[_classify_exception(exc), f"original_error:{type(exc).__name__}"],
            provider_attempts_before=before,
            provider_attempts_after=after,
            provider_attempts_stage=observed,
            embedding_attempts=0,
            result_ref=None,
            cleanup_status="unknown",
        )
    (run_root / f"stage_status/{stage_id}.json").write_text(
        status.model_dump_json(indent=2) + "\n", encoding="utf-8"
    )
    return status
