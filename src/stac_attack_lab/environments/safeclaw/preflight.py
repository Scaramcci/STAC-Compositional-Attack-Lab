from __future__ import annotations

import os
import shutil
import subprocess
from collections.abc import Callable, Mapping
from pathlib import Path
from typing import Literal

from pydantic import Field, PositiveInt

from stac_attack_lab.contracts import StrictModel
from stac_attack_lab.environments.safeclaw.task_adapter import PINNED_SAFECLAW_COMMIT
from stac_attack_lab.hashing import file_hash


class SafeClawPreflightConfig(StrictModel):
    schema_version: Literal["2.0"] = "2.0"
    upstream_dir: str
    pinned_commit: str = PINNED_SAFECLAW_COMMIT
    image_tag: str = "openclaw-env:2026.3.12"
    required_files: list[str]
    patch_path: str
    require_docker: bool = True
    target_model_env: str
    allowed_target_models: list[str] = Field(default_factory=list)
    target_base_url_env: str
    target_api_key_env: str
    embedding_policy: Literal["required_endpoint", "disabled_semantic_memory", "exclude_tasks"]
    embedding_provider: Literal["openai"] | None = None
    embedding_model_env: str | None = None
    embedding_base_url_env: str | None = None
    embedding_api_key_env: str | None = None
    minimum_free_disk_gb: PositiveInt = 20


class PreflightCheck(StrictModel):
    check_id: str
    passed: bool
    reason_code: str
    public_details: dict[str, str] = Field(default_factory=dict)


class SafeClawPreflightReport(StrictModel):
    schema_version: Literal["2.0"] = "2.0"
    passed: bool
    checks: list[PreflightCheck]
    upstream_commit: str
    image_tag: str
    patch_hash: str | None


CommandRunner = Callable[[list[str], Path | None], subprocess.CompletedProcess[str]]


def _default_runner(command: list[str], cwd: Path | None) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        command,
        cwd=cwd,
        text=True,
        capture_output=True,
        check=False,
    )


def load_safeclaw_preflight_config(path: Path) -> SafeClawPreflightConfig:
    return SafeClawPreflightConfig.model_validate_json(path.read_text(encoding="utf-8"))


def run_safeclaw_preflight(
    project_root: Path,
    config: SafeClawPreflightConfig,
    *,
    environment: Mapping[str, str] | None = None,
    command_runner: CommandRunner = _default_runner,
) -> SafeClawPreflightReport:
    env = environment if environment is not None else os.environ
    upstream = (project_root / config.upstream_dir).resolve()
    patch = (project_root / config.patch_path).resolve()
    checks: list[PreflightCheck] = []
    checks.append(
        PreflightCheck(
            check_id="upstream_checkout",
            passed=upstream.is_dir(),
            reason_code="upstream_present" if upstream.is_dir() else "upstream_missing",
            public_details={"path": str(upstream)},
        )
    )
    observed_commit = "unavailable"
    if upstream.is_dir():
        result = command_runner(["git", "rev-parse", "HEAD"], upstream)
        observed_commit = result.stdout.strip() if result.returncode == 0 else "unavailable"
    checks.append(
        PreflightCheck(
            check_id="upstream_commit",
            passed=observed_commit == config.pinned_commit,
            reason_code=(
                "upstream_commit_matches"
                if observed_commit == config.pinned_commit
                else "upstream_commit_mismatch"
            ),
            public_details={"observed": observed_commit, "required": config.pinned_commit},
        )
    )
    missing_files = [name for name in config.required_files if not (upstream / name).is_file()]
    checks.append(
        PreflightCheck(
            check_id="required_files",
            passed=not missing_files,
            reason_code="required_files_present" if not missing_files else "required_files_missing",
            public_details={"missing": ",".join(missing_files)},
        )
    )
    checks.append(
        PreflightCheck(
            check_id="safety_patch",
            passed=patch.is_file(),
            reason_code="safety_patch_present" if patch.is_file() else "safety_patch_missing",
            public_details={"path": str(patch)},
        )
    )
    required_env_names = [
        config.target_model_env,
        config.target_base_url_env,
        config.target_api_key_env,
    ]
    if config.embedding_policy == "required_endpoint":
        required_env_names.extend(
            name
            for name in (
                config.embedding_model_env,
                config.embedding_base_url_env,
                config.embedding_api_key_env,
            )
            if name
        )
        if not all(
            (
                config.embedding_provider,
                config.embedding_model_env,
                config.embedding_base_url_env,
                config.embedding_api_key_env,
            )
        ):
            required_env_names.append("INVALID_EMBEDDING_CONFIG")
    missing_env = sorted(name for name in required_env_names if not env.get(name))
    target_model = env.get(config.target_model_env)
    target_model_allowed = (
        not target_model
        or not config.allowed_target_models
        or (target_model in config.allowed_target_models)
    )
    checks.append(
        PreflightCheck(
            check_id="model_environment",
            passed=not missing_env,
            reason_code="model_environment_present"
            if not missing_env
            else "model_environment_missing",
            public_details={"missing_variable_names": ",".join(missing_env)},
        )
    )
    checks.append(
        PreflightCheck(
            check_id="target_model",
            passed=target_model_allowed,
            reason_code=(
                "target_model_allowed" if target_model_allowed else "target_model_not_allowed"
            ),
            public_details={
                "configured_model": target_model or "missing",
                "allowed_models": ",".join(config.allowed_target_models),
            },
        )
    )
    if config.require_docker:
        docker = command_runner(["docker", "info", "--format", "{{json .ServerVersion}}"], None)
        docker_ok = docker.returncode == 0
        image = command_runner(
            ["docker", "image", "inspect", config.image_tag, "--format", "{{json .Id}}"],
            None,
        )
        image_ok = image.returncode == 0
    else:
        docker_ok = True
        image_ok = True
    checks.append(
        PreflightCheck(
            check_id="docker",
            passed=docker_ok,
            reason_code="docker_available" if docker_ok else "docker_unavailable",
        )
    )
    checks.append(
        PreflightCheck(
            check_id="docker_image",
            passed=image_ok,
            reason_code="docker_image_present" if image_ok else "docker_image_missing",
            public_details={"image_tag": config.image_tag},
        )
    )
    disk_base = upstream if upstream.exists() else project_root
    free_gb = shutil.disk_usage(disk_base).free // (1024**3)
    checks.append(
        PreflightCheck(
            check_id="free_disk",
            passed=free_gb >= config.minimum_free_disk_gb,
            reason_code="disk_sufficient"
            if free_gb >= config.minimum_free_disk_gb
            else "disk_insufficient",
            public_details={
                "free_gb": str(free_gb),
                "required_gb": str(config.minimum_free_disk_gb),
            },
        )
    )
    return SafeClawPreflightReport(
        passed=all(check.passed for check in checks),
        checks=checks,
        upstream_commit=observed_commit,
        image_tag=config.image_tag,
        patch_hash=file_hash(patch) if patch.is_file() else None,
    )
