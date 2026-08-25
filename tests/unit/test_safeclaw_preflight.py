from __future__ import annotations

import subprocess
from pathlib import Path

from stac_attack_lab.environments.safeclaw.preflight import (
    SafeClawPreflightConfig,
    load_safeclaw_preflight_config,
    run_safeclaw_preflight,
)
from stac_attack_lab.environments.safeclaw.task_adapter import PINNED_SAFECLAW_COMMIT

ROOT = Path(__file__).resolve().parents[2]


def _runner(command: list[str], cwd: Path | None) -> subprocess.CompletedProcess[str]:
    del cwd
    if command[:3] == ["git", "rev-parse", "HEAD"]:
        return subprocess.CompletedProcess(command, 0, PINNED_SAFECLAW_COMMIT + "\n", "")
    if command[:2] == ["docker", "info"]:
        return subprocess.CompletedProcess(command, 0, '"27.0"\n', "")
    if command[:3] == ["docker", "image", "inspect"]:
        return subprocess.CompletedProcess(command, 0, '"sha256:synthetic"\n', "")
    return subprocess.CompletedProcess(command, 1, "", "unsupported")


def test_preflight_fails_closed_on_missing_checkout_without_secret_values() -> None:
    config = load_safeclaw_preflight_config(
        ROOT / "configs/environments/safeclaw_openclaw_v1.yaml"
    ).model_copy(update={"upstream_dir": "tests/fixtures/safeclaw/missing-upstream"})
    secret = "sk-never-render-this-secret-123456"
    report = run_safeclaw_preflight(
        ROOT,
        config,
        environment={
            "SAFECLAW_MODEL": "synthetic-model",
            "OPENAI_BASE_URL": "http://127.0.0.1:9999/v1",
            "OPENAI_API_KEY": secret,
            "SAFECLAW_EMBEDDING_MODEL": "synthetic-embedding",
        },
        command_runner=_runner,
    )

    assert report.passed is False
    assert any(check.reason_code == "upstream_missing" for check in report.checks)
    assert any(check.reason_code == "target_model_not_allowed" for check in report.checks)
    assert secret not in report.model_dump_json()


def test_preflight_passes_with_pinned_synthetic_checkout(tmp_path: Path) -> None:
    upstream = tmp_path / "upstream"
    (upstream / "scripts").mkdir(parents=True)
    for relative in ("scripts/judge.py", "scripts/reset_env.sh", "Dockerfile"):
        target = upstream / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text("synthetic\n", encoding="utf-8")
    config = SafeClawPreflightConfig(
        upstream_dir=str(upstream),
        required_files=["scripts/judge.py", "scripts/reset_env.sh", "Dockerfile"],
        patch_path=str(ROOT / "integrations/safeclaw/patches/a11f5cce-safety.patch"),
        target_model_env="SAFECLAW_MODEL",
        target_base_url_env="OPENAI_BASE_URL",
        target_api_key_env="OPENAI_API_KEY",
        embedding_policy="required_endpoint",
        embedding_provider="openai",
        embedding_model_env="SAFECLAW_EMBEDDING_MODEL",
        embedding_base_url_env="OPENAI_BASE_URL",
        embedding_api_key_env="OPENAI_API_KEY",
        minimum_free_disk_gb=1,
    )
    report = run_safeclaw_preflight(
        tmp_path,
        config,
        environment={
            "SAFECLAW_MODEL": "synthetic-model",
            "OPENAI_BASE_URL": "http://127.0.0.1:9999/v1",
            "OPENAI_API_KEY": "synthetic-key",
            "SAFECLAW_EMBEDDING_MODEL": "synthetic-embedding",
        },
        command_runner=_runner,
    )

    assert report.passed is True
    assert all(check.passed for check in report.checks)


def test_preflight_fails_closed_when_docker_image_is_missing(tmp_path: Path) -> None:
    upstream = tmp_path / "upstream"
    (upstream / "scripts").mkdir(parents=True)
    for relative in ("scripts/judge.py", "scripts/reset_env.sh", "Dockerfile"):
        target = upstream / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text("synthetic\n", encoding="utf-8")
    config = SafeClawPreflightConfig(
        upstream_dir=str(upstream),
        required_files=["scripts/judge.py", "scripts/reset_env.sh", "Dockerfile"],
        patch_path=str(ROOT / "integrations/safeclaw/patches/a11f5cce-safety.patch"),
        target_model_env="SAFECLAW_MODEL",
        target_base_url_env="OPENAI_BASE_URL",
        target_api_key_env="OPENAI_API_KEY",
        embedding_policy="exclude_tasks",
        minimum_free_disk_gb=1,
    )

    def missing_image_runner(
        command: list[str], cwd: Path | None
    ) -> subprocess.CompletedProcess[str]:
        if command[:3] == ["docker", "image", "inspect"]:
            return subprocess.CompletedProcess(command, 1, "", "missing")
        return _runner(command, cwd)

    report = run_safeclaw_preflight(
        tmp_path,
        config,
        environment={
            "SAFECLAW_MODEL": "synthetic-model",
            "OPENAI_BASE_URL": "http://127.0.0.1:9999/v1",
            "OPENAI_API_KEY": "synthetic-key",
        },
        command_runner=missing_image_runner,
    )

    assert report.passed is False
    assert any(check.reason_code == "docker_image_missing" for check in report.checks)
