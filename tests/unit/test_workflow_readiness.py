from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

from stac_attack_lab.env_loader import load_env_file
from stac_attack_lab.execution.readiness import (
    assess_compatibility_probe,
    diagnose_workflow,
    load_config_document,
    validate_run_id,
)
from stac_attack_lab.execution.sample_generation import load_sample_generation_config
from stac_attack_lab.execution.sample_preflight import run_sample_collection_preflight

ROOT = Path(__file__).resolve().parents[2]


def test_doctor_accepts_absolute_fixture_config_and_separates_execution_gate() -> None:
    config = (ROOT / "configs/benign_collection/synthetic_stage_a.disabled.json").resolve()
    report = diagnose_workflow(ROOT, config)
    assert report.workflow_kind == "fixture"
    assert report.config_valid is True
    assert report.implementation_ready is True
    assert report.environment_ready is True
    assert report.execution_enabled is False
    assert report.can_prepare is True
    assert report.can_collect is False
    assert "execution_disabled" in report.pending_checks
    assert report.authorization_state == "absent"


def test_disabled_benign_live_can_be_environment_ready_without_becoming_collectable() -> None:
    def runner(command: list[str], cwd: Path | None) -> subprocess.CompletedProcess[str]:
        del cwd
        stdout = (
            "a11f5cceaba0676be721021f8d232638fd111305\n"
            if command[:3] == ["git", "rev-parse", "HEAD"]
            else "ok\n"
        )
        return subprocess.CompletedProcess(command, 0, stdout=stdout, stderr="")

    environment = {
        "SAFECLAW_MODEL": "ep-20260909180104-hmx9m",
        "SAFECLAW_BASE_URL": "http://127.0.0.1.invalid",
        "SAFECLAW_API_KEY": "synthetic-test-value",
        "SAFECLAW_EMBEDDING_MODEL": "fake-embedding",
        "SAFECLAW_EMBEDDING_BASE_URL": "http://127.0.0.1.invalid",
        "SAFECLAW_EMBEDDING_API_KEY": "synthetic-test-value",
    }
    report = diagnose_workflow(
        ROOT,
        ROOT / "configs/benign_collection/live_pilot.disabled.json",
        environment=environment,
        command_runner=runner,
    )
    assert report.workflow_kind == "benign_collection"
    assert report.config_valid is True
    assert report.environment_ready is True
    assert report.execution_enabled is False
    assert report.can_prepare is True
    assert report.can_collect is False


def test_yaml_loader_and_run_id_rules(tmp_path: Path) -> None:
    path = tmp_path / "config with spaces.yaml"
    path.write_text("pipeline_id: demo\nexecution_enabled: false\n", encoding="utf-8")
    assert load_config_document(path)["pipeline_id"] == "demo"
    assert validate_run_id("pilot_01") == "pilot_01"
    for value in (".", "..", "../escape", "with.dot"):
        with pytest.raises(ValueError, match="run_id_invalid"):
            validate_run_id(value)


def test_sample_loader_accepts_real_yaml(tmp_path: Path) -> None:
    original = json.loads(
        (
            ROOT / "configs/sample_generation/provider_compatibility_revalidation.disabled.json"
        ).read_text(encoding="utf-8")
    )
    path = tmp_path / "sample.yaml"
    import yaml

    path.write_text(yaml.safe_dump(original), encoding="utf-8")
    assert load_sample_generation_config(path).pipeline_id == original["pipeline_id"]


@pytest.mark.parametrize(
    ("exception", "reason"),
    [
        (FileNotFoundError(), "docker_executable_missing"),
        (PermissionError(), "docker_permission_denied"),
        (
            subprocess.TimeoutExpired(cmd=["docker"], timeout=10),
            "docker_command_timeout",
        ),
    ],
)
def test_preflight_external_failures_are_classified_and_do_not_abort(
    exception: BaseException, reason: str
) -> None:
    config = load_sample_generation_config(
        ROOT / "configs/sample_generation/provider_compatibility_revalidation.disabled.json"
    )

    def runner(command: list[str], cwd: Path | None) -> subprocess.CompletedProcess[str]:
        del cwd
        if command[0] == "docker":
            raise exception
        return subprocess.CompletedProcess(command, 0, stdout="", stderr="")

    report = run_sample_collection_preflight(
        ROOT, config, environment={}, command_runner=runner, readiness_mode="prepare"
    )
    reasons = {item.reason_code for item in report.checks}
    assert reason in reasons
    assert report.execution_enabled is False
    assert report.readiness_mode == "prepare"


def test_preflight_distinguishes_daemon_and_missing_image() -> None:
    config = load_sample_generation_config(
        ROOT / "configs/sample_generation/provider_compatibility_revalidation.disabled.json"
    )

    def runner(command: list[str], cwd: Path | None) -> subprocess.CompletedProcess[str]:
        del cwd
        if command[:2] == ["docker", "info"]:
            return subprocess.CompletedProcess(
                command, 1, stdout="", stderr="Cannot connect to the Docker daemon"
            )
        if command[:3] == ["docker", "image", "inspect"]:
            return subprocess.CompletedProcess(command, 1, stdout="", stderr="No such image")
        return subprocess.CompletedProcess(command, 0, stdout="", stderr="")

    report = run_sample_collection_preflight(
        ROOT, config, environment={}, command_runner=runner, readiness_mode="prepare"
    )
    reasons = {item.reason_code for item in report.checks}
    assert "docker_daemon_unreachable" in reasons
    assert "safeclaw_image_missing" in reasons


def test_compatibility_probe_does_not_require_accepted_or_cross_session() -> None:
    report = assess_compatibility_probe(
        [
            {"state": "attempted", "request_id": "request-1"},
            {"state": "response_received", "request_id": "request-1"},
        ]
    )
    assert report.status == "passed"
    assert report.accepted_sample_required is False
    assert report.cross_session_required is False


def test_doctor_keeps_completed_execution_separate_from_failed_admission(
    tmp_path: Path,
) -> None:
    run_root = tmp_path / "old-run"
    run_root.mkdir()
    (run_root / "result_summary.json").write_text(
        json.dumps({"status": "complete", "failure_category": None}), encoding="utf-8"
    )
    (run_root / "exit_codes.tsv").write_text("construction\t0\nadmission\t1\n", encoding="utf-8")
    report = diagnose_workflow(
        ROOT,
        ROOT / "configs/benign_collection/synthetic_stage_a.disabled.json",
        run_root=run_root,
    )
    assert report.existing_run_state == "execution_complete_admission_failed"


def test_shell_print_is_cwd_independent_accepts_absolute_path_and_has_no_side_effect(
    tmp_path: Path,
) -> None:
    config = tmp_path / "config with spaces.yaml"
    config.write_text(
        "pipeline_id: pipeline-demo\nlibrary_version: library-demo\n", encoding="utf-8"
    )
    run_id = "print_only_test_72819"
    output_root = ROOT / "experiments/runs" / run_id
    assert not output_root.exists()
    result = subprocess.run(
        [
            "bash",
            str(ROOT / "scripts/run_safeclaw_sample_collection.sh"),
            "--config",
            str(config),
            "--run-id",
            run_id,
            "--print-output-dir",
        ],
        cwd=tmp_path,
        env={**os.environ, "STAC_PYTHON": sys.executable},
        text=True,
        capture_output=True,
        check=False,
    )
    assert result.returncode == 0, result.stderr
    assert "library-demo/interactions/raw/pipeline-demo" in result.stdout
    assert not output_root.exists()


def test_dotenv_values_are_data_not_shell_commands(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    marker = tmp_path / "should-not-exist"
    dotenv = tmp_path / ".env"
    dotenv.write_text(f"STAC_TEST_LITERAL=$(touch {marker})\n", encoding="utf-8")
    monkeypatch.delenv("STAC_TEST_LITERAL", raising=False)
    load_env_file(dotenv)
    assert os.environ["STAC_TEST_LITERAL"].startswith("$(touch")
    assert not marker.exists()
