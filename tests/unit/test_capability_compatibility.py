from __future__ import annotations

import json
from pathlib import Path

import pytest

import stac_attack_lab.capability.compatibility as compatibility
from stac_attack_lab.capability.compatibility import (
    bind_compatibility_execution,
    diagnose_capability_compatibility,
    read_compatibility_status,
    run_compatibility_stage,
)
from stac_attack_lab.capability.models import CompatibilityPreparationManifest
from stac_attack_lab.hashing import file_hash, stable_hash

ROOT = Path(__file__).resolve().parents[2]
CONFIG = ROOT / "configs/capability/provider_compatibility.disabled.json"


def test_doctor_reports_configured_identity_without_provider_request(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    commands: list[list[str]] = []

    def fake_run(command: list[str], cwd: Path | None):
        commands.append(command)
        return compatibility.subprocess.CompletedProcess(command, 0, stdout="", stderr="")

    monkeypatch.setattr(compatibility, "_run", fake_run)
    report = diagnose_capability_compatibility(
        ROOT,
        CONFIG,
        environment={
            "SAFECLAW_MODEL": "ep-other",
            "SAFECLAW_BASE_URL": "https://example.invalid/api/v3/chat/completions",
            "SAFECLAW_API_KEY": "synthetic-test-value",
        },
    )
    assert report.model_id_configured == "ep-20260909180104-hmx9m"
    assert report.model_identity_match is False
    assert report.endpoint_host == "example.invalid"
    assert report.endpoint_path == "/api/v3/chat/completions"
    assert "configured_model_environment_mismatch" in report.blockers
    assert all(command[0] in {"git", "docker"} for command in commands)


def test_probe_dry_run_creates_no_launch_marker(tmp_path: Path) -> None:
    run_root = tmp_path / "cap-compat-test-0001"
    run_root.mkdir()
    snapshot = run_root / "compatibility_config.snapshot.json"
    config = json.loads(CONFIG.read_text(encoding="utf-8"))
    config.update(run_id="cap-compat-test-0001", output_root=str(run_root))
    snapshot.write_text(json.dumps(config), encoding="utf-8")
    payload = {
        "schema_version": "capability-compatibility-preparation/1.0",
        "batch_id": "cap-compat-test-0001",
        "run_root": str(run_root),
        "config_hash": file_hash(snapshot),
        "source_config_hash": file_hash(CONFIG),
        "compilation_manifest_hash": "a" * 64,
        "task_hash": "b" * 64,
        "patch_hash": "c" * 64,
        "bridge_hash": "d" * 64,
        "processing_source_hash": "f" * 64,
        "model_id": config["model_id"],
        "endpoint_host": "example.invalid",
        "endpoint_path": "/api/v3/chat/completions",
        "stages": config["stages"],
        "execution_enabled": False,
        "authorization_needed": True,
        "network_requests_performed": False,
    }
    manifest = CompatibilityPreparationManifest.model_validate(
        {**payload, "manifest_hash": stable_hash(payload)}
    )
    legacy = {key: value for key, value in payload.items() if key != "processing_source_hash"}
    assert (
        CompatibilityPreparationManifest.model_validate(
            {**legacy, "manifest_hash": stable_hash(legacy)}
        ).processing_source_hash
        is None
    )
    (run_root / "preparation_manifest.json").write_text(
        manifest.model_dump_json(indent=2), encoding="utf-8"
    )
    status = run_compatibility_stage(ROOT, run_root, "P0", authorized=False, dry_run=True)
    assert status.reason_codes == ["dry_run_no_request"]
    assert status.provider_attempts_stage == 0
    assert not (run_root / "launch-P0.reserved").exists()


def test_probe_without_authorization_fails_before_launch(tmp_path: Path) -> None:
    run_root = tmp_path / "cap-compat-test-0002"
    run_root.mkdir()
    snapshot = run_root / "compatibility_config.snapshot.json"
    config = json.loads(CONFIG.read_text(encoding="utf-8"))
    config.update(run_id="cap-compat-test-0002", output_root=str(run_root))
    snapshot.write_text(json.dumps(config), encoding="utf-8")
    payload = {
        "schema_version": "capability-compatibility-preparation/1.0",
        "batch_id": "cap-compat-test-0002",
        "run_root": str(run_root),
        "config_hash": file_hash(snapshot),
        "source_config_hash": file_hash(CONFIG),
        "compilation_manifest_hash": "a" * 64,
        "task_hash": "b" * 64,
        "patch_hash": "c" * 64,
        "bridge_hash": "d" * 64,
        "processing_source_hash": "f" * 64,
        "model_id": config["model_id"],
        "endpoint_host": None,
        "endpoint_path": None,
        "stages": config["stages"],
        "execution_enabled": False,
        "authorization_needed": True,
        "network_requests_performed": False,
    }
    manifest = CompatibilityPreparationManifest.model_validate(
        {**payload, "manifest_hash": stable_hash(payload)}
    )
    (run_root / "preparation_manifest.json").write_text(
        manifest.model_dump_json(indent=2), encoding="utf-8"
    )
    with pytest.raises(PermissionError, match="capability_live_authorization_missing"):
        run_compatibility_stage(ROOT, run_root, "P0", authorized=False)
    assert not (run_root / "launch-P0.reserved").exists()


def test_binding_is_single_use_and_invalid_hash_fails_before_launch(tmp_path: Path) -> None:
    run_root = tmp_path / "cap-compat-test-0003"
    run_root.mkdir()
    config = json.loads(CONFIG.read_text(encoding="utf-8"))
    config.update(run_id=run_root.name, output_root=str(run_root))
    source = run_root / "compatibility_config.snapshot.json"
    source.write_text(json.dumps(config), encoding="utf-8")
    payload = {
        "schema_version": "capability-compatibility-preparation/1.0",
        "batch_id": run_root.name,
        "run_root": str(run_root),
        "config_hash": file_hash(source),
        "source_config_hash": file_hash(CONFIG),
        "compilation_manifest_hash": "a" * 64,
        "task_hash": "b" * 64,
        "patch_hash": "c" * 64,
        "bridge_hash": "d" * 64,
        "processing_source_hash": "f" * 64,
        "model_id": config["model_id"],
        "endpoint_host": "example.invalid",
        "endpoint_path": "/api/v3/chat/completions",
        "stages": config["stages"],
        "execution_enabled": False,
        "authorization_needed": True,
        "network_requests_performed": False,
    }
    manifest = CompatibilityPreparationManifest.model_validate(
        {**payload, "manifest_hash": stable_hash(payload)}
    )
    (run_root / "preparation_manifest.json").write_text(manifest.model_dump_json())
    bound = bind_compatibility_execution(run_root, "synthetic-test-reference")
    with pytest.raises(FileExistsError):
        bind_compatibility_execution(run_root, "second-reference")
    bound.write_text(bound.read_text() + " ")
    with pytest.raises(ValueError, match="capability_execution_binding_invalid"):
        run_compatibility_stage(ROOT, run_root, "P0", authorized=True)
    assert not (run_root / "launch-P0.reserved").exists()


def test_status_marks_launched_missing_ledger_as_unknown(tmp_path: Path) -> None:
    run_root = tmp_path / "cap-compat-test-0004"
    run_root.mkdir()
    config = json.loads(CONFIG.read_text(encoding="utf-8"))
    payload = {
        "schema_version": "capability-compatibility-preparation/1.0",
        "batch_id": run_root.name,
        "run_root": str(run_root),
        "config_hash": "a" * 64,
        "source_config_hash": "b" * 64,
        "compilation_manifest_hash": "c" * 64,
        "task_hash": "d" * 64,
        "patch_hash": "e" * 64,
        "bridge_hash": "f" * 64,
        "processing_source_hash": "a" * 64,
        "model_id": config["model_id"],
        "endpoint_host": None,
        "endpoint_path": None,
        "stages": config["stages"],
        "execution_enabled": False,
        "authorization_needed": True,
        "network_requests_performed": False,
    }
    manifest = CompatibilityPreparationManifest.model_validate(
        {**payload, "manifest_hash": stable_hash(payload)}
    )
    (run_root / "preparation_manifest.json").write_text(manifest.model_dump_json())
    (run_root / "stage_status").mkdir()
    for stage in ("P0", "P1", "P2"):
        (run_root / f"stage_status/{stage}.json").write_text(
            json.dumps(
                {
                    "batch_id": run_root.name,
                    "stage_id": stage,
                    "execution_status": "not_started",
                    "verdict": "not_evaluated",
                    "reason_codes": ["not_started"],
                    "provider_attempts_before": 0,
                    "provider_attempts_after": 0,
                    "provider_attempts_stage": 0,
                    "embedding_attempts": 0,
                    "result_ref": None,
                    "cleanup_status": "not_applicable",
                }
            )
        )
    (run_root / "launch-P0.reserved").touch()
    status = read_compatibility_status(run_root)
    assert status["provider_attempts_remaining"] is None
    assert status["network_requests_performed"] is None
    assert status["next_stage"] is None
