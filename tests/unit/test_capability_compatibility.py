from __future__ import annotations

import json
from pathlib import Path

import pytest

import stac_attack_lab.capability.compatibility as compatibility
from stac_attack_lab.capability.compatibility import (
    diagnose_capability_compatibility,
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
    run_root = tmp_path / "prepared"
    run_root.mkdir()
    snapshot = run_root / "compatibility_config.snapshot.json"
    snapshot.write_bytes(CONFIG.read_bytes())
    config = json.loads(snapshot.read_text(encoding="utf-8"))
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
    (run_root / "preparation_manifest.json").write_text(
        manifest.model_dump_json(indent=2), encoding="utf-8"
    )
    status = run_compatibility_stage(ROOT, run_root, "P0", authorized=False, dry_run=True)
    assert status.reason_codes == ["dry_run_no_request"]
    assert status.provider_attempts_stage == 0
    assert not (run_root / "launch-P0.reserved").exists()


def test_probe_without_authorization_fails_before_launch(tmp_path: Path) -> None:
    run_root = tmp_path / "prepared"
    run_root.mkdir()
    snapshot = run_root / "compatibility_config.snapshot.json"
    snapshot.write_bytes(CONFIG.read_bytes())
    config = json.loads(snapshot.read_text(encoding="utf-8"))
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
