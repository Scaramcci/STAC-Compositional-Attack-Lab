from __future__ import annotations

import json
import subprocess
from pathlib import Path

from stac_attack_lab.environments.safeclaw.workspace_snapshot import (
    CONTAINER_CAPTURE_SCRIPT,
    validate_workspace_snapshot,
)


def _capture(root: Path, stage: str = "initial") -> dict[str, object]:
    result = subprocess.run(
        ["python", "-c", CONTAINER_CAPTURE_SCRIPT, str(root), stage, "test-run"],
        text=True,
        capture_output=True,
        check=True,
        timeout=5,
    )
    value = json.loads(result.stdout)
    assert isinstance(value, dict)
    return value


def _write_fixture(root: Path) -> None:
    (root / "reports").mkdir(parents=True)
    (root / "trusted").mkdir(parents=True)
    (root / "reports/status.json").write_text('{"projects":{}}', encoding="utf-8")
    (root / "trusted/acceptance-ledger.json").write_text("{}", encoding="utf-8")


def test_capture_observes_preexisting_file_overwrite(tmp_path: Path) -> None:
    _write_fixture(tmp_path)
    initial, initial_reasons = validate_workspace_snapshot(
        _capture(tmp_path, "initial"), expected_stage="initial"
    )
    (tmp_path / "reports/status.json").write_text(
        '{"projects":{"project-b":{"status":"accepted"}}}', encoding="utf-8"
    )
    final, final_reasons = validate_workspace_snapshot(
        _capture(tmp_path, "final"), expected_stage="final"
    )
    assert not initial_reasons
    assert not final_reasons
    assert initial["reports/status.json"] != final["reports/status.json"]


def test_capture_rejects_symlink_and_oversized_file(tmp_path: Path) -> None:
    _write_fixture(tmp_path)
    outside = tmp_path.parent / f"{tmp_path.name}-outside.json"
    outside.write_text("{}", encoding="utf-8")
    (tmp_path / "reports/status.json").unlink()
    (tmp_path / "reports/status.json").symlink_to(outside)
    (tmp_path / "trusted/acceptance-ledger.json").write_text("x" * 65_537, encoding="utf-8")
    contents, reasons = validate_workspace_snapshot(_capture(tmp_path))
    assert contents == {}
    assert "capability_file_symlink_rejected" in reasons
    assert "capability_file_size_limit" in reasons


def test_snapshot_rejects_unknown_path_and_recomputed_inconsistent_metadata() -> None:
    value = {
        "schema_version": "1.0",
        "stage": "initial",
        "files": [
            {
                "path": "../private-oracle.json",
                "status": "observed",
                "reason_code": None,
                "content": "{}",
                "content_sha256": "0" * 64,
                "size_bytes": 2,
                "truncated": False,
            }
        ],
    }
    contents, reasons = validate_workspace_snapshot(value, expected_stage="initial")
    assert contents == {}
    assert "capability_workspace_snapshot_path_invalid" in reasons
    assert "capability_file_record_missing:reports/status.json" in reasons


def test_snapshot_stage_and_hash_are_bound() -> None:
    value = {
        "schema_version": "1.0",
        "stage": "final",
        "files": [
            {
                "path": "reports/status.json",
                "status": "observed",
                "reason_code": None,
                "content": "{}",
                "content_sha256": "0" * 64,
                "size_bytes": 2,
                "truncated": False,
            },
            {
                "path": "trusted/acceptance-ledger.json",
                "status": "missing",
                "reason_code": "capability_file_missing",
                "content": None,
                "content_sha256": None,
                "size_bytes": None,
                "truncated": False,
            },
        ],
    }
    assert validate_workspace_snapshot(value, expected_stage="initial") == (
        {},
        ["capability_workspace_snapshot_stage_mismatch"],
    )
    contents, reasons = validate_workspace_snapshot(value, expected_stage="final")
    assert contents == {}
    assert "capability_file_observation_integrity_mismatch" in reasons
    assert "capability_file_missing" in reasons
