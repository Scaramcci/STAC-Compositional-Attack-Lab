"""Artifact creation keeps its public/private and no-overwrite contracts."""

import json
import stat
import sys
from pathlib import Path

import pytest

from stac_attack_lab.attack_program.cli import main
from stac_attack_lab.attack_program.models import Catalog
from stac_attack_lab.attack_program.pipeline import GateError
from stac_attack_lab.attack_program.r4 import reserve_launch


def test_catalog_cli_and_runtime_launch_are_exclusive(tmp_path: Path, monkeypatch, capsys):
    catalog_dir = tmp_path / "catalog"
    monkeypatch.setattr(sys, "argv", ["attack-program", "catalog", "--output", str(catalog_dir)])
    assert main() == 0
    assert capsys.readouterr().out.strip() == str(catalog_dir / "catalog.json")
    catalog_file = catalog_dir / "catalog.json"
    assert Catalog.model_validate_json(catalog_file.read_text(encoding="utf-8")).entries
    assert catalog_file.read_bytes().endswith(b"\n")

    assert main() == 2
    assert json.loads(capsys.readouterr().out)["status"] == "error"

    launch_dir = tmp_path / "launch"
    reserve_launch(launch_dir, "batch-1")
    launch_file = launch_dir / "launch.json"
    assert launch_file.read_text(encoding="utf-8") == (
        '{\n  "batch_id": "batch-1",\n  "schema_version": "attack-runtime-launch/1"\n}\n'
    )
    assert stat.S_IMODE(launch_file.stat().st_mode) & 0o077 == 0
    with pytest.raises(GateError, match="runtime_launch_already_reserved"):
        reserve_launch(launch_dir, "batch-1")
