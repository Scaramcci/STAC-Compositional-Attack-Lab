from __future__ import annotations

import json
from pathlib import Path

import pytest

from stac_attack_lab.cli import _main

ROOT = Path(__file__).resolve().parents[2]


def test_safeclaw_inventory_cli_emits_no_private_oracle(
    capsys: pytest.CaptureFixture[str],
) -> None:
    exit_code = _main(
        [
            "safeclaw",
            "inventory",
            "--upstream",
            str(ROOT),
            "--task",
            "tests/fixtures/safeclaw/compositional_task.json",
        ]
    )
    output = capsys.readouterr().out

    assert exit_code == 0
    assert "CANARY_PRIVATE_EVALUATION_ONLY" not in output
    assert "official_success_condition_hash" in output


def test_safeclaw_pse_smoke_resolves_project_root_task_path(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    captured: dict[str, Path] = {}

    def fake_smoke(judge_path: Path, task_path: Path):
        captured["judge"] = judge_path
        captured["task"] = task_path
        return type(
            "Report", (), {"passed": True, "model_dump_json": lambda self, indent=2: "{}"}
        )()

    monkeypatch.setattr("stac_attack_lab.cli.smoke_official_pse_evaluator", fake_smoke)
    exit_code = _main(
        [
            "safeclaw",
            "pse-smoke",
            "--upstream",
            "integrations/safeclaw/upstream/SafeClawArena",
            "--task",
            "integrations/safeclaw/upstream/SafeClawArena/tasks/pse/pse-2.1-002.json",
        ]
    )
    capsys.readouterr()
    assert exit_code == 0
    assert (
        captured["task"]
        == (
            ROOT / "integrations/safeclaw/upstream/SafeClawArena/tasks/pse/pse-2.1-002.json"
        ).resolve()
    )


@pytest.mark.parametrize("reported", [0, 10, 20, 30])
def test_revalidation_cli_uses_explicit_stage_exit_semantics(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, reported: int
) -> None:
    run_root = tmp_path / "run"
    run_root.mkdir()
    monkeypatch.setattr("stac_attack_lab.cli.project_root", lambda: tmp_path)
    monkeypatch.setattr("stac_attack_lab.cli.load_project_env", lambda _root: None)
    monkeypatch.setattr(
        "stac_attack_lab.cli.offline_revalidation",
        lambda *_args: {"exit_code": reported, "overall_status": "test"},
    )
    assert _main(["revalidation", "offline", "--run-root", "run"]) == reported


def test_sample_admission_cli_structural_pass_is_not_failed_by_missing_authorization(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    collection, library = tmp_path / "collection", tmp_path / "library"
    collection.mkdir()
    library.mkdir()
    monkeypatch.setattr("stac_attack_lab.cli.project_root", lambda: tmp_path)
    monkeypatch.setattr("stac_attack_lab.cli.load_project_env", lambda _root: None)
    monkeypatch.setattr(
        "stac_attack_lab.cli.audit_construction_collection",
        lambda *_args: {
            "structural_admission": {"status": "passed"},
            "runtime_review": {"status": "pending"},
            "execution_authorization": {"status": "absent"},
            "pilot_admitted": False,
        },
    )
    exit_code = _main(["sample", "admission", "--collection", "collection", "--library", "library"])
    output = json.loads(capsys.readouterr().out)
    assert exit_code == 0
    assert output["structural_admission"]["status"] == "passed"
    assert output["pilot_admitted"] is False
