from __future__ import annotations

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
