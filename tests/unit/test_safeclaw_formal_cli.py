from __future__ import annotations

from pathlib import Path

import pytest

from stac_attack_lab.cli import _main
from stac_attack_lab.execution.safeclaw_formal import (
    load_formal_task_set,
    load_safeclaw_formal_config,
)

ROOT = Path(__file__).resolve().parents[2]


def test_repository_formal_config_is_explicitly_fail_closed(
    capsys: pytest.CaptureFixture[str],
) -> None:
    config_path = ROOT / "configs/experiments/safeclaw_formal_v1.yaml"
    config = load_safeclaw_formal_config(config_path)
    task_set = load_formal_task_set(ROOT / config.task_set_path)

    assert config.execution_enabled is False
    assert config.require_frozen_library is True
    assert task_set.status == "blocked"
    assert task_set.blocked_reason is not None

    exit_code = _main(["safeclaw", "run", "--config", str(config_path)])
    output = capsys.readouterr().out

    assert exit_code == 2
    assert "formal_execution_disabled_by_config" in output
    assert "API_KEY=" not in output
