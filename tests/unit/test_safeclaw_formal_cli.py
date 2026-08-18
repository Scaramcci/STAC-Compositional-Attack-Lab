from __future__ import annotations

import json
from pathlib import Path

import pytest

from stac_attack_lab.cli import _main
from stac_attack_lab.execution.safeclaw_formal import (
    FormalTaskEntry,
    load_formal_task_set,
    load_safeclaw_formal_config,
)
from stac_attack_lab.hashing import file_hash

ROOT = Path(__file__).resolve().parents[2]


def test_repository_formal_config_is_explicitly_fail_closed(
    capsys: pytest.CaptureFixture[str],
) -> None:
    config_path = ROOT / "configs/experiments/safeclaw_formal_v1.yaml"
    config = load_safeclaw_formal_config(config_path)
    task_set = load_formal_task_set(ROOT / config.task_set_path)

    assert config.execution_enabled is False
    assert config.require_frozen_library is True
    assert "no_sample" in config.conditions
    assert task_set.tasks[0].sample_derived_slots == [
        "untrusted_source",
        "agent_context",
        "persistent_memory",
    ]
    assert task_set.tasks[0].template_hash == file_hash(ROOT / task_set.tasks[0].template_path)
    assert task_set.status == "blocked"
    assert task_set.blocked_reason is not None

    exit_code = _main(["safeclaw", "run", "--config", str(config_path)])
    output = capsys.readouterr().out

    assert exit_code == 2
    assert "formal_execution_disabled_by_config" in output
    assert "API_KEY=" not in output


def test_formal_task_entry_rejects_unmatched_baseline_slots() -> None:
    payload = json.loads(
        (ROOT / "configs/task_sets/safeclaw_compositional_v1.yaml").read_text(encoding="utf-8")
    )["tasks"][0]
    payload["baseline_materialization_values"].pop("persistent_memory")

    with pytest.raises(ValueError, match="baseline_materialization_slot_set_mismatch"):
        FormalTaskEntry.model_validate(payload)
