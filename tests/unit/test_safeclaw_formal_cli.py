from __future__ import annotations

import json
from pathlib import Path

import pytest

from stac_attack_lab.execution.safeclaw_formal import (
    FormalTaskEntry,
    load_formal_task_set,
    load_safeclaw_formal_config,
    run_safeclaw_formal,
)

ROOT = Path(__file__).resolve().parents[2]


def test_repository_formal_config_is_ready_for_authorized_execution() -> None:
    config_path = ROOT / "configs/experiments/safeclaw_formal_v1.yaml"
    config = load_safeclaw_formal_config(config_path)
    task_set = load_formal_task_set(ROOT / config.task_set_path)

    assert config.execution_enabled is True
    assert config.require_frozen_library is True
    assert "no_sample" in config.conditions
    assert task_set.tasks[0].sample_derived_slots == [
        "untrusted_source",
        "agent_context",
        "persistent_memory",
    ]
    assert task_set.tasks[0].task_id == "pse-2.1-001"
    assert task_set.tasks[0].template_hash == (
        "05b1559d80084aff6b9723bcaa21f8edb00897ba2aeba456cb5f6eea25c0df42"
    )
    assert task_set.tasks[0].formal_experiment is not None
    assert task_set.status == "ready"
    assert task_set.blocked_reason is None


def test_formal_runner_rejects_non_allowlisted_target_before_execution() -> None:
    config = load_safeclaw_formal_config(
        ROOT / "configs/experiments/safeclaw_formal_v1.yaml"
    ).model_copy(
        update={
            "execution_enabled": True,
            "allowed_target_models": ["gemini-2.5-flash"],
        }
    )

    with pytest.raises(ValueError, match="formal_target_model_not_allowed:synthetic-model"):
        run_safeclaw_formal(
            ROOT,
            config,
            environment={
                "SAFECLAW_MODEL": "synthetic-model",
                "OPENAI_BASE_URL": "http://127.0.0.1:9999/v1",
                "OPENAI_API_KEY": "synthetic-key",
            },
        )


def test_formal_task_entry_rejects_unmatched_baseline_slots() -> None:
    payload = json.loads(
        (ROOT / "configs/task_sets/safeclaw_compositional_v1.yaml").read_text(encoding="utf-8")
    )["tasks"][0]
    payload["baseline_materialization_values"].pop("persistent_memory")

    with pytest.raises(ValueError, match="baseline_materialization_slot_set_mismatch"):
        FormalTaskEntry.model_validate(payload)
