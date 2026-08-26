from __future__ import annotations

from pathlib import Path

import pytest
from pydantic import ValidationError

from stac_attack_lab.environments.safeclaw.preflight import (
    load_safeclaw_preflight_config,
)
from stac_attack_lab.execution.safeclaw_formal import (
    load_formal_task_set,
    load_safeclaw_formal_config,
)
from stac_attack_lab.execution.sample_generation import (
    SampleGenerationConfig,
    load_sample_generation_config,
)
from stac_attack_lab.hashing import file_hash
from stac_attack_lab.interactions.base import CollectionBudget
from stac_attack_lab.interactions.safeclaw_collection import (
    SafeClawConstructionTaskSet,
)

ROOT = Path(__file__).resolve().parents[2]


def test_v2_collection_campaign_is_bounded_disjoint_and_hash_pinned() -> None:
    main = load_sample_generation_config(
        ROOT / "configs/sample_generation/safeclaw_adversarial_v2.yaml"
    )
    pilot = load_sample_generation_config(
        ROOT / "configs/sample_generation/safeclaw_adversarial_v2_pilot.yaml"
    )
    task_set = SafeClawConstructionTaskSet.model_validate_json(
        (ROOT / str(main.construction_task_set_path)).read_text(encoding="utf-8")
    )

    assert len(main.source_task_ids) * len(main.effective_seeds) == 120
    assert main.max_collection_trajectories == 120
    assert main.target_accepted_samples == 30
    assert len(pilot.source_task_ids) * len(pilot.effective_seeds) == 4
    assert pilot.max_collection_trajectories == 4
    assert pilot.target_accepted_samples == 2
    assert main.embedding_provider == "openai"
    assert main.embedding_model_env == "SAFECLAW_EMBEDDING_MODEL"
    assert main.embedding_base_url_env == "SAFECLAW_EMBEDDING_BASE_URL"
    assert main.embedding_api_key_env == "SAFECLAW_EMBEDDING_API_KEY"
    assert set(pilot.source_task_ids) < set(main.source_task_ids)
    assert set(main.source_task_ids) == {task.source_task_id for task in task_set.tasks}
    assert not set(main.source_task_ids) & set(task_set.formal_excluded_task_ids)
    for task in task_set.tasks:
        template = ROOT / task.template_path
        assert template.is_file()
        assert file_hash(template) == task.template_hash

    with pytest.raises(ValidationError, match="sample_collection_matrix_exceeds_trajectory_cap"):
        SampleGenerationConfig.model_validate(
            {**main.model_dump(mode="json"), "max_collection_trajectories": 119}
        )


def test_v2_independent_collection_budget_contract_fails_closed() -> None:
    main = load_sample_generation_config(
        ROOT / "configs/sample_generation/safeclaw_adversarial_v2.yaml"
    )

    assert CollectionBudget(
        max_sessions=main.max_sessions,
        max_turns=main.max_turns,
        max_actions=main.max_actions,
        max_tool_calls=main.max_tool_calls,
        max_tokens=main.max_tokens,
        max_wall_time_seconds=main.max_wall_time_seconds,
        max_events=main.max_events,
        timeout_seconds=main.timeout_seconds,
    )
    with pytest.raises(ValidationError, match="collection_turn_budget_below_session_budget"):
        CollectionBudget(max_sessions=4, max_turns=3)
    with pytest.raises(ValidationError, match="collection_action_budget_below_turn_budget"):
        CollectionBudget(max_sessions=2, max_turns=4, max_actions=3)
    with pytest.raises(
        ValidationError, match="collection_request_timeout_exceeds_wall_time_budget"
    ):
        CollectionBudget(timeout_seconds=301, max_wall_time_seconds=300)


def test_v2_formal_matrix_is_three_condition_and_coverage_limited() -> None:
    formal = load_safeclaw_formal_config(ROOT / "configs/experiments/safeclaw_formal_v2.yaml")
    environment = load_safeclaw_preflight_config(ROOT / formal.environment_config_path)
    task_set = load_formal_task_set(ROOT / formal.task_set_path)

    assert formal.conditions == [
        "assigned_sample",
        "no_sample",
        "dependency_ablation",
    ]
    assert len(formal.conditions) * len(formal.seeds) * len(task_set.tasks) == 15
    assert formal.allowed_target_models == ["gpt-5.5"]
    assert environment.allowed_target_models == formal.allowed_target_models
    assert environment.embedding_policy == "required_endpoint"
    assert environment.embedding_provider == "openai"
    assert environment.embedding_model_env == "SAFECLAW_EMBEDDING_MODEL"
    assert environment.embedding_base_url_env == "SAFECLAW_EMBEDDING_BASE_URL"
    assert environment.embedding_api_key_env == "SAFECLAW_EMBEDDING_API_KEY"
    assert task_set.task_set_id.endswith("coverage-limited")
    assert [task.task_id for task in task_set.tasks] == ["pse-2.1-001"]
    for task in task_set.tasks:
        template = ROOT / task.template_path
        assert template.is_file()
        assert file_hash(template) == task.template_hash

    assert formal.library_path == ("data/primitive_libraries/frozen/formal-v3-safeclaw-20260824")
    assert not (ROOT / formal.library_path).exists()
