from __future__ import annotations

import json
from pathlib import Path

import pytest

from stac_attack_lab.capability.compiler import (
    compile_cases,
    inventory_upstream,
    validate_compatibility_config,
    validate_compilation,
    validate_split_assignments,
)
from stac_attack_lab.capability.models import RuntimeTask

ROOT = Path(__file__).resolve().parents[2]
CONFIG = ROOT / "configs/capability/f1_status_acceptance.json"


def test_compiler_changes_only_low_trust_material_and_separates_views(tmp_path: Path) -> None:
    compiled = compile_cases(CONFIG, tmp_path / "compiled")
    manifest = validate_compilation(compiled)
    tasks = [
        RuntimeTask.model_validate_json((compiled / ref).read_text(encoding="utf-8"))
        for ref in manifest.case_refs
    ]
    assert len({task.case.contract_hash for task in tasks}) == 1
    assert len({task.case.low_trust_material for task in tasks}) == 3
    for task in tasks:
        public = task.public_view.model_dump(mode="json")
        text = json.dumps(public).lower()
        assert "private_oracle" not in text
        assert "harmful_status" not in text
        assert "planned_node" not in text
        assert "variant" not in public
        assert task.case.case_id not in text
        assert task.upstream_schema_compatible is False


def test_private_marker_hidden_in_material_is_rejected(tmp_path: Path) -> None:
    payload = json.loads(CONFIG.read_text(encoding="utf-8"))
    payload["materials"]["semantic"] += " private_oracle"
    config = tmp_path / "leaky.json"
    config.write_text(json.dumps(payload), encoding="utf-8")
    with pytest.raises(ValueError, match="capability_private_view_leak"):
        compile_cases(config, tmp_path / "compiled")


def test_variants_and_duplicates_cannot_cross_data_splits() -> None:
    with pytest.raises(ValueError, match="capability_split_group_crosses_data_split"):
        validate_split_assignments([("base-1", "dev"), ("base-1", "test")])


def test_pinned_upstream_inventory_records_official_semantic_boundaries() -> None:
    report = inventory_upstream(ROOT / "integrations/safeclaw/upstream/SafeClawArena")
    assert report["upstream_commit"] == "a11f5cceaba0676be721021f8d232638fd111305"
    assert report["task_count"] == 406
    assert report["upstream_worktree_clean"] is True
    assert report["extension_upstream_schema_compatible"] is False
    assert report["pse_metric"] == "PSE-Score"
    reasons = {item["reason_code"] for item in report["compatibility_boundaries"]}
    assert {
        "official_pse_attack_success_uses_any_check",
        "official_failed_preconditions_do_not_abort_session",
        "official_session_key_shared_without_restart",
        "official_memory_checks_post_state_without_actor_lineage",
    } <= reasons


def test_real_compatibility_template_is_concrete_disabled_and_zero_retry() -> None:
    config = validate_compatibility_config(
        ROOT / "configs/capability/provider_compatibility.disabled.json"
    )
    assert config.execution_enabled is False
    assert config.max_attacker_http_attempts == 0
    assert config.max_victim_http_attempts == config.max_batch_http_attempts == 3
    assert config.max_embedding_http_attempts == 0
    assert config.automatic_retries == 0
    assert config.authorization_reference is None
