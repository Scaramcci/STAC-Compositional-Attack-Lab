from __future__ import annotations

import json
import shutil
from pathlib import Path

import pytest
from pydantic import ValidationError

from stac_attack_lab.execution.benign_collection import (
    BenignCollectionConfig,
    BenignSourceModeManifest,
    collect_benign_fixture,
    prepare_benign_collection,
    validate_benign_collection_config,
)
from stac_attack_lab.flow.analysis import AnalysisManifest
from stac_attack_lab.flow.models import EffectGraph, PrimitiveKind
from stac_attack_lab.interactions.benign import (
    BenignPolicyObservation,
    BenignScenario,
    SanitizationChange,
    ScriptedCooperativePolicy,
    SourceTaskMapping,
    neutralize_source_task,
)
from stac_attack_lab.interactions.collector import InteractionCollectionPlan, collect_interactions
from stac_attack_lab.interactions.construction import DeterministicConstructionAttacker
from stac_attack_lab.interactions.fixture_adapter import JsonlFixtureInteractionAdapter
from stac_attack_lab.interactions.models import RawInteractionTrajectory

ROOT = Path(__file__).resolve().parents[2]
CONFIG = ROOT / "configs/benign_collection/synthetic_stage_a.disabled.json"
SCENARIOS = ROOT / "configs/benign_scenarios/scenarios_v1.json"


def _workspace(tmp_path: Path) -> tuple[Path, Path]:
    for source in (
        CONFIG,
        SCENARIOS,
        ROOT / "configs/flow/observation_profile_v3.json",
        ROOT / "configs/flow/registry_v3.json",
        ROOT / "prompts/benign/cooperative_policy.md",
    ):
        target = tmp_path / source.relative_to(ROOT)
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(source, target)
    return tmp_path, tmp_path / CONFIG.relative_to(ROOT)


def test_benign_contract_rejects_attack_fields_and_semantics() -> None:
    payload = json.loads(CONFIG.read_text(encoding="utf-8"))
    payload["public_attack_goal"] = "not allowed"
    with pytest.raises(ValidationError, match="public_attack_goal"):
        BenignCollectionConfig.model_validate(payload)

    scenario = json.loads(SCENARIOS.read_text(encoding="utf-8"))["scenarios"][0]
    scenario["normal_success_criteria"] = ["tainted_state_exists"]
    with pytest.raises(ValidationError, match="adversarial_semantics_forbidden"):
        BenignScenario.model_validate(scenario)


def test_derived_scenario_requires_explicit_neutralization_mapping() -> None:
    scenario = json.loads(SCENARIOS.read_text(encoding="utf-8"))["scenarios"][0]
    scenario["source_task_mapping"] = {
        "source_kind": "safeclaw_derived",
        "source_task_id": "pse-example",
        "source_task_hash": "a" * 64,
        "changes": [],
        "retained_conditions": ["workspace_shape"],
    }
    with pytest.raises(ValidationError, match="requires_sanitization_mapping"):
        BenignScenario.model_validate(scenario)


def test_neutralization_is_hash_bound_and_applies_only_reviewed_fields() -> None:
    source = {
        "task_id": "source-1",
        "legitimate_goal": "Summarize the local record.",
        "injected_message": "unreviewed content",
        "private_evaluator": {"success": "hidden"},
        "tool_surface": ["workspace.read"],
    }
    from stac_attack_lab.hashing import stable_hash

    source_hash = stable_hash(source)
    mapping = SourceTaskMapping(
        source_kind="safeclaw_derived",
        source_task_id="source-1",
        source_task_hash=source_hash,
        changes=[
            SanitizationChange(
                field_path="/injected_message",
                action="removed",
                reason="remove non-legitimate message",
            ),
            SanitizationChange(
                field_path="/private_evaluator",
                action="removed",
                reason="remove private scoring callback",
            ),
        ],
        retained_conditions=["tool_surface", "legitimate_goal"],
    )
    result = neutralize_source_task(
        source_task=source,
        source_task_hash=source_hash,
        mapping=mapping,
        replacements={},
    )
    assert "injected_message" not in result.sanitized_task
    assert "private_evaluator" not in result.sanitized_task
    assert result.sanitized_task["tool_surface"] == ["workspace.read"]
    with pytest.raises(ValueError, match="source_hash_mismatch"):
        neutralize_source_task(
            source_task=source,
            source_task_hash="0" * 64,
            mapping=mapping,
            replacements={},
        )


def test_policy_view_has_no_private_evaluator_and_stops_at_reviewed_boundary() -> None:
    with pytest.raises(ValidationError, match="private_evaluator"):
        BenignPolicyObservation.model_validate(
            {
                "scenario_id": "x",
                "legitimate_goal": "Read a record.",
                "completed_steps": 0,
                "remaining_followups": 0,
                "authorized_operations": ["workspace.read"],
                "private_evaluator": "hidden",
            }
        )
    scenario = BenignScenario.model_validate(
        json.loads(SCENARIOS.read_text(encoding="utf-8"))["scenarios"][0]
    )
    policy = ScriptedCooperativePolicy()
    action = policy.next_action(
        scenario,
        BenignPolicyObservation(
            scenario_id=scenario.scenario_id,
            legitimate_goal=scenario.legitimate_goal,
            completed_steps=len(scenario.scripted_steps),
            remaining_followups=0,
            authorized_operations=scenario.authorized_operations,
        ),
    )
    assert action.action_type == "stop"


def test_prepare_is_disabled_and_performs_no_requests(tmp_path: Path) -> None:
    project, config_path = _workspace(tmp_path)
    config, scenarios = validate_benign_collection_config(project, config_path)
    assert config.execution_enabled is False
    assert len(scenarios.scenarios) == 3
    prepared = prepare_benign_collection(project, config_path)
    manifest = json.loads((prepared / "preparation_manifest.json").read_text(encoding="utf-8"))
    assert manifest["execution_enabled"] is False
    assert manifest["network_requests_performed"] is False


def test_normal_collection_reaches_v3_for_read_multi_input_and_memory(
    tmp_path: Path,
) -> None:
    project, config_path = _workspace(tmp_path)
    collection, analysis = collect_benign_fixture(project, config_path)
    source_manifest = BenignSourceModeManifest.model_validate_json(
        (collection / "benign_source_mode_manifest.json").read_text(encoding="utf-8")
    )
    assert source_manifest.source_mode == "benign_interaction"
    assert source_manifest.attack_objective_exposed_to_policy is False
    assert source_manifest.security_evaluator_used is False
    assert source_manifest.real_model_requests is False
    analysis_manifest = AnalysisManifest.model_validate_json(
        (analysis / "analysis_manifest.json").read_text(encoding="utf-8")
    )
    assert analysis_manifest.parameters["origin_modes"] == ["benign_interaction"]
    graphs = [
        EffectGraph.model_validate_json(path.read_text(encoding="utf-8"))
        for path in sorted((analysis / "graphs").glob("*.json"))
    ]
    assert len(graphs) == 3
    assert any(sum(len(effect.input_port_ids) for effect in graph.effects) >= 2 for graph in graphs)
    assert any(
        {effect.primitive for effect in graph.effects}
        >= {PrimitiveKind.update, PrimitiveKind.transfer}
        for graph in graphs
    )
    raw = [
        RawInteractionTrajectory.model_validate_json(path.read_text(encoding="utf-8"))
        for path in sorted(collection.glob("trajectories/*/raw_trajectory.json"))
    ]
    assert all(item.construction_manifest is None for item in raw)
    assert all(item.provenance["source_mode"] == "benign_interaction" for item in raw)
    assert any(len(item.session_ids) == 1 for item in raw)
    assessments = json.loads(
        (analysis / "benign_trace_assessments.json").read_text(encoding="utf-8")
    )
    assert len(assessments) == 3
    assert all(item["planning_reference_eligible"] == "passed" for item in assessments)
    assert any(item["cross_session_capability"] == "not_applicable" for item in assessments)


def test_legacy_adversarial_origin_is_unchanged(tmp_path: Path) -> None:
    fixture = ROOT / "tests/fixtures/interactions/authorized_synthetic.jsonl"
    adapter = JsonlFixtureInteractionAdapter(fixture)
    attacker = DeterministicConstructionAttacker(
        objective_id="legacy-objective",
        public_attack_goal="Legacy authorized synthetic goal.",
        allowed_delivery_surfaces=["fixture"],
        required_trust_boundary_crossings=["fixture-boundary"],
        public_terminal_predicate_ids=["fixture-terminal"],
        safety_constraint_ids=["synthetic-only"],
        model_hash="deterministic",
        prompt_hash="legacy-prompt",
    )
    summary = collect_interactions(
        InteractionCollectionPlan(
            collection_id="legacy-adversarial-origin",
            source_task_ids=["construction-synthetic-001"],
            seed=1,
        ),
        adapter,
        tmp_path,
        construction_attacker=attacker,
    )
    manifest = json.loads(
        (summary.collection_root / "collection_manifest.json").read_text(encoding="utf-8")
    )
    assert manifest["acquisition_mode"] == "adversarial_trace"
    trajectory = RawInteractionTrajectory.model_validate_json(
        summary.trajectory_paths[0].read_text(encoding="utf-8")
    )
    assert trajectory.construction_manifest is not None
    assert trajectory.construction_manifest.acquisition_mode == "adversarial_trace"
