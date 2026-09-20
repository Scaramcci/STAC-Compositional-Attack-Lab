from __future__ import annotations

import json
import shutil
from pathlib import Path
from typing import Any, cast

import pytest

from stac_attack_lab.cli import main
from stac_attack_lab.execution.flow_reanalysis import (
    reanalyze_flow_v3,
    validate_flow_analysis,
)
from stac_attack_lab.execution.safeclaw_formal import SafeClawFormalConfig
from stac_attack_lab.extraction.flow_slice import slice_dependency_graph
from stac_attack_lab.flow.analysis import (
    AdmissionProfile,
    FlowAnalysisReport,
    GateStatus,
    JoinRequirement,
    SliceBudget,
    SliceJoinSemantics,
)
from stac_attack_lab.flow.models import EffectGraph
from stac_attack_lab.hashing import file_hash
from stac_attack_lab.interactions.collector import InteractionCollectionPlan, collect_interactions
from stac_attack_lab.interactions.fixture_adapter import JsonlFixtureInteractionAdapter
from stac_attack_lab.interactions.models import InteractionGraph
from stac_attack_lab.interactions.normalizer import normalize_trajectory
from stac_attack_lab.planning.binding_planner import build_benchmark_binding

ROOT = Path(__file__).resolve().parents[2]
PROFILE = ROOT / "configs/flow/observation_profile_v3.json"
REGISTRY = ROOT / "configs/flow/registry_v3.json"
FIXTURE = ROOT / "tests/fixtures/interactions/authorized_synthetic.jsonl"


def _legacy_graph(tmp_path: Path) -> Path:
    summary = collect_interactions(
        InteractionCollectionPlan(
            collection_id="v3-phase2-fixture",
            source_task_ids=["construction-synthetic-001"],
            seed=37,
        ),
        JsonlFixtureInteractionAdapter(FIXTURE),
        tmp_path / "raw",
    )
    graph_path, _ = normalize_trajectory(
        summary.trajectory_paths[0],
        collection_root=summary.collection_root,
        output_root=tmp_path / "normalized",
    )
    return graph_path


def test_disk_input_runs_project_verify_slice_profile_and_report(tmp_path: Path) -> None:
    input_path = _legacy_graph(tmp_path)
    before = file_hash(input_path)
    first = reanalyze_flow_v3(
        ROOT,
        input_path=input_path,
        output_root=tmp_path / "analyses",
        profile_path=PROFILE,
        registry_path=REGISTRY,
        terminal_outputs=True,
    )
    second = reanalyze_flow_v3(
        ROOT,
        input_path=input_path,
        output_root=tmp_path / "analyses",
        profile_path=PROFILE,
        registry_path=REGISTRY,
        terminal_outputs=True,
    )
    assert first != second
    left = validate_flow_analysis(first)
    right = validate_flow_analysis(second)
    assert left.analysis_key == right.analysis_key
    assert file_hash(input_path) == before
    report = FlowAnalysisReport.model_validate_json(
        (first / "report.json").read_text(encoding="utf-8")
    )
    public_report = (first / "report.json").read_text(encoding="utf-8")
    assert "source_locator" not in public_report
    assert "fixture:" not in public_report
    assert report.graph_count == report.slice_count == 1
    assert report.official_outcome == "not_evaluated"
    assert report.execution_authorization == "absent"
    statuses = {item.profile: item.status for item in report.profiles}
    assert statuses[AdmissionProfile.descriptive_trace] == GateStatus.passed
    assert statuses[AdmissionProfile.intervention_comparison] != GateStatus.passed
    assert "verified_negative" not in {
        item.classification.value for item in report.profiles if item.status == GateStatus.unknown
    }


def test_slice_keeps_fan_in_and_marks_budget_boundary(tmp_path: Path) -> None:
    input_path = _legacy_graph(tmp_path)
    analysis = reanalyze_flow_v3(
        ROOT,
        input_path=input_path,
        output_root=tmp_path / "analyses",
        profile_path=PROFILE,
        registry_path=REGISTRY,
        terminal_outputs=True,
    )
    graph_path = next((analysis / "graphs").glob("*.json"))
    graph = EffectGraph.model_validate_json(graph_path.read_text(encoding="utf-8"))
    sink = next(port for effect in graph.effects for port in effect.output_port_ids)
    dependency_slice = slice_dependency_graph(
        graph,
        sink_port_ids=[sink],
        budget=SliceBudget(max_nodes=1, max_edges=1, max_candidates=1),
    )
    assert dependency_slice.truncated
    assert dependency_slice.external_preconditions
    assert dependency_slice.replay_consistency == "not_evaluated"


def test_cli_profile_validation_and_unmet_profile_exit(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    input_path = _legacy_graph(tmp_path)
    (tmp_path / "configs/flow").mkdir(parents=True)
    shutil.copy2(PROFILE, tmp_path / "configs/flow/observation_profile_v3.json")
    shutil.copy2(REGISTRY, tmp_path / "configs/flow/registry_v3.json")
    monkeypatch.setattr("stac_attack_lab.cli.project_root", lambda: tmp_path)
    assert main(["flow", "profile-validate"]) == 0
    relative_input = input_path.relative_to(tmp_path)
    assert (
        main(
            [
                "flow",
                "reanalyze",
                "--input",
                str(relative_input),
                "--output-root",
                "analyses",
                "--terminal-outputs",
                "--require-profile",
                "intervention_comparison",
            ]
        )
        == 10
    )


def test_join_thresholds_are_explicit_and_planner_rejects_v3(tmp_path: Path) -> None:
    analysis = reanalyze_flow_v3(
        ROOT,
        input_path=_legacy_graph(tmp_path),
        output_root=tmp_path / "analyses",
        profile_path=PROFILE,
        registry_path=REGISTRY,
        terminal_outputs=True,
    )
    graph = EffectGraph.model_validate_json(
        next((analysis / "graphs").glob("*.json")).read_text(encoding="utf-8")
    )
    target = next(item.target_port_id for item in graph.claims)
    members = [item.claim_id for item in graph.claims if item.target_port_id == target]
    join = JoinRequirement(
        join_group_id="fixture-k-of-n",
        target_port_id=target,
        member_claim_ids=members,
        semantics=SliceJoinSemantics.k_of_n,
        k=1,
        origin="template_requirement",
    )
    sliced = slice_dependency_graph(graph, sink_port_ids=[target], join_requirements=[join])
    assert sliced.joins[0].semantics == SliceJoinSemantics.k_of_n
    assert all(item.required for item in sliced.claims if item.claim_id in members)
    with pytest.raises(ValueError, match="planner_v3_effect_graph_unsupported"):
        build_benchmark_binding(cast(Any, graph), cast(Any, object()))


def test_v3_and_legacy_inputs_are_not_silently_interchangeable(tmp_path: Path) -> None:
    input_path = _legacy_graph(tmp_path)
    legacy = InteractionGraph.model_validate_json(input_path.read_text(encoding="utf-8"))
    payload = legacy.model_dump(mode="json")
    payload["schema_version"] = "3.0"
    bad = tmp_path / "bad.json"
    bad.write_text(json.dumps(payload), encoding="utf-8")
    with pytest.raises(Exception, match="schema_version"):
        reanalyze_flow_v3(
            ROOT,
            input_path=bad,
            output_root=tmp_path / "out",
            profile_path=PROFILE,
            registry_path=REGISTRY,
            terminal_outputs=True,
        )


def test_formal_config_capability_gate_rejects_v3() -> None:
    payload = json.loads(
        (ROOT / "configs/experiments/formal_evaluation.yaml").read_text(encoding="utf-8")
    )
    payload["analysis_representation"] = "effect_graph_v3"
    with pytest.raises(Exception, match="legacy_chain_v2"):
        SafeClawFormalConfig.model_validate(payload)


def test_analysis_validation_detects_output_mutation(tmp_path: Path) -> None:
    analysis = reanalyze_flow_v3(
        ROOT,
        input_path=_legacy_graph(tmp_path),
        output_root=tmp_path / "analyses",
        profile_path=PROFILE,
        registry_path=REGISTRY,
        terminal_outputs=True,
    )
    report = analysis / "report.json"
    report.write_text(report.read_text(encoding="utf-8") + " ", encoding="utf-8")
    try:
        validate_flow_analysis(analysis)
    except ValueError as exc:
        assert str(exc) == "analysis_output_hash_mismatch"
    else:  # pragma: no cover
        raise AssertionError("mutated analysis output was accepted")
