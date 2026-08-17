from __future__ import annotations

import json
from pathlib import Path

import pytest

from stac_attack_lab.interactions.collector import (
    InteractionCollectionPlan,
    collect_interactions,
)
from stac_attack_lab.interactions.fixture_adapter import JsonlFixtureInteractionAdapter
from stac_attack_lab.interactions.models import (
    DependencyType,
    InteractionGraph,
    RawInteractionTrajectory,
)
from stac_attack_lab.interactions.normalizer import (
    NormalizationAudit,
    normalize_source_events,
    normalize_trajectory,
)

ROOT = Path(__file__).resolve().parents[2]
FIXTURE = ROOT / "tests/fixtures/interactions/authorized_synthetic.jsonl"


def _plan() -> InteractionCollectionPlan:
    return InteractionCollectionPlan(
        collection_id="phase2-test",
        source_task_ids=["construction-synthetic-001"],
        formal_excluded_task_ids=["heldout-safeclaw-task"],
        seed=17,
    )


def test_collection_is_split_safe_immutable_and_resumable(tmp_path: Path) -> None:
    adapter = JsonlFixtureInteractionAdapter(FIXTURE)
    first = collect_interactions(_plan(), adapter, tmp_path / "raw")
    second = collect_interactions(_plan(), adapter, tmp_path / "raw")

    assert len(first.trajectory_paths) == 1
    assert first.failure_count == 0
    assert len(second.skipped_trajectory_ids) == 1
    assert first.trajectory_paths == second.trajectory_paths
    trajectory = RawInteractionTrajectory.model_validate_json(
        first.trajectory_paths[0].read_text(encoding="utf-8")
    )
    assert trajectory.source_split == "synthetic"
    assert trajectory.provenance["authorization_scope"] == "project_synthetic_fixture"


def test_collection_rejects_formal_test_or_excluded_sources() -> None:
    with pytest.raises(ValueError, match="formal_test_split"):
        InteractionCollectionPlan(
            collection_id="invalid",
            source_task_ids=["construction-synthetic-001"],
            allowed_source_splits=["test"],
            seed=1,
        )
    with pytest.raises(ValueError, match="formal_excluded_task_requested"):
        InteractionCollectionPlan(
            collection_id="invalid",
            source_task_ids=["construction-synthetic-001"],
            formal_excluded_task_ids=["construction-synthetic-001"],
            seed=1,
        )


def test_normalization_builds_causal_graph_across_benign_gap(tmp_path: Path) -> None:
    adapter = JsonlFixtureInteractionAdapter(FIXTURE)
    summary = collect_interactions(_plan(), adapter, tmp_path / "raw")
    graph_path, audit_path = normalize_trajectory(
        summary.trajectory_paths[0],
        collection_root=summary.collection_root,
        output_root=tmp_path / "normalized",
    )

    graph = InteractionGraph.model_validate_json(graph_path.read_text(encoding="utf-8"))
    audit = NormalizationAudit.model_validate_json(audit_path.read_text(encoding="utf-8"))
    assert audit.passed is True
    assert len(graph.events) == 9
    assert len(graph.artifacts) == 5
    assert graph.unresolved_links == []
    assert any(
        edge.edge_type == DependencyType.state
        and edge.source_event_id == "e3"
        and edge.target_event_id == "e6"
        for edge in graph.edges
    )
    assert any(
        edge.edge_type == DependencyType.control
        and edge.source_event_id == "e5"
        and edge.target_event_id == "e6"
        for edge in graph.edges
    )
    assert not any(
        edge.source_event_id == "e4" and edge.target_event_id == "e6" for edge in graph.edges
    )


def test_orphan_request_is_explicitly_unresolved() -> None:
    trajectory = RawInteractionTrajectory(
        trajectory_id="orphan-trajectory",
        source_adapter_id="fixture",
        source_adapter_version="1",
        source_environment_family="synthetic",
        source_environment_version="1",
        source_task_id="orphan-task",
        source_split="synthetic",
        episode_id="episode-orphan",
        session_ids=["s1"],
        event_refs=[],
        checkpoint_refs=[],
        model_hashes={},
        config_hash="config-hash",
        collection_seed=1,
        collection_status="partial",
        provenance={},
    )
    events = [
        {
            "event_id": "result-1",
            "session_id": "s1",
            "sequence_no": 1,
            "actor_role": "tool",
            "event_type": "tool_result",
            "component_role": "effect_tool",
            "operation": "result",
            "status": "passed",
            "request_event_id": "missing-request",
        }
    ]
    graph, audit = normalize_source_events(trajectory, events, audit_ref="audit.json")

    assert audit.passed is False
    assert audit.reason_counts == {"missing_request_event": 1}
    assert graph.unresolved_links[0].source_event_id == "missing-request"


def test_collection_manifest_contains_no_fixture_payload(tmp_path: Path) -> None:
    adapter = JsonlFixtureInteractionAdapter(FIXTURE)
    summary = collect_interactions(_plan(), adapter, tmp_path / "raw")
    manifest = json.loads(
        (summary.collection_root / "collection_manifest.json").read_text(encoding="utf-8")
    )
    assert "SYNTHETIC_MARKER" not in json.dumps(manifest)
    assert manifest["formal_exclusion_hash"]
