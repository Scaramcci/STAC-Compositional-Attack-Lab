from __future__ import annotations

from pathlib import Path

from stac_attack_lab.extraction.occurrences import extract_primitive_occurrences
from stac_attack_lab.interactions.collector import (
    InteractionCollectionPlan,
    collect_interactions,
)
from stac_attack_lab.interactions.fixture_adapter import JsonlFixtureInteractionAdapter
from stac_attack_lab.interactions.models import InteractionGraph
from stac_attack_lab.interactions.normalizer import normalize_trajectory
from stac_attack_lab.primitives.core import CorePrimitiveFamily, PrimitiveOutcome
from stac_attack_lab.primitives.formal_registry import load_formal_registry

ROOT = Path(__file__).resolve().parents[2]
FIXTURE = ROOT / "tests/fixtures/interactions/authorized_synthetic.jsonl"


def _graph(tmp_path: Path) -> InteractionGraph:
    adapter = JsonlFixtureInteractionAdapter(FIXTURE)
    plan = InteractionCollectionPlan(
        collection_id="extraction-test",
        source_task_ids=["construction-synthetic-001"],
        seed=19,
    )
    summary = collect_interactions(plan, adapter, tmp_path / "raw")
    graph_path, _ = normalize_trajectory(
        summary.trajectory_paths[0],
        collection_root=summary.collection_root,
        output_root=tmp_path / "normalized",
    )
    return InteractionGraph.model_validate_json(graph_path.read_text(encoding="utf-8"))


def test_deterministic_extractor_recognizes_all_formal_families(tmp_path: Path) -> None:
    graph = _graph(tmp_path)
    registry = load_formal_registry(ROOT / "configs/primitives/formal_v1.yaml")
    result = extract_primitive_occurrences(graph, registry)

    assert len(result.occurrences) == 8
    assert {item.family for item in result.occurrences} == set(CorePrimitiveFamily)
    assert all(item.outcome == PrimitiveOutcome.passed for item in result.occurrences)
    assert all(item.hard_fact for item in result.occurrences)
    assert any(
        decision.event_id == "e4" and decision.reason_codes == ["no_deterministic_primitive_match"]
        for decision in result.decisions
    )


def test_semantic_proposal_does_not_override_missing_hard_evidence(tmp_path: Path) -> None:
    graph = _graph(tmp_path)
    graph = graph.model_copy(
        update={
            "events": [
                event.model_copy(update={"output_artifact_ids": []})
                if event.event_id == "e2"
                else event
                for event in graph.events
            ]
        }
    )
    registry = load_formal_registry(ROOT / "configs/primitives/formal_v1.yaml")
    result = extract_primitive_occurrences(
        graph,
        registry,
        semantic_proposals={"e2": {"proposal": "pass", "subtype": "extract"}},
    )
    extract = next(item for item in result.occurrences if item.subtype == "extract")

    assert extract.outcome == PrimitiveOutcome.not_observable
    assert extract.hard_fact is False
    assert extract.semantic_labels["proposal"] == "pass"
    assert "transform_lineage_incomplete" in extract.reason_codes
