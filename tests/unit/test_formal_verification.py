from __future__ import annotations

from pathlib import Path

from stac_attack_lab.datasets.library import PrimitiveChainLibrary
from stac_attack_lab.environments.safeclaw.contracts import (
    SafeClawEpisodeResult,
    SafeClawExecutionStatus,
)
from stac_attack_lab.environments.safeclaw.task_adapter import parse_safeclaw_task
from stac_attack_lab.execution.sample_generation import (
    build_sample_library,
    load_sample_generation_config,
)
from stac_attack_lab.extraction.occurrences import extract_primitive_occurrences
from stac_attack_lab.interactions.collector import (
    InteractionCollectionPlan,
    collect_interactions,
)
from stac_attack_lab.interactions.fixture_adapter import JsonlFixtureInteractionAdapter
from stac_attack_lab.interactions.models import InteractionGraph
from stac_attack_lab.interactions.normalizer import normalize_trajectory
from stac_attack_lab.planning.formal_base import FormalBudget, FormalPlannerInput
from stac_attack_lab.planning.formal_baselines import RuleBasedFormalPlanner
from stac_attack_lab.primitives.core import EvidenceGrade, PrimitiveOutcome
from stac_attack_lab.primitives.formal_registry import load_formal_registry
from stac_attack_lab.verification.formal_aggregate import (
    CausalVerdict,
    aggregate_formal_result,
    evaluate_formal_mechanism,
)
from stac_attack_lab.verification.occurrence import verify_occurrence
from stac_attack_lab.verification.safeclaw_official import parse_safeclaw_official

ROOT = Path(__file__).resolve().parents[2]
INTERACTIONS = ROOT / "tests/fixtures/interactions/authorized_synthetic.jsonl"
TASK = ROOT / "tests/fixtures/safeclaw/compositional_task.json"


def _graph(tmp_path: Path) -> InteractionGraph:
    adapter = JsonlFixtureInteractionAdapter(INTERACTIONS)
    summary = collect_interactions(
        InteractionCollectionPlan(
            collection_id="formal-verification-test",
            source_task_ids=["construction-synthetic-001"],
            seed=41,
        ),
        adapter,
        tmp_path / "raw",
    )
    graph_path, _ = normalize_trajectory(
        summary.trajectory_paths[0],
        collection_root=summary.collection_root,
        output_root=tmp_path / "normalized",
    )
    return InteractionGraph.model_validate_json(graph_path.read_text(encoding="utf-8"))


def _plan_and_views(tmp_path: Path):  # type: ignore[no-untyped-def]
    base = load_sample_generation_config(ROOT / "configs/sample_generation/formal_v1.yaml")
    config = base.model_copy(
        update={
            "library_version": "formal-verifier-test-v1",
            "output_root": str(tmp_path / "library"),
        }
    )
    library = PrimitiveChainLibrary(build_sample_library(ROOT, config))
    descriptor = parse_safeclaw_task(TASK, upstream_root=ROOT)
    public = library.public_index()[0]
    planner_input = FormalPlannerInput(
        planner_input_id="formal-verifier-input",
        library_id=library.manifest.library_id,
        library_version=library.manifest.library_version,
        library_hash=library.manifest.tree_hash,
        public_samples=[public],
        public_task=descriptor.public_view,
        budget=FormalBudget(
            max_sessions=3,
            max_turns=24,
            max_tool_calls=16,
            max_tokens=8192,
            max_wall_time_seconds=600,
        ),
        condition="sample_rule_based",
        seed=41,
    )
    plan = RuleBasedFormalPlanner().plan(planner_input)
    assert plan.selected_sample_id is not None
    return (
        plan,
        public.planner_view,
        library.execution_view(plan.selected_sample_id),
    )


def _episode(status: SafeClawExecutionStatus = SafeClawExecutionStatus.completed):
    return SafeClawEpisodeResult(
        episode_id="episode-formal-001",
        case_id="case-formal-001",
        task_id="formal-pse-template-001",
        binding_id="binding-formal-001",
        status=status,
        error_category="retryable_api_error"
        if status == SafeClawExecutionStatus.api_error
        else None,
        upstream_commit="a11f5cceaba0676be721021f8d232638fd111305",
        runner_version="test-runner",
        target_model_id="synthetic-model",
        started_at="2026-01-01T00:00:00+00:00",
        ended_at="2026-01-01T00:00:01+00:00",
        duration_ms=1000,
        attempt_count=1,
        sessions=[],
        sanitized_result_ref="sanitized_result.json",
        sanitized_result_hash="synthetic-result-hash",
        canonical_trajectory_ref="interaction_graph.json",
        official_checks_ref="sanitized_result.json#/checks",
        state_evidence_refs=[],
        taint_evidence_refs=[],
        secret_scan_passed=True,
        provenance={"materialized_task_hash": "synthetic-task-hash"},
    )


def _official_payload(attack_succeeded: bool = True) -> dict[str, object]:
    return {
        "task_id": "formal-pse-template-001",
        "attack_succeeded": attack_succeeded,
        "score": 1.0 if attack_succeeded else 0.0,
        "utility_success": True,
        "checks": {"success": attack_succeeded, "safe": not attack_succeeded},
        "taint_leakage": [{"channel": "synthetic_sim_google"}],
    }


def test_formal_mechanism_verifies_all_required_layers(tmp_path: Path) -> None:
    graph = _graph(tmp_path)
    registry = load_formal_registry(ROOT / "configs/primitives/formal_v1.yaml")
    occurrences = extract_primitive_occurrences(graph, registry).occurrences
    _, planner_view, execution_view = _plan_and_views(tmp_path)
    mechanism = evaluate_formal_mechanism(
        planner_view=planner_view,
        execution_view=execution_view,
        occurrences=occurrences,
        graph=graph,
        registry=registry,
        official_terminal_success=True,
    )

    assert len(mechanism.occurrence_verdicts) == 8
    assert len(mechanism.edge_verdicts) == 7
    assert len(mechanism.macro_verdicts) == 4
    assert all(item.outcome == PrimitiveOutcome.passed for item in mechanism.occurrence_verdicts)
    assert all(item.verdict == CausalVerdict.causal_pass for item in mechanism.edge_verdicts)
    assert all(item.outcome == PrimitiveOutcome.passed for item in mechanism.macro_verdicts)
    assert mechanism.forbidden_shortcut is False


def test_occurrence_missing_state_diff_is_not_observable(tmp_path: Path) -> None:
    graph = _graph(tmp_path)
    registry = load_formal_registry(ROOT / "configs/primitives/formal_v1.yaml")
    occurrence = next(
        item
        for item in extract_primitive_occurrences(graph, registry).occurrences
        if item.primitive_ref == "core.mutate.memory_write@1"
    )
    graph_without_post = graph.model_copy(
        update={
            "events": [
                event.model_copy(update={"post_state_ref": None})
                if event.event_id in occurrence.source_event_ids
                else event
                for event in graph.events
            ]
        }
    )
    verdict = verify_occurrence(occurrence, graph_without_post)

    assert verdict.outcome == PrimitiveOutcome.not_observable
    assert verdict.hard_fact is False
    assert "mutate_transition_not_observable" in verdict.reason_codes


def test_semantic_evidence_cannot_upgrade_hard_occurrence(tmp_path: Path) -> None:
    graph = _graph(tmp_path)
    registry = load_formal_registry(ROOT / "configs/primitives/formal_v1.yaml")
    occurrence = (
        extract_primitive_occurrences(graph, registry)
        .occurrences[0]
        .model_copy(
            update={
                "hard_fact": False,
                "evidence_grades": [EvidenceGrade.semantic],
                "semantic_labels": {"proposal": "pass"},
            }
        )
    )
    verdict = verify_occurrence(occurrence, graph)

    assert verdict.outcome == PrimitiveOutcome.not_observable
    assert "semantic_annotation_cannot_override_hard_verdict" in verdict.reason_codes


def test_typed_state_edge_is_not_replaced_by_temporal_order(tmp_path: Path) -> None:
    graph = _graph(tmp_path)
    graph = graph.model_copy(
        update={
            "edges": [
                edge
                for edge in graph.edges
                if not (edge.source_event_id == "e3" and edge.target_event_id == "e6")
            ]
        }
    )
    registry = load_formal_registry(ROOT / "configs/primitives/formal_v1.yaml")
    occurrences = extract_primitive_occurrences(graph, registry).occurrences
    _, planner_view, execution_view = _plan_and_views(tmp_path)
    mechanism = evaluate_formal_mechanism(
        planner_view=planner_view,
        execution_view=execution_view,
        occurrences=occurrences,
        graph=graph,
        registry=registry,
        official_terminal_success=True,
    )
    verdict = next(
        item
        for item in mechanism.edge_verdicts
        if "memory_write@1->core.transfer.retrieve@1" in item.edge_id
    )

    assert verdict.verdict == CausalVerdict.fail
    assert verdict.reason_codes == ["missing_observable_typed_dependency"]


def test_official_adapter_and_aggregate_truth_table(tmp_path: Path) -> None:
    graph = _graph(tmp_path)
    registry = load_formal_registry(ROOT / "configs/primitives/formal_v1.yaml")
    occurrences = extract_primitive_occurrences(graph, registry).occurrences
    plan, planner_view, execution_view = _plan_and_views(tmp_path)
    episode = _episode()
    official = parse_safeclaw_official(episode, _official_payload())
    mechanism = evaluate_formal_mechanism(
        planner_view=planner_view,
        execution_view=execution_view,
        occurrences=occurrences,
        graph=graph,
        registry=registry,
        official_terminal_success=True,
    )
    passed = aggregate_formal_result(
        run_id="formal-run",
        case_id=episode.case_id,
        pair_id="pair-001",
        seed=41,
        library_version="formal-verifier-test-v1",
        plan=plan,
        episode=episode,
        official_verdict=official,
        mechanism=mechanism,
    )
    official_failed = parse_safeclaw_official(episode, _official_payload(False))
    mechanism_only = aggregate_formal_result(
        run_id="formal-run",
        case_id="case-formal-failed",
        pair_id="pair-002",
        seed=41,
        library_version="formal-verifier-test-v1",
        plan=plan,
        episode=episode,
        official_verdict=official_failed,
        mechanism=mechanism,
    )
    error_episode = _episode(SafeClawExecutionStatus.api_error)
    error_result = aggregate_formal_result(
        run_id="formal-run",
        case_id="case-formal-error",
        pair_id="pair-003",
        seed=41,
        library_version="formal-verifier-test-v1",
        plan=plan,
        episode=error_episode,
        official_verdict=parse_safeclaw_official(error_episode, None),
        mechanism=mechanism,
    )

    assert passed.full_chain_success is True
    assert passed.terminal_only_or_shortcut is False
    assert mechanism_only.mechanism_completed_terminal_failed is True
    assert mechanism_only.full_chain_success is False
    assert error_result.execution_error is True
    assert error_result.execution_error_category == "retryable_api_error"
    assert error_result.mechanism_completed_terminal_failed is False
