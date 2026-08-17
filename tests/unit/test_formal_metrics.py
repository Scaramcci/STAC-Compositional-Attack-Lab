from __future__ import annotations

from stac_attack_lab.reporting.formal_metrics import (
    paired_condition_delta,
    summarize_formal_results,
)
from stac_attack_lab.verification.formal_models import (
    FormalRunResult,
    OfficialSafeClawVerdict,
)


def _result(
    *,
    case_id: str,
    pair_id: str,
    condition: str,
    full_chain: bool,
    terminal: bool | None,
    shortcut: bool = False,
    execution_error: bool = False,
    not_observable_count: int = 0,
) -> FormalRunResult:
    return FormalRunResult(
        result_id=f"result-{case_id}",
        run_id="formal-metrics-run",
        case_id=case_id,
        pair_id=pair_id,
        condition=condition,
        seed=7,
        planner_type="test",
        library_version="formal-v1",
        sample_id="sample-1",
        plan_id="plan-1",
        binding_id="binding-1",
        task_id="task-1",
        binding_valid=True,
        binding_reason_codes=["binding_valid"],
        occurrence_verdicts=[],
        edge_verdicts=[],
        macro_verdicts=[],
        all_required_occurrences_passed=full_chain,
        all_required_edges_passed=full_chain,
        all_required_macros_passed=full_chain,
        official_verdict=OfficialSafeClawVerdict(
            evaluator_version="safeclaw@test",
            execution_complete=terminal is not None and not execution_error,
            attack_succeeded=terminal,
            security_score=1.0 if terminal else 0.0,
            utility_success=True if not execution_error else None,
            safe_check_results={},
            success_check_results={},
            taint_channels=[],
            evidence_ref_ids=[],
            instrumentation_gaps=[],
        ),
        forbidden_shortcut=shortcut,
        full_chain_success=full_chain,
        terminal_only_or_shortcut=bool(terminal and not full_chain),
        mechanism_completed_terminal_failed=bool(full_chain and terminal is False),
        execution_error=execution_error,
        execution_error_category="api_error" if execution_error else None,
        not_observable_count=not_observable_count,
        tool_calls=0,
        tokens=0,
        api_calls=0,
        duration_ms=100,
        cost=0.0,
        artifact_paths={},
        provenance_hashes={},
    )


def test_formal_metrics_use_conditional_denominators_and_exclude_errors() -> None:
    results = [
        _result(
            case_id="treatment",
            pair_id="pair-1",
            condition="sample",
            full_chain=True,
            terminal=True,
        ),
        _result(
            case_id="control",
            pair_id="pair-1",
            condition="control",
            full_chain=False,
            terminal=True,
            shortcut=True,
        ),
        _result(
            case_id="error",
            pair_id="pair-2",
            condition="sample",
            full_chain=False,
            terminal=None,
            execution_error=True,
        ),
        _result(
            case_id="gap",
            pair_id="pair-3",
            condition="sample",
            full_chain=False,
            terminal=False,
            not_observable_count=1,
        ),
    ]
    report = summarize_formal_results(results)

    assert report.overall.execution_error_rate.numerator == 1
    assert report.overall.execution_error_rate.denominator == 4
    assert report.overall.instrumentation_coverage.numerator == 2
    assert report.overall.instrumentation_coverage.denominator == 3
    assert report.overall.full_chain_success.numerator == 1
    assert report.overall.full_chain_success.denominator == 2
    assert report.overall.official_terminal_success.numerator == 2
    assert report.overall.official_terminal_success.denominator == 3
    assert report.overall.shortcut_rate_given_terminal_success.numerator == 1
    assert report.overall.shortcut_rate_given_terminal_success.denominator == 2


def test_paired_delta_uses_only_complete_observable_pairs() -> None:
    results = [
        _result(
            case_id="treatment",
            pair_id="pair-1",
            condition="sample",
            full_chain=True,
            terminal=True,
        ),
        _result(
            case_id="control",
            pair_id="pair-1",
            condition="control",
            full_chain=False,
            terminal=True,
        ),
        _result(
            case_id="unpaired",
            pair_id="pair-2",
            condition="sample",
            full_chain=True,
            terminal=True,
        ),
    ]
    delta = paired_condition_delta(
        results,
        treatment_condition="sample",
        control_condition="control",
        outcome="full_chain_success",
    )

    assert delta.pair_count == 1
    assert delta.treatment_only == 1
    assert delta.control_only == 0
    assert delta.risk_difference == 1.0
