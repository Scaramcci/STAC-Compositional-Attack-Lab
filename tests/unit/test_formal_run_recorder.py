from __future__ import annotations

from pathlib import Path

import pytest

from stac_attack_lab.recording.formal_run_recorder import (
    FormalRunManifest,
    FormalRunRecorder,
    FormalStage,
)
from stac_attack_lab.reporting.formal_report import build_formal_report
from stac_attack_lab.verification.formal_models import (
    FormalRunResult,
    OfficialSafeClawVerdict,
)


def _manifest() -> FormalRunManifest:
    return FormalRunManifest(
        run_id="formal-recorder-run",
        experiment_id="formal-recorder-test",
        track="safeclaw_compositional",
        config_hash="config-hash",
        library_version="formal-v1",
        library_hash="library-hash",
        registry_hash="registry-hash",
        upstream_commit="a11f5cceaba0676be721021f8d232638fd111305",
        safety_patch_hash="patch-hash",
        target_model_id="synthetic-model",
        environment_variable_names=["OPENAI_API_KEY"],
        case_ids=["case-1"],
        created_at="2026-08-17T00:00:00+00:00",
    )


def _result() -> FormalRunResult:
    return FormalRunResult(
        result_id="result-1",
        run_id="formal-recorder-run",
        case_id="case-1",
        pair_id="pair-1",
        condition="sample_rule_based",
        seed=1,
        planner_type="sample_rule_based",
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
        all_required_occurrences_passed=False,
        all_required_edges_passed=False,
        all_required_macros_passed=False,
        official_verdict=OfficialSafeClawVerdict(
            evaluator_version="safeclaw@test",
            execution_complete=True,
            attack_succeeded=False,
            security_score=0.0,
            utility_success=True,
            safe_check_results={},
            success_check_results={},
            taint_channels=[],
            evidence_ref_ids=[],
            instrumentation_gaps=[],
        ),
        forbidden_shortcut=False,
        full_chain_success=False,
        terminal_only_or_shortcut=False,
        mechanism_completed_terminal_failed=False,
        execution_error=False,
        execution_error_category=None,
        not_observable_count=0,
        tool_calls=0,
        tokens=0,
        api_calls=0,
        duration_ms=100,
        cost=0.0,
        artifact_paths={},
        provenance_hashes={},
    )


def test_formal_recorder_is_idempotent_and_reportable(tmp_path: Path) -> None:
    recorder = FormalRunRecorder(tmp_path / "run", ["sk-exact-secret-123456789"])
    recorder.initialize(
        _manifest(),
        [("case-1", "pair-1", "task-1", "sample_rule_based", 1)],
    )
    first = recorder.record_artifact("case-1", FormalStage.planned, "plan", {"plan_id": "plan-1"})
    resumed = FormalRunRecorder(tmp_path / "run", ["sk-exact-secret-123456789"])
    second = resumed.record_artifact("case-1", FormalStage.planned, "plan", {"plan_id": "plan-1"})
    resumed.finalize_result(_result())
    resumed.finalize_result(_result())
    audit = resumed.audit()
    report = build_formal_report(tmp_path / "run")

    assert first == second
    assert audit.passed is True
    assert audit.result_count == 1
    assert report["result_count"] == 1
    assert (tmp_path / "run/formal_report.md").is_file()
    assert (tmp_path / "run/formal_results.csv").is_file()


def test_formal_recorder_rejects_secrets_before_write(tmp_path: Path) -> None:
    secret = "sk-exact-secret-123456789"
    recorder = FormalRunRecorder(tmp_path / "run", [secret])
    recorder.initialize(
        _manifest(),
        [("case-1", "pair-1", "task-1", "sample_rule_based", 1)],
    )

    with pytest.raises(ValueError, match="formal_artifact_secret_gate_failed"):
        recorder.record_artifact(
            "case-1",
            FormalStage.executed,
            "unsafe",
            {"message": f"provider returned {secret}"},
        )

    assert not (tmp_path / "run/cases/case-1/unsafe.json").exists()


def test_formal_recorder_audit_detects_artifact_tampering(tmp_path: Path) -> None:
    recorder = FormalRunRecorder(tmp_path / "run")
    recorder.initialize(
        _manifest(),
        [("case-1", "pair-1", "task-1", "sample_rule_based", 1)],
    )
    record = recorder.record_artifact("case-1", FormalStage.planned, "plan", {"plan_id": "plan-1"})
    (tmp_path / "run" / record.relative_path).write_text("{}\n", encoding="utf-8")

    audit = recorder.audit()

    assert audit.passed is False
    assert any("artifact_hash_mismatch" in item for item in audit.finding_codes)
