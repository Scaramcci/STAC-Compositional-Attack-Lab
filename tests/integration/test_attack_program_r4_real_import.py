"""A real development attempt must come from one intact, independently replayed run."""

import json
from pathlib import Path

import pytest

from stac_attack_lab.attack_program.pipeline import GateError
from stac_attack_lab.attack_program.r4_real_import import (
    _validated_source,
    audit_real_attempt,
    import_real_attempt,
)

ROOT = Path(__file__).resolve().parents[2]
BATCH = ROOT / "experiments/runs/attack-program/r4-real-dev-disabled-live-readiness-20260928-v1"
REVIEW = BATCH.parent / f"{BATCH.name}-review-20260929-v1"
AUDIT = BATCH.parent / f"{BATCH.name}-independent-replay-20260929-v1/audit.json"


@pytest.mark.skipif(not BATCH.is_dir(), reason="sealed historical fixture unavailable")
def test_import_one_real_attempt_and_idempotent_denominator(tmp_path):
    first = import_real_attempt(ROOT, BATCH, REVIEW, AUDIT, tmp_path)
    second = import_real_attempt(ROOT, BATCH, REVIEW, AUDIT, tmp_path)
    assert first["attempt_path"] == second["attempt_path"]
    assert second["status"] == "imported_existing"
    assert len(list(tmp_path.rglob("attempt.json"))) == 1
    attempt = json.loads(Path(first["attempt_path"]).read_text())
    assert attempt["denominator"]["real_attempts"] == 1
    assert attempt["official"]["attack_succeeded"] is True
    assert attempt["independent_claims"][0]["scope"] == "pse_s2_agent_response_only"
    assert attempt["classification"] == "scope_limited_real_development_observation"
    development = json.loads(Path(first["development_report_path"]).read_text())
    assert development["scope"] == "real_development_import"
    assert development["attempt_denominator"] == 1
    assert (Path(first["attempt_path"]).parent / "manifest.json").is_file()
    assert audit_real_attempt(ROOT, BATCH, REVIEW, AUDIT, tmp_path)["status"] == "valid"
    diagnosis = json.loads(Path(first["report_path"]).read_text())
    assert diagnosis["official_benchmark_outcome"]["memory_contains"]["post_matches"] == {
        "memory_content": False,
        "memory_root_content": False,
        "memory_dir_content": True,
    }
    assert diagnosis["evidence_integrity"]["historical_source_delivered_count"] == 0
    assert diagnosis["evidence_integrity"]["reprojected_source_delivered_count"] == 1
    assert diagnosis["evidence_integrity"]["memory_dated_file_write"].startswith("tool_write")
    assert diagnosis["evidence_integrity"]["memory_md_precondition_s2"] is False
    assert diagnosis["evidence_integrity"]["usage"]["tokens"] == "unknown"
    assert all(
        not x["s2_agent_response_contains"]
        for x in diagnosis["other_channels"]["asset_observations"]
        if x["official_log_file_hit"]
    )
    public = Path(first["report_path"]).read_text()
    assert "CANARY_" not in public
    assert "verified_negative" in public
    assert "session_transcript" in public
    Path(first["report_path"]).write_text("{}")
    with pytest.raises(GateError):
        audit_real_attempt(ROOT, BATCH, REVIEW, AUDIT, tmp_path)


@pytest.mark.skipif(not BATCH.is_dir(), reason="sealed historical fixture unavailable")
def test_forged_source_and_wrong_candidate_binding_rejected(tmp_path):
    with pytest.raises(GateError):
        import_real_attempt(ROOT, tmp_path / "self_declared_real", REVIEW, AUDIT, tmp_path)
    copied = tmp_path / "forged"
    import shutil

    shutil.copytree(BATCH, copied)
    candidate_path = copied / "candidate.json"
    candidate = json.loads(candidate_path.read_text())
    candidate["candidate_id"] = "wrong"
    candidate_path.write_text(json.dumps(candidate))
    with pytest.raises(GateError, match="real_import_candidate_or_task_mismatch"):
        _validated_source(copied, REVIEW, AUDIT)
    candidate_path.write_bytes((BATCH / "candidate.json").read_bytes())
    activation_path = copied / "execution/activation.json"
    activation = json.loads(activation_path.read_text())
    activation["binding_hash"] = "0" * 64
    activation_path.write_text(json.dumps(activation))
    with pytest.raises(GateError, match="real_import_provenance_mismatch"):
        _validated_source(copied, REVIEW, AUDIT)
