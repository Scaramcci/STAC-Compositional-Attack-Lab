import json
from pathlib import Path

import pytest

from stac_attack_lab.attack_program.r4_real_diagnosis import diagnose_batch

ROOT = Path(__file__).resolve().parents[2]
BATCH = ROOT / "experiments/runs/attack-program/r4-generation-real-20260930-v1"
REVIEW = BATCH / "victim-review-20260930-v1"
AUDIT = BATCH / "victim-review-20260930-v1"


@pytest.mark.skipif(not BATCH.is_dir(), reason="sealed generated batch unavailable")
def test_diagnosis_distinguishes_unknown_source_from_complete_usage(tmp_path):
    diagnose_batch(BATCH, REVIEW, AUDIT, tmp_path / "diagnosis")
    summary = json.loads((tmp_path / "diagnosis/summary.json").read_text())
    assert summary["counts"] == {"cases": 3, "victim_http_attempts": 36}
    for case in summary["cases"]:
        assert case["source_evidence"]["source_delivery"] == "unknown"
        assert case["source_evidence"]["provider_context_reachable"] == "unknown"
        assert case["provider_usage"]["status"] == "complete"
        assert case["provider_usage"]["missing_usage_records"] == 0
        assert all(s["finish_reason"] == "stop" for s in case["execution_completeness"]["all_finish_reasons"])

