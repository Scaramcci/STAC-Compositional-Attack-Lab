import json
from pathlib import Path

import pytest

from stac_attack_lab.capability import stage_summary
from stac_attack_lab.capability.f5_repeats import (
    prepare_f5_repeats,
    report_f5_repeats,
    validate_f5_repeats,
)
from stac_attack_lab.capability.m3_f5 import F5Config, assess_f5_acceptance
from stac_attack_lab.hashing import stable_hash

PROJECT = Path(__file__).resolve().parents[2]


def test_historical_stage_sources_and_direct_behavior() -> None:
    summary = stage_summary.build_stage_summary(PROJECT)
    assert summary["denominators"]["selected_development_observations"] == {
        "F1": 8,
        "F3": 3,
        "F5_historical_baseline": 1,
        "F5_current_batch": 2,
    }
    assert summary["denominators"]["F5_current_victim_http"] == 12
    assert summary["denominators"]["F5_historical_victim_http"] == 6
    assert summary["cases"]["F5"][1]["harm"] == "unknown"
    assert summary["cases"]["F5"][1]["recover"] == "not_observed"
    direct = PROJECT / stage_summary.RUNS / stage_summary.F5_BATCH / "results/direct"
    events = [
        json.loads(line) for line in (direct / "runtime_events.jsonl").read_text().splitlines()
    ]
    writes = [
        event
        for event in events
        if event["event_type"] == "tool_call"
        and event["public_payload"].get("tool_name") == "write"
    ]
    assert [event["public_payload"]["workspace_relative_path"] for event in writes] == [
        "reports/primary-status.json",
        "authorized backup reports/status.json",
    ]
    final = json.loads((direct / "checkpoints/final.json").read_text())
    files = {item["path"]: item for item in final["capability_workspace_snapshot_v1"]["files"]}
    assert json.loads(files["reports/status.json"]["content"])["decision"] == "not_started"
    assert (
        assess_f5_acceptance(
            {"utility": False, "new_harm": "unknown"},
            execution_status="completed",
            cleanup_status="completed",
            tool_trace_complete=True,
        )["harm"]
        == "unknown"
    )


def test_stage_rejects_missing_source_and_wrong_identity(monkeypatch: pytest.MonkeyPatch) -> None:
    original = stage_summary._read

    def missing(path: Path):
        if path.name == "mixed_review_summary.json":
            raise ValueError("stage_source_missing")
        return original(path)

    monkeypatch.setattr(stage_summary, "_read", missing)
    with pytest.raises(ValueError, match="stage_source_missing"):
        stage_summary.build_stage_summary(PROJECT)
    monkeypatch.setattr(stage_summary, "_read", original)

    def wrong(path: Path):
        value = original(path)
        if path.name == "review_mapping.json":
            value["mapping"][0]["unit_id"] = "semantic"
        return value

    monkeypatch.setattr(stage_summary, "_read", wrong)
    with pytest.raises(ValueError, match="stage_f3_label_identity_mismatch"):
        stage_summary.build_stage_summary(PROJECT)


def test_repeat_plan_is_disabled_unique_and_keeps_all_denominators(tmp_path: Path) -> None:
    root = tmp_path / "plan"
    prepare_f5_repeats(PROJECT, PROJECT / "configs/capability/m3b_f5_repeat.disabled.json", root)
    plan = validate_f5_repeats(PROJECT, root)
    assert plan["denominator"] == 9
    assert plan["authorization_status"] == "absent"
    assert plan["model_generation_seed"] == "uncontrolled"
    assert len({unit for group in plan["groups"] for unit in group["units"]}) == 9
    for group in plan["groups"]:
        run = root / group["group_id"]
        assert not (run / "execution_binding.json").exists()
        assert not list(run.glob("launch-*.reserved"))
    report_path = tmp_path / "report.json"
    report_f5_repeats(PROJECT, root, report_path)
    report = json.loads(report_path.read_text())
    assert (report["denominator"], report["not_started"], report["victim_http_attempts"]) == (
        9,
        9,
        0,
    )
    assert report["historical_baseline_counted"] == 0


def test_repeat_rejects_identity_and_pair_tampering(tmp_path: Path) -> None:
    root = tmp_path / "plan"
    prepare_f5_repeats(PROJECT, PROJECT / "configs/capability/m3b_f5_repeat.disabled.json", root)
    plan_file = root / "plan.json"
    plan = json.loads(plan_file.read_text())
    plan["groups"][1]["units"][0] = "r01-benign"
    plan["plan_hash"] = stable_hash({k: v for k, v in plan.items() if k != "plan_hash"})
    plan_file.write_text(json.dumps(plan))
    with pytest.raises(ValueError, match="f5_repeat_group_units_invalid"):
        validate_f5_repeats(PROJECT, root)


def test_repeat_profile_is_explicit() -> None:
    config = json.loads((PROJECT / "configs/capability/m3b_f5_repeat.disabled.json").read_text())
    config["observation_profile"] = None
    with pytest.raises(ValueError, match="m3_f5_observation_profile_required"):
        F5Config.model_validate(config)
