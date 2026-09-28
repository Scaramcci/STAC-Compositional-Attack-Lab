"""R3 paired planner, transport and replay checks using only synthetic inputs."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from stac_attack_lab.attack_program.demo_r2 import demo as r2_demo
from stac_attack_lab.attack_program.models import Patch, R3Config, R3Plan
from stac_attack_lab.attack_program.pipeline import GateError
from stac_attack_lab.attack_program.r3 import (
    PlannerReply,
    ScriptedTransport,
    _validate_plan,
    build_manifest,
    replay,
    run,
)

ROOT = Path(__file__).resolve().parents[2]


@pytest.fixture(scope="module")
def library(tmp_path_factory):
    root = tmp_path_factory.mktemp("r3-library")
    r2_demo(ROOT, root / "r2")
    return root / "r2/library"


def _config() -> R3Config:
    return R3Config(
        task_id="pse-2.1-001",
        repeats=1,
        top_k=2,
        planner_model_id="scripted",
        planner_request_budget=3,
        victim_request_budget=0,
    )


def test_pair_retrieval_selection_materialization_and_replay(library, tmp_path):
    manifest, requests = build_manifest(ROOT, library, _config())
    no, raw, structured = [requests[c.case_id] for c in manifest.cases]
    assert no.compatible_samples == []
    assert len(raw.compatible_samples) == len(structured.compatible_samples) == 2
    assert [s.sample_id for s in raw.compatible_samples] == [
        s.sample_id for s in structured.compatible_samples
    ]
    assert "occurrences" not in raw.model_dump_json()
    assert "CANARY_" not in raw.model_dump_json() + structured.model_dump_json()

    report = run(ROOT, library, _config(), tmp_path / "matrix", ScriptedTransport())
    assert report["assigned"] == 3
    assert report["status_counts"]["completed"] == 3
    assert report["planner_http_attempts"] == report["victim_http_attempts"] == 0
    assert report["cases"][1]["selected_sample_ids"] == [raw.compatible_samples[1].sample_id]
    assert report["cases"][2]["selected_sample_ids"] == [raw.compatible_samples[1].sample_id]
    assert report["cases"][0]["materialized_hash"] != report["cases"][1]["materialized_hash"]
    assert replay(ROOT, library, tmp_path / "matrix", tmp_path / "audit", compare=True) == report
    assert json.loads((tmp_path / "audit/audit.json").read_text())["paired_cases"] == 3


def test_plan_validation_abstain_combine_and_outside_samples(library):
    _, requests = build_manifest(ROOT, library, _config())
    raw = requests["repeat-001-raw_examples"]
    sample_a, sample_b = raw.compatible_samples
    pointer = raw.allowed_surfaces[0]["pointer"]
    plan = R3Plan(
        selected_sample_ids=[sample_a.sample_id, sample_b.sample_id],
        patches=[Patch(pointer=pointer, value=sample_a.raw_example + "\n" + sample_b.raw_example)],
        abstain=False,
        decision_summary="combine",
    )
    assert _validate_plan(raw, plan.model_dump_json()).selected_sample_ids == [
        sample_a.sample_id,
        sample_b.sample_id,
    ]
    for bad in (
        "not json",
        plan.model_dump_json().replace(sample_b.sample_id, "foreign-id"),
        plan.model_dump_json().replace(sample_b.sample_id, sample_a.sample_id),
        plan.model_dump_json().replace(pointer, "/sessions/0/user_instruction"),
        plan.model_dump_json().replace('"abstain":false', '"abstain":true'),
    ):
        with pytest.raises(GateError):
            _validate_plan(raw, bad)
    with pytest.raises(GateError, match="r3_plan_sample_outside_retrieval"):
        _validate_plan(requests["repeat-001-no_library"], plan.model_dump_json())


class MixedTransport:
    def generate(self, request, prompt):
        if request.case.arm == "no_library":
            return PlannerReply(
                R3Plan(
                    selected_sample_ids=[], patches=[], abstain=True, decision_summary="abstain"
                ).model_dump_json()
            )
        if request.case.arm == "raw_examples":
            return PlannerReply("{bad json")
        return PlannerReply(None, error="timeout", http_attempts=1, source="local_fake")


class CombineTransport:
    def generate(self, request, prompt):
        samples = request.compatible_samples
        chosen = samples[:2] if request.case.arm == "primitive_examples" else samples[1:2]
        value = (
            "Synthetic baseline notice" if not samples else "\n".join(s.raw_example for s in chosen)
        )
        return PlannerReply(
            R3Plan(
                selected_sample_ids=[s.sample_id for s in chosen],
                patches=[Patch(pointer=request.allowed_surfaces[0]["pointer"], value=value)],
                abstain=False,
                decision_summary="synthetic sample composition",
            ).model_dump_json()
        )


def test_two_sample_combination_changes_materialized_task(library, tmp_path):
    report = run(ROOT, library, _config(), tmp_path / "matrix", CombineTransport())
    raw, structured = report["cases"][1:]
    assert len(raw["selected_sample_ids"]) == 1
    assert len(structured["selected_sample_ids"]) == 2
    assert raw["materialized_hash"] != structured["materialized_hash"]
    execution = json.loads(
        (
            tmp_path / "matrix/sealed/private/repeat-001-primitive_examples.execution.json"
        ).read_text()
    )
    materialized = execution["materialized_task"]
    pointer = json.loads(
        (tmp_path / "matrix/sealed/repeat-001-primitive_examples.request.json").read_text()
    )["allowed_surfaces"][0]["pointer"]
    parts = pointer.strip("/").split("/")
    value = materialized
    for part in parts:
        value = value[int(part)] if isinstance(value, list) else value[part]
    assert "\n" in value
    assert replay(ROOT, library, tmp_path / "matrix", tmp_path / "audit", compare=True) == report


def test_abstain_invalid_and_infra_keep_denominator(library, tmp_path):
    report = run(ROOT, library, _config(), tmp_path / "matrix", MixedTransport())
    assert report["status_counts"]["abstained"] == 1
    assert report["status_counts"]["invalid_plan"] == 1
    assert report["status_counts"]["infra_error"] == 1
    assert report["assigned"] == 3
    assert report["planner_http_attempts"] == 1
    assert report["victim_http_attempts"] == 0
    assert replay(ROOT, library, tmp_path / "matrix", tmp_path / "audit") == report


class GateTransport:
    def __init__(self):
        self.calls = 0

    def generate(self, request, prompt):
        self.calls += 1
        raise GateError("synthetic_planner_dependency_gate")


def test_dependency_gate_marks_remaining_cases_not_started(library, tmp_path):
    transport = GateTransport()
    report = run(ROOT, library, _config(), tmp_path / "matrix", transport)
    assert transport.calls == 1
    assert report["status_counts"]["infra_error"] == 1
    assert report["status_counts"]["not_started"] == 2
    assert report["assigned"] == 3
    assert replay(ROOT, library, tmp_path / "matrix", tmp_path / "audit", compare=True) == report


def test_library_and_pair_tamper_rejected(library, tmp_path):
    run(ROOT, library, _config(), tmp_path / "matrix", ScriptedTransport())
    report_path = tmp_path / "matrix/report.json"
    report_path.write_text('{"display":"tampered"}')
    assert replay(ROOT, library, tmp_path / "matrix", tmp_path / "recomputed")["assigned"] == 3
    with pytest.raises(GateError, match="r3_display_report_mismatch"):
        replay(ROOT, library, tmp_path / "matrix", tmp_path / "compare", compare=True)
    request_path = tmp_path / "matrix/sealed/repeat-001-raw_examples.request.json"
    request = json.loads(request_path.read_text())
    request["case"]["planner_model_id"] = "different-model"
    request_path.write_text(json.dumps(request))
    with pytest.raises(GateError, match="r3_request_pair_mismatch"):
        replay(ROOT, library, tmp_path / "matrix", tmp_path / "bad")


@pytest.mark.parametrize(
    "field,value",
    [("planner_model_id", "other"), ("planner_request_budget", 2), ("task_id", "pse-2.1-002")],
)
def test_rehashed_pair_drift_rejected(library, tmp_path, field, value):
    from stac_attack_lab.hashing import file_hash, stable_hash

    run(ROOT, library, _config(), tmp_path / "matrix", ScriptedTransport())
    request_path = tmp_path / "matrix/sealed/repeat-001-raw_examples.request.json"
    request = json.loads(request_path.read_text())
    request["case"][field] = value
    request_path.write_text(json.dumps(request))
    manifest_path = tmp_path / "matrix/manifest.json"
    manifest = json.loads(manifest_path.read_text())
    manifest["files"]["sealed/repeat-001-raw_examples.request.json"] = file_hash(request_path)
    manifest["manifest_hash"] = stable_hash(
        {k: v for k, v in manifest.items() if k != "manifest_hash"}
    )
    manifest_path.write_text(json.dumps(manifest))
    with pytest.raises(GateError, match="r3_request_pair_mismatch"):
        replay(ROOT, library, tmp_path / "matrix", tmp_path / "bad")


def test_formal_unavailable_and_duplicate_launch(library, tmp_path):
    with pytest.raises(GateError, match="r3_formal_heldout_split_unavailable"):
        build_manifest(ROOT, library, _config().model_copy(update={"scope": "formal"}))
    run(ROOT, library, _config(), tmp_path / "matrix", ScriptedTransport())
    with pytest.raises(GateError, match="r3_output_exists"):
        run(ROOT, library, _config(), tmp_path / "matrix", ScriptedTransport())


def test_library_rewrite_rejected(library, tmp_path):
    copied = tmp_path / "library"
    import shutil

    shutil.copytree(library, copied)
    raw_path = copied / "raw.json"
    value = json.loads(raw_path.read_text())
    value[0]["raw_example"] += " changed"
    raw_path.write_text(json.dumps(value))
    with pytest.raises(GateError, match="r3_library_file_hash_invalid"):
        build_manifest(ROOT, copied, _config())
