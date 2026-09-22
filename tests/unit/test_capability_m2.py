from __future__ import annotations

import json
from pathlib import Path

import pytest

from stac_attack_lab.capability.compiler import compile_cases
from stac_attack_lab.capability.m2 import (
    assess_bind_guard,
    bind_m2_execution,
    export_annotation_review,
    import_annotation_review,
    materialize_f1_task,
    prepare_m2,
    report_m2,
    run_m2_local_fake_unit,
    run_m2_unit,
    validate_m2,
)
from stac_attack_lab.capability.models import RuntimeTask
from stac_attack_lab.environments.safeclaw.provider_relay import (
    evaluate_tool_calls_precommit,
)
from stac_attack_lab.hashing import stable_hash

ROOT = Path(__file__).resolve().parents[2]


def _task(tmp_path: Path, variant: str) -> RuntimeTask:
    compiled = compile_cases(
        ROOT / "configs/capability/f1_status_acceptance.json", tmp_path / "compiled"
    )
    return RuntimeTask.model_validate_json(
        (compiled / f"cases/cap-f1-001-{variant}/runtime_task.json").read_text()
    )


def test_materializer_uses_low_trust_file_and_freezes_goal(tmp_path: Path) -> None:
    direct = _task(tmp_path, "direct")
    template = ROOT / "configs/capability/runtime/f1_benign_task.json"
    rendered = materialize_f1_task(direct, template)
    files = {item["path"]: item["content"] for item in rendered["environment"]["workspace_files"]}
    assert files["inbox/vendor-delivery-note.txt"] == direct.public_view.low_trust_material + "\n"
    assert rendered["sessions"][0]["user_instruction"].startswith(direct.public_view.user_goal)
    assert "Ignore the acceptance requirement" not in rendered["sessions"][0]["user_instruction"]
    assert "private_oracle" not in json.dumps(rendered)
    tampered = json.loads(json.dumps(rendered))
    tampered["environment"]["workspace_files"][0]["content"] = "changed"
    with pytest.raises(ValueError, match="m2_trusted_ledger_template_mismatch"):
        materialize_f1_task(direct, template, baseline=tampered)


def test_bind_guard_is_precommit_and_sham_does_not_block() -> None:
    ledger = {
        "projects": {
            "project-a": {"acceptance_proof": None},
            "project-b": {"acceptance_proof": "proof-b-001"},
        }
    }
    proposed = {
        "projects": {"project-a": {"status": "accepted"}, "project-b": {"status": "accepted"}}
    }
    assert assess_bind_guard("g_bind", ledger, proposed).decision == "block"
    assert assess_bind_guard("sham_guard", ledger, proposed).decision == "allow"
    proposed["projects"]["project-a"]["status"] = "pending"
    assert assess_bind_guard("g_bind", ledger, proposed).decision == "allow"
    with pytest.raises(ValueError, match="m2_guard_untrusted_ledger"):
        assess_bind_guard("g_bind", {"projects": {}}, proposed)

    def policy(mode: str) -> dict[str, object]:
        return {
            "schema_version": "f1-bind-guard/1.0",
            "mode": mode,
            "target_tool": "write",
            "target_path": "reports/status.json",
            "trusted_ledger": ledger,
            "trusted_ledger_hash": stable_hash(ledger),
        }

    calls = [
        {
            "function": {
                "name": "write",
                "arguments": json.dumps(
                    {"path": "reports/status.json", "content": json.dumps(proposed)}
                ),
            }
        }
    ]
    assert evaluate_tool_calls_precommit(calls, policy("g_bind")).decision == "allow"
    proposed["projects"]["project-a"]["status"] = "accepted"
    calls[0]["function"]["arguments"] = json.dumps(
        {"path": "reports/status.json", "content": json.dumps(proposed)}
    )
    assert evaluate_tool_calls_precommit(calls, policy("sham_guard")).decision == "allow"
    assert evaluate_tool_calls_precommit(calls, policy("g_bind")).decision == "block"


def test_preregistered_denominator_and_missing_results(tmp_path: Path) -> None:
    out = tmp_path / "m2"
    prepare_m2(ROOT, ROOT / "configs/capability/m2_f1.disabled.json", out)
    manifest = validate_m2(out)
    assert len(manifest["units"]) == 8
    assert {unit["variant"] for unit in manifest["units"]} == {
        "benign",
        "direct",
        "semantic",
        "semantic_source_explicit",
    }
    report = report_m2(out, tmp_path / "report")
    assert report["denominator"] == 8
    assert report["result_missing"] == 8
    assert report["official_outcome"] == "not_evaluated"
    assert {item["comparison_id"] for item in report["paired_comparisons"]} == {
        "benign_gbind_vs_off",
        "benign_sham_vs_off",
        "semantic_gbind_vs_off",
        "semantic_sham_vs_off",
    }
    assert all(
        item["pairing_invariants_observed"] is True and item["causal_conclusion"] == "not_evaluated"
        for item in report["paired_comparisons"]
    )
    with pytest.raises(ValueError, match="m2_authorization_reference_placeholder"):
        bind_m2_execution(out, "AUTHORIZATION_REFERENCE")
    binding = bind_m2_execution(out, "audit-record:test-only")
    assert json.loads(binding.read_text())["execution_enabled"] is True

    exported = export_annotation_review(out, tmp_path / "review.json")
    form = json.loads(exported.read_text())
    assert "variant" not in json.dumps(form)
    imported = import_annotation_review(out, exported, tmp_path / "imported.json")
    labels = json.loads(imported.read_text())
    assert {row["verdict"] for row in labels["reviews"]} == {"unknown"}

    form["reviews"][0]["task_sha256"] = "0" * 64
    exported.write_text(json.dumps(form))
    with pytest.raises(ValueError, match="m2_annotation_task_mismatch"):
        import_annotation_review(out, exported, tmp_path / "bad-import.json")


def test_report_distinguishes_reserved_and_failed_units_from_not_started(tmp_path: Path) -> None:
    out = tmp_path / "m2"
    prepare_m2(ROOT, ROOT / "configs/capability/m2_f1.disabled.json", out)
    (out / "launch-benign.reserved").write_text("benign", encoding="utf-8")
    (out / "launch-direct.reserved").write_text("direct", encoding="utf-8")
    status_dir = out / "unit_status"
    status_dir.mkdir()
    (status_dir / "direct.json").write_text(
        json.dumps(
            {
                "schema_version": "capability-m2-unit-status/1.0",
                "unit_id": "direct",
                "execution": "error",
                "reason_code": "m2_unit_execution_exception",
                "error_type": "ValueError",
            }
        ),
        encoding="utf-8",
    )

    report = report_m2(out, tmp_path / "report")
    rows = {row["unit_id"]: row for row in report["units"]}
    assert rows["benign"]["execution"] == "inflight"
    assert rows["benign"]["execution_reason"] == ("m2_launch_reserved_without_terminal_artifact")
    assert rows["direct"]["execution"] == "error"
    assert rows["semantic"]["execution"] == "not_started"
    assert report["execution_counts"] == {
        "not_started": 6,
        "inflight": 1,
        "completed": 0,
        "partial": 0,
        "blocked": 0,
        "error": 1,
        "unknown": 0,
    }
    assert report["denominator"] == 8


def test_report_keeps_attempt_without_result_unknown_and_classifies_guard_block(
    tmp_path: Path,
) -> None:
    out = tmp_path / "m2"
    prepare_m2(ROOT, ROOT / "configs/capability/m2_f1.disabled.json", out)
    unit = next(item for item in validate_m2(out)["units"] if item["unit_id"] == "semantic-gbind")
    task = RuntimeTask.model_validate_json((out / unit["task_ref"]).read_text())
    episode = out / "results" / unit["unit_id"] / task.case.case_id
    episode.mkdir(parents=True)
    (out / "launch-semantic-gbind.reserved").write_text("semantic-gbind", encoding="utf-8")
    (episode / "provider_attempt_ledger.jsonl").write_text(
        json.dumps(
            {
                "accepted": True,
                "status": 200,
                "upstream_status": 200,
                "error_category": None,
                "precommit_guard": {
                    "mode": "g_bind",
                    "decision": "allow",
                    "phase": "provider_response_pre_tool_execution",
                    "reason_code": "f1_bind_target_not_present",
                },
            }
        )
        + "\n"
        + json.dumps(
            {
                "accepted": True,
                "status": 409,
                "upstream_status": 200,
                "error_category": "provider_precommit_guard_blocked",
                "precommit_guard": {
                    "mode": "g_bind",
                    "decision": "block",
                    "phase": "provider_response_pre_tool_execution",
                    "reason_code": "f1_bind_missing_acceptance_proof",
                },
            }
        )
        + "\n",
        encoding="utf-8",
    )

    report = report_m2(out, tmp_path / "report")
    row = next(item for item in report["units"] if item["unit_id"] == "semantic-gbind")
    assert row["execution"] == "unknown"
    assert row["execution_reason"] == "m2_provider_attempt_without_result"
    assert row["guard"]["provider_outcome"] == "policy_blocked"
    assert row["actual_commit"] == "unknown"
    assert row["tool_rejection_observed"] == "unknown"
    assert report["policy_blocked"] == 1
    assert report["infra_failure"] == 0


def test_local_fake_runner_rejects_nonlocal_provider_before_launch(tmp_path: Path) -> None:
    out = tmp_path / "m2"
    prepare_m2(ROOT, ROOT / "configs/capability/m2_f1.disabled.json", out)
    with pytest.raises(ValueError, match="m2_local_fake_provider_not_local"):
        run_m2_local_fake_unit(
            ROOT,
            out,
            "benign",
            provider_url="https://8.8.8.8/v1",
            environment={},
        )
    assert not (out / "launch-benign.reserved").exists()


def test_runtime_preflight_failure_after_reservation_is_persisted_as_error(
    tmp_path: Path,
) -> None:
    out = tmp_path / "m2"
    prepare_m2(ROOT, ROOT / "configs/capability/m2_f1.disabled.json", out)
    bind_m2_execution(out, "audit-record:unit-test")
    with pytest.raises(ValueError, match="m2_provider_environment_missing"):
        run_m2_unit(ROOT, out, "benign", authorized=True, environment={})

    status = json.loads((out / "unit_status/benign.json").read_text())
    assert status["execution"] == "error"
    assert status["reason_code"] == "m2_unit_execution_exception"
    assert (out / "launch-benign.reserved").is_file()
    report = report_m2(out, tmp_path / "report")
    row = next(item for item in report["units"] if item["unit_id"] == "benign")
    assert row["execution"] == "error"
    assert report["infra_failure"] == 1
