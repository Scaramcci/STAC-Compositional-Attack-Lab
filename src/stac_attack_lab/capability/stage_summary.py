"""Read-only provenance and case projection for the F1/F3/F5 development stage."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, cast

from stac_attack_lab.capability.evidence import verify_episode_evidence, write_private_json
from stac_attack_lab.capability.m3_f5 import recompute_f5_episode
from stac_attack_lab.hashing import file_hash, stable_hash

RUNS = Path("experiments/runs/capability")
F1 = "m2-f1-candidate-20260922-b6da0cd-final-v1"
F1_REVIEW = "m2-f1-real-review-20260922-7232928-v1"
F1_AI = "m2-ai-review-mixed-derived-20260923-a29903a-v1"
F3 = "m3a-f3-prepared-20260923-a29903a-v5"
F3_REVIEW = "m3a-f3-v5-final-review-20260923-a29903a-v1"
F3_AI = "m3-f3-ai-review-reanalysis-20260924-a29903a-v4"
F3_AI_RUN = "m3-f3-ai-review-prepared-20260923-a29903a-v4"
F5_BENIGN = "m3b-f5-prepared-20260924-a29903a-v11"
F5_BATCH = "m3b-f5-external-prepared-20260924-a29903a-v4"
F5_REPORT = "m3b-f5-external-final-report-20260924-a29903a-v1.json"


def _read(path: Path) -> dict[str, Any]:
    if not path.is_file():
        raise ValueError(f"stage_source_missing:{path}")
    return cast(dict[str, Any], json.loads(path.read_text(encoding="utf-8")))


def _manifest(root: Path) -> dict[str, Any]:
    manifest = _read(root / "manifest.json")
    if manifest.get("manifest_hash") != stable_hash(
        {key: value for key, value in manifest.items() if key != "manifest_hash"}
    ):
        raise ValueError("stage_manifest_hash_mismatch")
    return manifest


def _units(
    root: Path,
    manifest: dict[str, Any],
    expected: list[str],
    *,
    nested_task: bool = False,
    selected: list[str] | None = None,
) -> list[dict[str, Any]]:
    units = manifest["units"]
    if [unit["unit_id"] for unit in units] != expected:
        raise ValueError("stage_unit_identity_mismatch")
    rows = []
    for unit in units:
        if selected is not None and unit["unit_id"] not in selected:
            continue
        task = _read(root / unit["task_ref"])
        task_id = task["case"]["case_id"] if nested_task else task["task_id"]
        episode = root / "results" / unit["unit_id"]
        if nested_task:
            episode = episode / task_id
        bundle = verify_episode_evidence(episode)
        observed_task = _read(episode / "runtime_task.json")
        if task != observed_task:
            raise ValueError("stage_task_identity_mismatch")
        if not nested_task and file_hash(root / unit["task_ref"]) != file_hash(
            episode / "runtime_task.json"
        ):
            raise ValueError("stage_task_input_mismatch")
        rows.append(
            {
                "unit_id": unit["unit_id"],
                "task_id": task_id,
                "task_sha256": file_hash(root / unit["task_ref"]),
                "materialized_sha256": file_hash(root / unit["materialized_ref"]),
                "bundle_hash": bundle.bundle_hash,
                "input_hashes": bundle.input_hashes,
                "split_group_id": task.get("split_group_id"),
            }
        )
    return rows


def build_stage_summary(project_root: Path) -> dict[str, Any]:
    base = project_root / RUNS
    f1_root, f3_root = base / F1, base / F3
    f1_manifest, f3_manifest = _manifest(f1_root), _manifest(f3_root)
    f1_ids = [
        "benign",
        "direct",
        "semantic",
        "source-explicit",
        "benign-gbind",
        "semantic-gbind",
        "benign-sham",
        "semantic-sham",
    ]
    f3_ids = ["benign", "direct", "semantic"]
    f1_sources = _units(f1_root, f1_manifest, f1_ids, nested_task=True)
    f3_sources = _units(f3_root, f3_manifest, f3_ids)
    f1_report_path = base / F1_REVIEW / "report/report.json"
    f1_review_path = base / F1_REVIEW / "independent_review.json"
    f1_ai_path = base / F1_AI / "mixed_review_summary.json"
    f1_import_path = base / F1_AI / "review_import.json"
    f1_report, f1_review = _read(f1_report_path), _read(f1_review_path)
    f1_ai, f1_import = _read(f1_ai_path), _read(f1_import_path)
    f1_config_path = f1_root / "m2_config.snapshot.json"
    f1_config = _read(f1_config_path)
    if (
        f1_report["manifest_hash"] != f1_manifest["manifest_hash"]
        or file_hash(f1_config_path) != f1_manifest["config_sha256"]
        or f1_review["candidate_manifest_hash"] != f1_manifest["manifest_hash"]
        or f1_review["report_sha256"] != file_hash(f1_report_path)
        or f1_ai["source_denominator"] != 8
        or f1_ai["valid_ai_labels"] != 8
        or set(f1_ai["prompt_versions"]) != {"1.0", "1.1"}
        or f1_import["source_manifest_hash"] != f1_manifest["manifest_hash"]
    ):
        raise ValueError("stage_f1_source_mismatch")
    f1_seals = {row["unit_id"]: row["bundle_hash"] for row in f1_sources}
    if any(f1_seals[row["unit_id"]] != row["bundle_hash"] for row in f1_review["units"]):
        raise ValueError("stage_f1_seal_mismatch")
    f1_labels = {row["unit_id"]: row for row in f1_import["reviews"]}
    if set(f1_labels) != set(f1_ids) or [row["unit_id"] for row in f1_report["units"]] != f1_ids:
        raise ValueError("stage_f1_label_identity_mismatch")

    f3_report_path = base / F3_REVIEW / "report.json"
    f3_accept_path = base / F3_REVIEW / "acceptance.json"
    f3_map_path = base / F3_REVIEW / "adopt_review/researcher/review_mapping.json"
    f3_ai_path = base / F3_AI / "report.json"
    f3_report, f3_accept = _read(f3_report_path), _read(f3_accept_path)
    f3_map, f3_ai = _read(f3_map_path), _read(f3_ai_path)
    f3_ai_run = base / F3_AI_RUN
    f3_ai_manifest = _manifest(f3_ai_run)
    f3_ai_summary_path = f3_ai_run / "summary.json"
    f3_ai_summary = _read(f3_ai_summary_path)
    f3_config_path = f3_root / "m3_f3_config.snapshot.json"
    f3_config = _read(f3_config_path)
    if (
        f3_report["manifest_hash"] != f3_manifest["manifest_hash"]
        or file_hash(f3_config_path) != f3_manifest["config_sha256"]
        or f3_accept["manifest_hash"] != f3_manifest["manifest_hash"]
        or f3_ai["denominator"] != 3
        or f3_ai["valid_label_count"] != 3
        or f3_ai["verifier_version"] != "capability-m2-ai-review/1.1"
        or f3_ai["processing_versions"]["verifier"]["changed"] is not True
        or f3_ai["source_run_id"] != F3_AI_RUN
        or f3_ai_summary["http_attempts"] != 3
        or f3_ai_summary["run_id"] != F3_AI_RUN
    ):
        raise ValueError("stage_f3_source_mismatch")
    f3_seals = {row["unit_id"]: row["bundle_hash"] for row in f3_sources}
    mapping = {row["review_id"]: row["unit_id"] for row in f3_map["mapping"]}
    if (
        set(mapping.values()) != set(f3_ids)
        or any(f3_seals[row["unit_id"]] != row["evidence_bundle_hash"] for row in f3_map["mapping"])
        or set(mapping) != {row["review_id"] for row in f3_ai["reviews"]}
    ):
        raise ValueError("stage_f3_label_identity_mismatch")
    f3_labels = {mapping[row["review_id"]]: row["verdicts"] for row in f3_ai["reviews"]}

    f5_benign_root, f5_batch_root = base / F5_BENIGN, base / F5_BATCH
    f5_benign_manifest, f5_batch_manifest = _manifest(f5_benign_root), _manifest(f5_batch_root)
    f5_benign_sources = _units(f5_benign_root, f5_benign_manifest, f3_ids, selected=["benign"])
    f5_batch_sources = _units(f5_batch_root, f5_batch_manifest, ["direct", "semantic"])
    f5_report_path = base / F5_REPORT
    f5_report = _read(f5_report_path)
    f5_config_path = f5_batch_root / "config.snapshot.json"
    f5_config = _read(f5_config_path)
    if (
        f5_batch_manifest["external_baseline"]["manifest_hash"]
        != f5_benign_manifest["manifest_hash"]
        or file_hash(f5_config_path) != f5_batch_manifest["config_sha256"]
        or f5_batch_manifest["external_baseline"]["bundle_hash"]
        != f5_benign_sources[0]["bundle_hash"]
        or f5_report["current_batch_denominator"] != 2
        or f5_report["historical_baseline_denominator"] != 1
        or [row["unit_id"] for row in f5_report["rows"]] != f3_ids
    ):
        raise ValueError("stage_f5_source_mismatch")
    f5_rows = []
    for condition, run in (
        ("benign", f5_benign_root),
        ("direct", f5_batch_root),
        ("semantic", f5_batch_root),
    ):
        episode = recompute_f5_episode(run / "results" / condition)
        original = next(row for row in f5_report["rows"] if row["unit_id"] == condition)
        if (
            episode["acceptance"] != original["acceptance"]
            or episode["evidence"] != original["evidence"]
        ):
            raise ValueError("stage_f5_derived_mismatch")
        f5_rows.append(
            {
                "unit_id": condition,
                "source_kind": "historical_development_baseline"
                if condition == "benign"
                else "current_batch",
                "execution": episode["execution_status"],
                "utility": episode["acceptance"]["business_utility"],
                "harm": episode["acceptance"]["harm"],
                "procedure": episode["acceptance"]["procedural_compliance"],
                "recover": episode["evidence"]["recover"],
                "provider_attempts": episode["http_attempt_records"],
                "official_outcome": "not_evaluated",
            }
        )

    return {
        "schema_version": "capability-stage-summary/1.0",
        "source_manifest": {
            "F1": {
                "run_ref": str(RUNS / F1),
                "manifest_hash": f1_manifest["manifest_hash"],
                "config_sha256": file_hash(f1_config_path),
                "victim_model": f1_config["model_id"],
                "units": f1_sources,
                "review_ref": str(RUNS / F1_REVIEW / "report/report.json"),
                "review_sha256": file_hash(f1_report_path),
                "ai_ref": str(RUNS / F1_AI / "mixed_review_summary.json"),
                "ai_sha256": file_hash(f1_ai_path),
                "annotation_model": "gpt-5.6-sol",
                "ai_prompt_versions": f1_ai["prompt_versions"],
                "review_identity": "ai_only_no_independent_human",
            },
            "F3": {
                "run_ref": str(RUNS / F3),
                "manifest_hash": f3_manifest["manifest_hash"],
                "config_sha256": file_hash(f3_config_path),
                "victim_model": f3_config["model_id"],
                "units": f3_sources,
                "review_ref": str(RUNS / F3_REVIEW / "report.json"),
                "review_sha256": file_hash(f3_report_path),
                "acceptance_sha256": file_hash(f3_accept_path),
                "ai_ref": str(RUNS / F3_AI / "report.json"),
                "ai_sha256": file_hash(f3_ai_path),
                "ai_run_ref": str(RUNS / F3_AI_RUN),
                "ai_run_manifest_hash": f3_ai_manifest["manifest_hash"],
                "ai_run_summary_sha256": file_hash(f3_ai_summary_path),
                "ai_processing_versions": f3_ai["processing_versions"],
                "review_identity": "ai_only_no_independent_human",
            },
            "F5": {
                "historical_run_ref": str(RUNS / F5_BENIGN),
                "historical_manifest_hash": f5_benign_manifest["manifest_hash"],
                "current_run_ref": str(RUNS / F5_BATCH),
                "current_manifest_hash": f5_batch_manifest["manifest_hash"],
                "current_config_sha256": file_hash(f5_config_path),
                "source_sha256": f5_batch_manifest["source_sha256"],
                "historical_units": f5_benign_sources[:1],
                "current_units": f5_batch_sources,
                "review_ref": str(RUNS / F5_REPORT),
                "review_sha256": file_hash(f5_report_path),
                "victim_model": f5_config["model_id"],
                "review_identity": "no_ai_or_human_adopt_review",
            },
        },
        "denominators": {
            "selected_development_observations": {
                "F1": 8,
                "F3": 3,
                "F5_historical_baseline": 1,
                "F5_current_batch": 2,
            },
            "F1_victim_http": f1_review["provider_attempts"],
            "F1_annotation_http": f1_ai["combined_http_attempts"],
            "F1_valid_ai_labels": f1_ai["valid_ai_labels"],
            "F1_original_annotation_errors": len(f1_ai["preserved_base_annotation_errors"]),
            "F3_victim_http": f3_accept["provider_accounting"]["victim_http_attempts"],
            "F3_valid_ai_labels": f3_ai["valid_label_count"],
            "F3_annotation_http": f3_ai_summary["http_attempts"],
            "F5_historical_victim_http": f5_report["request_usage_by_run"][F5_BENIGN][
                "victim_http_attempts"
            ],
            "F5_current_victim_http": f5_report["request_usage_by_run"][F5_BATCH][
                "victim_http_attempts"
            ],
            "engineering_debug_attempts": "excluded_from_selected_set; see progress checkpoints",
        },
        "cases": {
            "F1": [
                {
                    "unit_id": row["unit_id"],
                    "execution": row["execution"],
                    "utility": row["utility"],
                    "harm": row["harm"],
                    "procedure": row["constraints"],
                    "adopt": f1_labels[row["unit_id"]]["verdict"],
                    "ai_label_source": "mixed_prompt_1.0_1.1",
                    "official_outcome": "not_evaluated",
                }
                for row in f1_report["units"]
            ],
            "F3": [
                {
                    "unit_id": row["unit_id"],
                    "execution": row["execution"],
                    "utility_s1": row["evidence"]["s1_utility"]["state"],
                    "utility_s2": row["evidence"]["s2_utility"]["state"],
                    "harm": row["evidence"]["harm"]["verdict"],
                    "persist": row["evidence"]["persist"]["state"],
                    "recall": row["evidence"]["recall"]["state"],
                    "actual_commit": row["evidence"]["actual_commit"]["state"],
                    "ai_labels": f3_labels[row["unit_id"]],
                    "official_outcome": "not_evaluated",
                }
                for row in f3_report["units"]
            ],
            "F5": f5_rows,
        },
        "official_outcome": "not_evaluated",
        "usage_is_not_billing": True,
    }


def write_stage_summary(project_root: Path, output: Path) -> Path:
    if output.exists():
        raise FileExistsError("stage_summary_output_exists")
    write_private_json(output, build_stage_summary(project_root))
    return output
