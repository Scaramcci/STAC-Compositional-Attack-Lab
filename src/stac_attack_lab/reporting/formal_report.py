from __future__ import annotations

import csv
import json
from pathlib import Path

from stac_attack_lab.recording.events import read_jsonl
from stac_attack_lab.recording.formal_run_recorder import (
    FormalRunManifest,
    FormalRunRecorder,
)
from stac_attack_lab.reporting.formal_metrics import summarize_formal_results
from stac_attack_lab.verification.formal_models import FormalRunResult


def build_formal_report(run_root: Path) -> dict[str, object]:
    recorder = FormalRunRecorder(run_root)
    audit = recorder.audit()
    if not audit.passed:
        raise ValueError("formal_recorder_audit_failed:" + ",".join(audit.finding_codes))
    manifest = FormalRunManifest.model_validate_json(
        (run_root / "formal_run_manifest.json").read_text(encoding="utf-8")
    )
    results = [
        FormalRunResult.model_validate(item) for item in read_jsonl(run_root / "results.jsonl")
    ]
    metrics = summarize_formal_results(results)
    gap_counts: dict[str, int] = {}
    for result in results:
        for gap in result.official_verdict.instrumentation_gaps:
            gap_counts[gap] = gap_counts.get(gap, 0) + 1
    payload: dict[str, object] = {
        "schema_version": "2.0",
        "run_id": manifest.run_id,
        "result_count": len(results),
        "metrics": metrics.model_dump(mode="json"),
        "instrumentation_gap_counts": dict(sorted(gap_counts.items())),
        "provenance": {
            "config_hash": manifest.config_hash,
            "library_version": manifest.library_version,
            "library_hash": manifest.library_hash,
            "registry_hash": manifest.registry_hash,
            "upstream_commit": manifest.upstream_commit,
            "safety_patch_hash": manifest.safety_patch_hash,
            "target_model_id": manifest.target_model_id,
        },
        "limitations": [
            "Execution errors are excluded from mechanism and terminal success denominators.",
            "Not-observable mechanism cases are excluded from full-chain success denominator.",
            "Official SafeClaw terminal verdicts are not recomputed by STAC.",
        ],
    }
    (run_root / "formal_report.json").write_text(
        json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    with (run_root / "formal_results.csv").open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(
            handle,
            fieldnames=[
                "case_id",
                "pair_id",
                "condition",
                "seed",
                "task_id",
                "binding_valid",
                "full_chain_success",
                "official_terminal_success",
                "forbidden_shortcut",
                "execution_error",
                "not_observable_count",
                "duration_ms",
                "cost",
            ],
        )
        writer.writeheader()
        for result in results:
            writer.writerow(
                {
                    "case_id": result.case_id,
                    "pair_id": result.pair_id,
                    "condition": result.condition,
                    "seed": result.seed,
                    "task_id": result.task_id,
                    "binding_valid": result.binding_valid,
                    "full_chain_success": result.full_chain_success,
                    "official_terminal_success": (
                        result.official_verdict.attack_succeeded
                        if result.official_verdict.execution_complete
                        else None
                    ),
                    "forbidden_shortcut": result.forbidden_shortcut,
                    "execution_error": result.execution_error,
                    "not_observable_count": result.not_observable_count,
                    "duration_ms": result.duration_ms,
                    "cost": result.cost,
                }
            )
    overall = metrics.overall
    lines = [
        "# Formal SafeClaw Evaluation Report",
        "",
        f"Run: `{manifest.run_id}`",
        f"Results: {len(results)}",
        "",
        "## Primary Metrics",
        "",
        "| Metric | Numerator | Denominator | Rate |",
        "|---|---:|---:|---:|",
    ]
    for label, metric in (
        ("Full chain success", overall.full_chain_success),
        ("Official terminal success", overall.official_terminal_success),
        ("Shortcut given terminal success", overall.shortcut_rate_given_terminal_success),
        ("Instrumentation coverage", overall.instrumentation_coverage),
        ("Execution error", overall.execution_error_rate),
        ("Benign utility", overall.benign_utility),
    ):
        rate = "NA" if metric.rate is None else f"{metric.rate:.4f}"
        lines.append(f"| {label} | {metric.numerator} | {metric.denominator} | {rate} |")
    lines.extend(
        [
            "",
            "## Provenance",
            "",
            f"- Library: `{manifest.library_version}` / `{manifest.library_hash}`",
            f"- Registry: `{manifest.registry_hash}`",
            f"- SafeClaw commit: `{manifest.upstream_commit}`",
            f"- Safety patch: `{manifest.safety_patch_hash}`",
            "",
            "## Limitations",
            "",
            "- Execution errors and instrumentation gaps use separate denominators.",
            "- Official terminal results remain authoritative and unchanged.",
        ]
    )
    (run_root / "formal_report.md").write_text("\n".join(lines) + "\n", encoding="utf-8")
    return payload
