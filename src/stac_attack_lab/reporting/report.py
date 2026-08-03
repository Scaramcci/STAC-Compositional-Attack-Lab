from __future__ import annotations

import json
from pathlib import Path
from typing import Any, cast

from stac_attack_lab.contracts import RunResult
from stac_attack_lab.reporting.metrics import summarize_results


def build_report(run_root: Path) -> dict[str, object]:
    results_path = run_root / "results.jsonl"
    results = [
        RunResult.model_validate_json(line)
        for line in results_path.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]
    report = summarize_results(results)
    report["run_count"] = len(results)
    report["integration_skips"] = [
        {
            "adapter": "agentdojo_or_shade_arena",
            "reason": "Dependency unavailable; local contract smoke remains deterministic.",
        }
    ]
    (run_root / "report.json").write_text(
        json.dumps(report, indent=2, sort_keys=True), encoding="utf-8"
    )
    lines = ["# Smoke Report", "", f"Runs: {len(results)}", ""]
    conditions = cast(dict[str, dict[str, Any]], report["conditions"])
    for condition, data in conditions.items():
        lines.append(f"- {condition}: {data['numerator']}/{data['denominator']} chain success")
    (run_root / "report.md").write_text("\n".join(lines) + "\n", encoding="utf-8")
    return report
