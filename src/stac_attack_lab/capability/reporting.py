from __future__ import annotations

import json
from pathlib import Path

from stac_attack_lab.capability.models import EpisodeResult, Verdict


def build_capability_report(run_root: Path, output_root: Path) -> Path:
    results = [
        EpisodeResult.model_validate_json(path.read_text(encoding="utf-8"))
        for path in sorted(run_root.glob("*/episode_result.json"))
    ]
    if not results:
        raise ValueError("capability_report_no_episode_results")
    output_root.mkdir(parents=True, exist_ok=False)
    total = len(results)
    known = [item for item in results if item.harm.verdict in {Verdict.TRUE, Verdict.FALSE}]
    harmed = [item for item in results if item.harm.verdict == Verdict.TRUE]
    metrics = {
        "matrix_size": total,
        "execution_complete": sum(item.execution_status == "completed" for item in results),
        "harm_confirmed": len(harmed),
        "harm_evaluable": len(known),
        "harm_unknown": total - len(known),
        "asr_observed": len(harmed) / len(known) if known else None,
        "asr_matrix_lower_bound": len(harmed) / total,
        "pp_success_count": sum(item.pp_success for item in results),
        "unknown_constraint_episodes": sum(
            any(check.status.value == "unknown" for check in item.constraints) for item in results
        ),
        "network_requests_performed": False,
    }
    (output_root / "metrics.json").write_text(
        json.dumps(metrics, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    lines = [
        "# Capability offline report",
        "",
        "Synthetic/fake engineering evidence only. No provider request or official evaluation ran.",
        "",
        f"- Matrix cells: {total}",
        f"- Confirmed harm: {len(harmed)} / {len(known)} evaluable",
        f"- PP success: {metrics['pp_success_count']} / {total}",
        f"- Episodes with unknown constraints: {metrics['unknown_constraint_episodes']}",
        "",
        "| case | variant | harm | attempted | Adopt | PP |",
        "|---|---|---|---:|---|---:|",
    ]
    for item in results:
        adopt = next(
            assessment.overall_execution.value
            for assessment in item.primitive_analysis
            if assessment.primitive.value == "Adopt"
        )
        lines.append(
            f"| {item.case_id} | {item.variant.value} | {item.harm.verdict.value} | "
            f"{str(item.harm.attempted_harm).lower()} | {adopt} | {str(item.pp_success).lower()} |"
        )
    report = output_root / "report.md"
    report.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return report
