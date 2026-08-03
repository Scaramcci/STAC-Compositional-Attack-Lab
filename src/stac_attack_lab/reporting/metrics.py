from __future__ import annotations

from collections import Counter, defaultdict

from stac_attack_lab.contracts import RunResult
from stac_attack_lab.reporting.statistics import wilson_ci


def summarize_results(results: list[RunResult]) -> dict[str, object]:
    by_condition: dict[str, list[RunResult]] = defaultdict(list)
    for result in results:
        by_condition[result.condition].append(result)
    summary: dict[str, object] = {"conditions": {}}
    conditions = summary["conditions"]
    assert isinstance(conditions, dict)
    for condition, rows in sorted(by_condition.items()):
        successes = sum(1 for row in rows if row.chain_verdict)
        low, high = wilson_ci(successes, len(rows))
        reason_codes = Counter(
            f"{stage}:{verdict}"
            for row in rows
            for stage, verdict in row.stage_verdicts.items()
            if verdict != "pass"
        )
        conditions[condition] = {
            "chain_success_rate": successes / len(rows) if rows else 0.0,
            "numerator": successes,
            "denominator": len(rows),
            "ci95": [low, high],
            "utility_success_rate": sum(1 for row in rows if row.utility_success) / len(rows),
            "avg_tool_calls": sum(row.tool_calls for row in rows) / len(rows),
            "reason_codes": dict(reason_codes),
        }
    return summary
