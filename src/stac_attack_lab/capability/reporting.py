from __future__ import annotations

import json
from collections import defaultdict
from pathlib import Path
from typing import Any

from stac_attack_lab.capability.models import BatchManifest, EpisodeResult, Verdict


def _read_network_attempts(run_root: Path, manifest: BatchManifest) -> tuple[int, bool | None]:
    attempts = 0
    ledgers = sorted(run_root.glob(manifest.provider_ledger_ref))
    if not ledgers:
        return 0, None
    for path in ledgers:
        for line in path.read_text(encoding="utf-8").splitlines():
            if not line.strip():
                continue
            item = json.loads(line)
            if not isinstance(item, dict):
                raise ValueError("capability_provider_ledger_record_invalid")
            value = item.get("upstream_attempt_count", 1 if item.get("accepted") is True else 0)
            if not isinstance(value, int) or value < 0:
                raise ValueError("capability_provider_ledger_attempt_count_invalid")
            attempts += value
    return attempts, attempts > 0


def build_capability_report(run_root: Path, output_root: Path) -> Path:
    manifest_path = run_root / "batch_manifest.json"
    if not manifest_path.is_file():
        raise ValueError("capability_batch_manifest_missing")
    manifest = BatchManifest.model_validate_json(manifest_path.read_text(encoding="utf-8"))
    output_root.mkdir(parents=True, exist_ok=False)
    rows: list[tuple[Any, EpisodeResult | None, str]] = []
    for unit in manifest.units:
        result_path = (run_root / unit.result_ref).resolve()
        if run_root.resolve() not in result_path.parents:
            raise ValueError("capability_result_ref_outside_run")
        if not result_path.is_file():
            rows.append((unit, None, "result_missing"))
            continue
        parsed_result = EpisodeResult.model_validate_json(result_path.read_text(encoding="utf-8"))
        if parsed_result.case_id != unit.case_id or parsed_result.variant != unit.variant:
            raise ValueError("capability_result_unit_identity_mismatch")
        rows.append((unit, parsed_result, "result_loaded"))

    grouped: dict[str, dict[str, int]] = defaultdict(
        lambda: {
            "preregistered": 0,
            "result_present": 0,
            "execution_completed": 0,
            "harm_true": 0,
            "harm_false": 0,
            "harm_unknown": 0,
            "utility_true": 0,
            "utility_false": 0,
            "utility_unknown": 0,
        }
    )
    for unit, row_result, _ in rows:
        key = f"{unit.variant.value}/{unit.transport}"
        group = grouped[key]
        group["preregistered"] += 1
        if row_result is None:
            continue
        group["result_present"] += 1
        group["execution_completed"] += row_result.execution_status == "completed"
        group[f"harm_{row_result.harm.verdict.value}"] += 1
        group[f"utility_{row_result.benign_utility.value}"] += 1

    attempt_count, network = _read_network_attempts(run_root, manifest)
    results = [result for _, result, _ in rows if result is not None]
    attack_results = [item for item in results if item.variant.value != "benign"]
    real_attack_results = [
        result
        for unit, result, _ in rows
        if result is not None and unit.variant.value != "benign" and unit.transport != "fixture"
    ]
    real_evaluable = [
        item for item in real_attack_results if item.harm.verdict in {Verdict.TRUE, Verdict.FALSE}
    ]
    metrics = {
        "batch_id": manifest.batch_id,
        "matrix_size": len(manifest.units),
        "result_present": len(results),
        "result_missing": len(manifest.units) - len(results),
        "execution_complete": sum(item.execution_status == "completed" for item in results),
        "infra_or_incomplete": sum(item.execution_status != "completed" for item in results)
        + len(manifest.units)
        - len(results),
        "harm_confirmed_all_tracks": sum(item.harm.verdict == Verdict.TRUE for item in results),
        "harm_unknown_all_tracks": sum(item.harm.verdict == Verdict.UNKNOWN for item in results),
        "benign_utility_verified": sum(
            item.variant.value == "benign" and item.benign_utility == Verdict.TRUE
            for item in results
        ),
        "attack_track_result_count": len(attack_results),
        "asr_observed_real_only": (
            sum(item.harm.verdict == Verdict.TRUE for item in real_evaluable) / len(real_evaluable)
            if real_evaluable
            else None
        ),
        "fixture_results_are_engineering_only": any(
            unit.transport == "fixture" for unit in manifest.units
        ),
        "provider_attempt_count": attempt_count,
        "network_requests_performed": network,
        "groups": dict(sorted(grouped.items())),
    }
    (output_root / "metrics.json").write_text(
        json.dumps(metrics, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    lines = [
        "# Capability batch report",
        "",
        "Fixture rows are engineering checks. Missing or failed rows remain "
        "in the manifest denominator.",
        "",
        f"- Preregistered units: {len(manifest.units)}",
        f"- Results present: {len(results)}",
        f"- Results missing: {metrics['result_missing']}",
        f"- Provider attempts from ledger: {attempt_count}",
        "",
        "| case | variant | transport | stage | result | harm | utility |",
        "|---|---|---|---|---|---|---|",
    ]
    for unit, row_result, load_status in rows:
        lines.append(
            f"| {unit.case_id} | {unit.variant.value} | {unit.transport} | {unit.stage} | "
            f"{load_status} | {row_result.harm.verdict.value if row_result else 'unknown'} | "
            f"{row_result.benign_utility.value if row_result else 'unknown'} |"
        )
    report = output_root / "report.md"
    report.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return report
