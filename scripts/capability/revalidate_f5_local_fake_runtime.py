#!/usr/bin/env python3
"""Revalidate sealed local F5 integration evidence with the current verifier."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

from stac_attack_lab.capability.evidence import verify_episode_evidence, write_private_json
from stac_attack_lab.capability.m3_f5 import (
    assess_f5_acceptance,
    f5_comparison_gate,
    verify_f5_evidence,
)
from stac_attack_lab.hashing import file_hash

EXPECTED = {
    "complete": {
        "requests": 7,
        "tools": 6,
        "recover": "observed",
        "commit": True,
        "recheck": "observed",
    },
    "ambiguous_commit": {
        "requests": 8,
        "tools": 7,
        "recover": "unknown",
        "commit": False,
        "recheck": "unknown",
    },
    "no_post_read": {
        "requests": 6,
        "tools": 5,
        "recover": "observed",
        "commit": True,
        "recheck": "unknown",
    },
    "missing_pre_with_post": {
        "requests": 6,
        "tools": 5,
        "recover": "observed",
        "commit": True,
        "recheck": "observed",
    },
}
LEGACY_EXPECTED = {
    "complete": {
        "requests": 6,
        "tools": 5,
        "recover": "observed",
        "commit": True,
        "recheck": "observed",
    },
    "ambiguous_commit": {
        "requests": 7,
        "tools": 6,
        "recover": "unknown",
        "commit": False,
        "recheck": "unknown",
    },
    "no_post_read": {
        "requests": 5,
        "tools": 4,
        "recover": "observed",
        "commit": True,
        "recheck": "unknown",
    },
}


def _read(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def _jsonl(path: Path) -> list[dict[str, Any]]:
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line]


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("input", type=Path)
    parser.add_argument("output", type=Path)
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[2]
    source = args.input.resolve()
    output = args.output.resolve()
    if output.exists():
        raise FileExistsError("f5_fake_revalidation_output_exists")
    if not source.is_dir():
        raise FileNotFoundError("f5_fake_revalidation_input_missing")
    summary_path = source / "summary.json"
    summary = _read(summary_path)
    expected_cases = EXPECTED if set(summary.get("cases", {})) == set(EXPECTED) else LEGACY_EXPECTED
    if set(summary.get("cases", {})) != set(expected_cases):
        raise ValueError("f5_fake_revalidation_case_set_invalid")
    output.mkdir(parents=True, mode=0o700)
    rows = []
    input_hashes = {"summary.json": file_hash(summary_path)}
    for case, expected in expected_cases.items():
        directory = source / "cases" / case
        verify_episode_evidence(directory)
        names = (
            "runtime_events.jsonl",
            "provider_boundary_evidence.jsonl",
            "provider_attempt_ledger.jsonl",
            "checkpoints/initial.json",
            "checkpoints/final.json",
            "runtime_review.json",
            "episode_result.json",
            "evidence_bundle.json",
        )
        for name in names:
            input_hashes[f"cases/{case}/{name}"] = file_hash(directory / name)
        events = _jsonl(directory / "runtime_events.jsonl")
        boundary = _jsonl(directory / "provider_boundary_evidence.jsonl")
        ledger = _jsonl(directory / "provider_attempt_ledger.jsonl")
        review = _read(directory / "runtime_review.json")
        evidence = verify_f5_evidence(
            events,
            boundary,
            _read(directory / "checkpoints/initial.json"),
            _read(directory / "checkpoints/final.json"),
        )
        actual = {
            "requests": sum(item.get("accepted") is True for item in ledger),
            "tools": review.get("observed_tool_calls"),
            "recover": evidence["recover"],
            "commit": evidence["backup_committed"],
            "recheck": evidence["constraint_recheck"],
        }
        acceptance = assess_f5_acceptance(
            evidence,
            execution_status=_read(directory / "episode_result.json").get(
                "execution_status", "unknown"
            ),
            cleanup_status=review.get("cleanup_status", "unknown"),
            tool_trace_complete=review.get("tool_trace_complete") is True,
        )
        gate = f5_comparison_gate(acceptance)
        accepted = (
            actual == expected
            and review.get("status") == "completed"
            and review.get("cleanup_status") == "completed"
            and review.get("embedding_attempts") == 0
            and summary["cases"][case].get("fake_requests") == actual["requests"]
            and _read(directory / "episode_result.json").get("execution_status") == "completed"
            and (expected_cases is LEGACY_EXPECTED or gate["admitted"] == (case == "complete"))
        )
        rows.append(
            {
                "case": case,
                "original_summary_acceptance": summary["cases"][case].get("acceptance"),
                "actual": actual,
                "expected": expected,
                "recomputed_evidence": evidence,
                "aggregate": acceptance["aggregate"],
                "comparison_gate": gate,
                "accepted": accepted,
            }
        )
    resources_restored = summary.get("baseline_owned_resources") == summary.get(
        "final_owned_resources"
    )
    report = {
        "schema_version": "capability-f5-local-fake-revalidation/1.1",
        "source_run": source.name,
        "original_summary_sha256": file_hash(summary_path),
        "original_summary_unchanged": True,
        "provider_kind": summary.get("provider_kind"),
        "real_model_requests_reported": summary.get("real_model_requests"),
        "resources_restored": resources_restored,
        "rows": rows,
        "accepted": (
            resources_restored
            and summary.get("provider_kind") == "local_fake_http"
            and summary.get("real_model_requests") == 0
            and all(row["accepted"] for row in rows)
        ),
        "input_hashes": input_hashes,
        "processing_source_hashes": {
            path: file_hash(root / path)
            for path in (
                "scripts/capability/revalidate_f5_local_fake_runtime.py",
                "src/stac_attack_lab/capability/m3_f5.py",
                "src/stac_attack_lab/interactions/safeclaw_collection.py",
                "src/stac_attack_lab/environments/safeclaw/provider_relay.py",
                "integrations/safeclaw/construction_bridge.py",
            )
        },
    }
    write_private_json(output / "report.json", report)
    if not report["accepted"]:
        raise AssertionError("f5_fake_revalidation_failed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
