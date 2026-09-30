"""Read-only diagnosis for the closed generated Victim development batch."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from stac_attack_lab.hashing import file_hash


def _read(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError(f"invalid_json_object:{path}")
    return value


def _usage(records: list[dict[str, Any]]) -> dict[str, Any]:
    accepted = [r for r in records if r.get("accepted") is True]
    complete = [r for r in accepted if r.get("provider_usage_observation") == "complete"]
    values = [r.get("provider_usage") for r in complete if isinstance(r.get("provider_usage"), dict)]
    totals = [v.get("total_tokens") for v in values if isinstance(v.get("total_tokens"), int)]
    return {
        "accepted_requests": len(accepted),
        "complete_usage_records": len(complete),
        "missing_usage_records": len(accepted) - len(complete),
        "token_total": sum(totals) if len(totals) == len(accepted) else None,
        "status": "complete" if len(complete) == len(accepted) else "unknown",
        "evidence": "sealed relay provider_usage fields",
    }


def diagnose_case(batch: Path, review: Path, audit: Path) -> dict[str, Any]:
    evidence = _read(batch / "execution/runtime-evidence.json")
    observation = _read(batch / "execution/case/observation.json")
    result = _read(batch / "execution/case/result.json")
    manifest = _read(batch / "manifest.json")
    events = observation.get("events", [])
    source_events = [
        {
            "event_type": e.get("event_type"),
            "status": e.get("status"),
            "provider_boundary_refs": e.get("evidence", {}).get("provider_boundary_refs", []),
            "tool_result_id": e.get("evidence", {}).get("tool_result_id"),
        }
        for e in events
        if e.get("event_type") in {"source_result_delivered", "source_delivered", "provider_context_reachable"}
    ]
    writes: list[dict[str, Any]] = []
    for session in evidence.get("sessions", []):
        for entry in session.get("transcript_entries", []):
            for block in entry.get("message", {}).get("content", []):
                if isinstance(block, dict) and block.get("type") == "toolCall" and block.get("name") == "write":
                    args = block.get("arguments", {})
                    if isinstance(args, dict):
                        writes.append({"session_id": session.get("session_id"), "path": args.get("path")})
    sessions = [
        {
            "session_id": s.get("session_id"),
            "role": s.get("role"),
            "preconditions_satisfied": s.get("preconditions_satisfied"),
            "provider_attempts_before": s.get("provider_attempts_before"),
            "provider_attempts_after": s.get("provider_attempts_after"),
            "finish_reason": (s.get("raw_api_response") or {}).get("choices", [{}])[0].get("finish_reason"),
        }
        for s in evidence.get("sessions", [])
    ]
    terminal = _read(batch / "execution/terminal.json")
    return {
        "schema_version": "attack-r4-real-evidence-diagnosis/2",
        "source_batch": str(batch),
        "source_manifest_hash": manifest.get("manifest_hash"),
        "source_case_manifest_hash": _read(batch / "execution/case/manifest.json").get("manifest_hash"),
        "source_review_sha256": file_hash(review),
        "source_audit_sha256": file_hash(audit),
        "historical_records_unchanged": True,
        "source_evidence": {
            "events": source_events,
            "source_delivery": "observed" if any(e["event_type"] == "source_delivered" and e["status"] == "observed" for e in source_events) else "unknown",
            "provider_context_reachable": "observed" if any(e["event_type"] == "provider_context_reachable" and e["status"] == "observed" for e in source_events) else "unknown",
            "interpretation": "tool-result events exist but no complete provider boundary reference; delivery/context reachability remain unknown",
        },
        "write_scope": {
            "declared_candidate_surface": "/environment/workspace_files/4/content",
            "runtime_allowed_scope": "memory state plus explicitly versioned memory/*.md snapshots",
            "observed_tool_writes": writes,
            "verifiable_file_versions": [
                {"session_id": s.get("session_id"), "before": s.get("file_versions_before", {}), "after": s.get("file_versions_after", {})}
                for s in evidence.get("sessions", [])
            ],
            "verdict": result.get("independent", {}).get("constraint_checks", {}).get("write_scope", "unknown"),
            "reason": "historical result retains the verifier's scope verdict; no write path or version is rewritten",
        },
        "provider_usage": _usage(evidence.get("relay_records", [])),
        "execution_completeness": {
            "terminal": terminal.get("status"),
            "victim_http_attempts": terminal.get("victim_http_attempts"),
            "victim_cap": manifest.get("max_http_attempts", {}).get("victim"),
            "all_finish_reasons": sessions,
            "budget_rejections": [r for r in evidence.get("relay_records", []) if r.get("error_category") == "provider_request_budget_exhausted"],
            "interpretation": "HTTP completion and finish_reason=stop are observed; natural task completion and sufficient evidence are not established by request count alone",
        },
        "official_result_unchanged": result.get("official"),
        "independent_result_unchanged": result.get("independent"),
    }


def diagnose_batch(batch_root: Path, review_root: Path, audit_root: Path, output: Path) -> dict[str, Any]:
    cases = []
    for slot in ("slot-001", "slot-002", "slot-003"):
        case = diagnose_case(batch_root / "victim-disabled" / slot, review_root / slot / "review/review.json", audit_root / slot / "audit/audit.json")
        cases.append(case)
    summary = {
        "schema_version": "attack-r4-real-evidence-diagnosis-summary/1",
        "source_batch": str(batch_root),
        "historical_records_unchanged": True,
        "cases": cases,
        "counts": {"cases": len(cases), "victim_http_attempts": sum(c["execution_completeness"]["victim_http_attempts"] for c in cases)},
        "conclusion": "The closed batch remains three scope-limited development observations; no success-rate, generalization, or causal claim is added.",
    }
    output.mkdir(parents=True, exist_ok=False)
    (output / "summary.json").write_text(json.dumps(summary, ensure_ascii=False, sort_keys=True, indent=2) + "\n", encoding="utf-8")
    for case in cases:
        slot = Path(case["source_batch"]).name
        (output / f"{slot}.json").write_text(json.dumps(case, ensure_ascii=False, sort_keys=True, indent=2) + "\n", encoding="utf-8")
    return summary
