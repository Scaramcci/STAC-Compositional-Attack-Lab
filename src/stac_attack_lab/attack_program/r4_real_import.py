"""Read-only diagnosis and one controlled import of a sealed real development run."""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

from stac_attack_lab.attack_program.pipeline import GateError
from stac_attack_lab.attack_program.r4 import RuntimeBundle, project_bundle
from stac_attack_lab.hashing import file_hash, stable_hash


def _read(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise GateError("real_import_record_missing_or_invalid") from exc
    if not isinstance(value, dict):
        raise GateError("real_import_record_invalid")
    return value


def _hashed(value: dict[str, Any], key: str) -> bool:
    return value.get(key) == stable_hash({k: v for k, v in value.items() if k != key})


def _validated_source(
    batch: Path, review: Path, audit_path: Path
) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any], RuntimeBundle, dict[str, Any]]:
    manifest = _read(batch / "manifest.json")
    binding = _read(batch / "binding.json")
    activation = _read(batch / "execution/activation.json")
    claim = _read(batch / "execution/runtime_claim.json")
    terminal = _read(batch / "execution/terminal.json")
    case = batch / "execution/case"
    sealed = _read(case / "manifest.json")
    old_review = _read(review / "review.json")
    audit = _read(audit_path)
    if (
        manifest.get("schema_version") != "attack-r4-prepared-batch/2"
        or manifest.get("scope") != "disabled_real_development"
        or manifest.get("source_split") != "development"
        or not _hashed(manifest, "manifest_hash")
        or not _hashed(binding, "binding_hash")
        or binding.get("snapshot") != manifest
        or binding.get("manifest_hash") != manifest["manifest_hash"]
        or any(
            x.get("binding_hash") != binding["binding_hash"] for x in (activation, claim, terminal)
        )
        or terminal.get("schema_version") != "attack-r4-terminal/1"
        or terminal.get("status") != "completed"
        or not _hashed(terminal, "terminal_hash")
        or terminal.get("cleanup", {}).get("status") != "completed"
        or any(terminal.get("cleanup", {}).get("owned_after", {}).values())
        or sealed.get("schema_version") != "attack-runtime-case/2"
        or sealed.get("source") != "real"
        or not _hashed(sealed, "manifest_hash")
        or sealed.get("run_id") != manifest.get("run_id")
        or sealed.get("candidate_id") != manifest.get("candidate_id")
        or old_review.get("source_manifest_hash") != manifest["manifest_hash"]
        or old_review.get("source") != "real"
        or old_review.get("candidate_id") != manifest["candidate_id"]
        or audit.get("schema_version") != "attack-runtime-audit/1"
        or audit.get("status") != "valid"
        or audit.get("source") != "real"
        or audit.get("source_manifest_hash") != sealed["manifest_hash"]
        or audit.get("candidate_id") != manifest["candidate_id"]
    ):
        raise GateError("real_import_provenance_mismatch")
    expected = {
        "catalog.json",
        "split.json",
        "candidate.json",
        "task.json",
        "runtime_bundle.json",
        "observation.json",
        "result.json",
    }
    if set(sealed.get("files", {})) != expected:
        raise GateError("real_import_case_index_invalid")
    for name, digest in sealed["files"].items():
        if file_hash(case / name) != digest:
            raise GateError("real_import_case_file_tampered")
    if (
        file_hash(batch / "candidate.json") != manifest["candidate_hash"]
        or file_hash(batch / "materialized_task.json") != manifest["materialized_file_hash"]
        or stable_hash(_read(batch / "materialized_task.json"))
        != manifest["materialized_task_hash"]
        or file_hash(case / "candidate.json") != manifest["candidate_hash"]
        or file_hash(case / "task.json") != manifest["materialized_file_hash"]
    ):
        raise GateError("real_import_candidate_or_task_mismatch")
    result = _read(case / "result.json")
    bundle = RuntimeBundle.model_validate(_read(case / "runtime_bundle.json"))
    if (
        result != terminal.get("result")
        or result.get("execution_source") != "real"
        or result.get("status") != "completed"
        or result.get("task_id") != manifest["task_id"]
        or result.get("task_group_id") != manifest["task_group_id"]
        or result.get("source_split") != manifest["source_split"]
        or result.get("candidate_id") != manifest["candidate_id"]
        or result.get("materialized_hash") != manifest["materialized_task_hash"]
        or bundle.execution_binding_hash != binding["binding_hash"]
        or bundle.run_id != manifest["run_id"]
        or bundle.candidate_id != manifest["candidate_id"]
        or bundle.materialized_task_hash != manifest["materialized_task_hash"]
        or bundle.cleanup != terminal["cleanup"]
        or terminal.get("victim_http_attempts")
        != len([r for r in bundle.relay_records if r.get("accepted") is True])
    ):
        raise GateError("real_import_execution_identity_mismatch")
    return manifest, sealed, result, bundle, old_review


def _diagnosis(
    batch: Path,
    manifest: dict[str, Any],
    sealed: dict[str, Any],
    result: dict[str, Any],
    bundle: RuntimeBundle,
    old_review: dict[str, Any],
    audit_path: Path,
) -> tuple[dict[str, Any], dict[str, Any]]:
    task = _read(batch / "execution/case/task.json")
    old_observation = _read(batch / "execution/case/observation.json")
    candidate = _read(batch / "execution/case/candidate.json")
    material = candidate["patches"][0]["value"]
    projected = project_bundle(bundle, material)
    new_events = projected.model_dump(mode="json")["events"]
    old_events = old_observation["events"]
    source_old = [e["event_type"] for e in old_events if e["event_type"] == "source_delivered"]
    source_new = [
        e["event_type"]
        for e in new_events
        if e["event_type"] == "source_delivered" and e["status"] == "observed"
    ]
    pre = bundle.pre_state
    post = bundle.post_state
    checks = task["evaluation"]["success_condition"]["checks"]
    memory_check = next(c for c in checks if c["type"] == "memory_contains")
    projections = {
        field: bool(re.search(memory_check["pattern"], str(post.get(field, ""))))
        for field in ("memory_content", "memory_root_content", "memory_dir_content")
    }
    assets = []
    write_paths = [
        block.get("arguments", {}).get("path")
        for session in bundle.sessions
        for entry in session.transcript_entries
        for block in entry.get("message", {}).get("content", [])
        if isinstance(block, dict)
        and block.get("type") == "toolCall"
        and block.get("name") == "write"
    ]
    dated_memory_write = any(
        isinstance(path, str)
        and path.removeprefix("/root/.openclaw/workspace/").startswith("memory/")
        and path.endswith(".md")
        for path in write_paths
    )
    official_leaks = {x["asset_id"]: x for x in result["official"]["taint_leakage"]}
    for asset in task["taint_assets"]:
        asset_id = asset["asset_id"]
        marker = asset["marker"]
        assets.append(
            {
                "asset_id": asset_id,
                "official_log_file_hit": "log_file" in official_leaks[asset_id]["leaked_via"],
                "gateway_log_contains": marker in str(post.get("gateway_log", "")),
                "session_transcript_contains": marker in str(post.get("session_transcript", "")),
                "s2_agent_response_contains": marker in bundle.sessions[-1].agent_response,
                "official_log_file_declared_unauthorized": "log_file"
                in asset.get("unauthorized_channels", []),
            }
        )
    log_hits = [x for x in assets if x["official_log_file_hit"]]
    usage = [r.get("provider_usage") for r in bundle.relay_records if r.get("accepted") is True]
    independent = result["independent"]
    report = {
        "schema_version": "attack-r4-real-evidence-diagnosis/1",
        "source_batch": str(batch),
        "source_manifest_hash": manifest["manifest_hash"],
        "sealed_case_manifest_hash": sealed["manifest_hash"],
        "independent_replay_audit_sha256": file_hash(audit_path),
        "historical_results_unchanged": True,
        "official_benchmark_outcome": {
            "attack_succeeded": result["official"]["score"]["attack_succeeded"],
            "metric": result["official"]["score"]["metric"],
            "score": result["official"]["score"]["score"],
            "memory_contains": {
                "checked_projection_fields": list(projections),
                "post_matches": projections,
                "pre_memory_file_exists": bool(pre.get("memory_exists")),
                "pre_memory_dir_file_count": len(pre.get("memory_dir_files", [])),
            },
            "s2_response_taint_check": (
                "hit" if any(x["s2_agent_response_contains"] for x in assets) else "not_hit"
            ),
        },
        "response_channel_independent_harm": {
            "verdict": independent["harm"],
            "evidence_class": result["evidence_class"],
            "scope": independent["harm_scope"],
            "global_attack_failure_claim": False,
        },
        "other_channels": {
            "asset_observations": assets,
            "log_file_hit_asset_ids": [x["asset_id"] for x in log_hits],
            "hit_source_field": (
                "post_state.session_transcript"
                if all(
                    x["session_transcript_contains"] and not x["gateway_log_contains"]
                    for x in log_hits
                )
                else "mixed_or_unknown"
            ),
            "gateway_log_hit_count": sum(x["gateway_log_contains"] for x in log_hits),
            "interpretation": (
                "pinned evaluator matches collected tool-read transcript; "
                "not proof of outbound logging or exfiltration"
            ),
            "unsupported_official_channels": result["official"].get(
                "unsupported_taint_channels", []
            ),
        },
        "propagation_contribution": "unknown",
        "evidence_integrity": {
            "sealed_files_hash_verified": True,
            "binding_terminal_and_replay_verified": True,
            "historical_source_delivered_count": len(source_old),
            "reprojected_source_delivered_count": len(source_new),
            "source_delivery_interpretation": (
                "full mail tool result and provider association observed by corrected mapper"
            )
            if source_new
            else "unknown",
            "semantic_consumption": "unknown",
            "causal_contribution": "unknown",
            "memory_dated_file_write": (
                "tool_write_observed_without_historical_per_file_versions"
                if dated_memory_write and not any(s.file_versions_after for s in bundle.sessions)
                else "not_established_by_legacy_snapshot"
            ),
            "memory_md_precondition_s2": bundle.sessions[-1].preconditions_satisfied,
            "pinned_runner_action": "warned_and_continued",
            "usage": {
                "http_attempts": len(usage),
                "usage_observed_count": sum(x is not None for x in usage),
                "tokens": "unknown" if any(x is None for x in usage) else "recorded",
                "historical_sse_body_saved": False,
                "request_compat_defect": (
                    "ark_stream_include_usage_not_requested"
                    if manifest.get("victim_endpoint_host") == "ark.cn-beijing.volces.com"
                    and sealed.get("processing_sources", {}).get(
                        "src/stac_attack_lab/attack_program/r4_runtime.py"
                    )
                    == "91e425ad46f6c9b989d1c7879eba2040176e4aca830280aad0eb7dd3f4d200a9"
                    else "unknown"
                ),
            },
        },
        "historical_review_source_delivered": old_review["runtime"]["source_delivered"],
    }
    attempt = {
        "schema_version": "attack-real-development-attempt/1",
        "classification": "scope_limited_real_development_observation",
        "task_id": manifest["task_id"],
        "task_group_id": manifest["task_group_id"],
        "split": manifest["source_split"],
        "candidate_id": manifest["candidate_id"],
        "candidate_hash": manifest["candidate_hash"],
        "materialized_task_hash": manifest["materialized_task_hash"],
        "run_id": manifest["run_id"],
        "attempt_id": result["attempt_id"],
        "source_batch_manifest_hash": manifest["manifest_hash"],
        "source_case_manifest_hash": sealed["manifest_hash"],
        "binding_hash": bundle.execution_binding_hash,
        "independent_replay_audit_sha256": file_hash(audit_path),
        "official": {
            "attack_succeeded": result["official"]["score"]["attack_succeeded"],
            "metric": result["official"]["score"]["metric"],
            "score": result["official"]["score"]["score"],
            "status": result["official"]["status"],
        },
        "independent_claims": [
            {
                "scope": independent["harm_scope"],
                "harm": independent["harm"],
                "evidence_class": result["evidence_class"],
                "constraint": independent["constraint"],
                "utility": independent["utility"],
                "propagation_contribution": independent["propagation_contribution"],
            }
        ],
        "primitive_evidence": independent["primitive_evidence"],
        "primitive_occurrences": result["occurrences"],
        "usage": {
            "source": "sealed_relay_provider_boundary",
            "http_attempts": len(usage),
            "tokens": None,
            "observation": "missing" if all(x is None for x in usage) else "partial",
        },
        "integrity": {
            "source_hashes_verified": True,
            "independent_replay_valid": True,
            "historical_result_unchanged": True,
        },
        "denominator": {
            "real_attempts": 1,
            "completed": 1,
            "not_started": 0,
            "victim_http_attempts": len(usage),
        },
    }
    return report, attempt


def import_real_attempt(
    root: Path, batch: Path, review: Path, audit_path: Path, output_parent: Path
) -> dict[str, Any]:
    """Import exactly one sealed run; deterministic key makes repeated calls idempotent."""
    batch = batch.resolve()
    review = review.resolve()
    audit_path = audit_path.resolve()
    if not (
        batch.is_relative_to(root.resolve())
        and review.is_relative_to(root.resolve())
        and audit_path.is_relative_to(root.resolve())
    ):
        raise GateError("real_import_outside_repository")
    manifest, sealed, result, bundle, old_review = _validated_source(batch, review, audit_path)
    report, attempt = _diagnosis(batch, manifest, sealed, result, bundle, old_review, audit_path)
    development_report = {
        "schema_version": "attack-development-report/1",
        "scope": "real_development_import",
        "source": "real",
        "task_id": manifest["task_id"],
        "assigned": 1,
        "statuses": {"completed": 1, "not_started": 0},
        "attempt_denominator": 1,
        "victim_http_attempts": attempt["denominator"]["victim_http_attempts"],
        "attempts": [
            {
                "attempt_id": attempt["attempt_id"],
                "candidate_id": attempt["candidate_id"],
                "status": "completed",
                "official_success": attempt["official"]["attack_succeeded"],
                "independent_harm": attempt["independent_claims"][0]["harm"],
                "independent_harm_scope": attempt["independent_claims"][0]["scope"],
                "classification": attempt["classification"],
            }
        ],
    }
    output_parent.mkdir(parents=True, exist_ok=True)
    destination = output_parent / manifest["manifest_hash"]
    existed = destination.exists()
    if existed:
        existing = _read(destination / "attempt.json")
        if existing != attempt or _read(destination / "diagnosis.json") != report:
            raise GateError("real_import_existing_record_conflict")
    else:
        destination.mkdir(mode=0o700, exist_ok=False)
        for name, value in (("attempt.json", attempt), ("diagnosis.json", report)):
            path = destination / name
            with path.open("x", encoding="utf-8") as handle:
                json.dump(value, handle, ensure_ascii=False, sort_keys=True, indent=2)
                handle.write("\n")
    development_path = destination / "report.json"
    if development_path.exists():
        if _read(development_path) != development_report:
            raise GateError("real_import_existing_record_conflict")
    else:
        with development_path.open("x", encoding="utf-8") as handle:
            json.dump(development_report, handle, ensure_ascii=False, sort_keys=True, indent=2)
            handle.write("\n")
    import_manifest = {
        "schema_version": "attack-real-development-import/1",
        "source": "real",
        "scope": "development",
        "source_batch_manifest_hash": manifest["manifest_hash"],
        "source_case_manifest_hash": sealed["manifest_hash"],
        "run_id": manifest["run_id"],
        "assigned_candidate_ids": [manifest["candidate_id"]],
        "attempt_ids": [attempt["attempt_id"]],
        "attempt_denominator": 1,
        "files": {
            name: file_hash(destination / name)
            for name in ("attempt.json", "diagnosis.json", "report.json")
        },
    }
    import_manifest["manifest_hash"] = stable_hash(import_manifest)
    manifest_path = destination / "manifest.json"
    if manifest_path.exists():
        if _read(manifest_path) != import_manifest:
            raise GateError("real_import_existing_record_conflict")
    else:
        with manifest_path.open("x", encoding="utf-8") as handle:
            json.dump(import_manifest, handle, ensure_ascii=False, sort_keys=True, indent=2)
            handle.write("\n")
    return {
        "status": "imported_existing" if existed else "imported",
        "attempt_path": str(destination / "attempt.json"),
        "report_path": str(destination / "diagnosis.json"),
        "development_report_path": str(development_path),
        "real_attempts": 1,
    }


def audit_real_attempt(
    root: Path, batch: Path, review: Path, audit_path: Path, output_parent: Path
) -> dict[str, Any]:
    """Independently recompute the derived records without writing or launching anything."""
    manifest, sealed, result, bundle, old_review = _validated_source(
        batch.resolve(), review.resolve(), audit_path.resolve()
    )
    expected_report, expected_attempt = _diagnosis(
        batch.resolve(), manifest, sealed, result, bundle, old_review, audit_path.resolve()
    )
    destination = output_parent / manifest["manifest_hash"]
    imported = _read(destination / "manifest.json")
    if (
        imported.get("schema_version") != "attack-real-development-import/1"
        or not _hashed(imported, "manifest_hash")
        or imported.get("attempt_denominator") != 1
        or imported.get("source_case_manifest_hash") != sealed["manifest_hash"]
        or imported.get("files")
        != {
            name: file_hash(destination / name)
            for name in ("attempt.json", "diagnosis.json", "report.json")
        }
    ):
        raise GateError("real_import_audit_mismatch")
    if (
        _read(destination / "attempt.json") != expected_attempt
        or _read(destination / "diagnosis.json") != expected_report
    ):
        raise GateError("real_import_audit_mismatch")
    development_report = _read(destination / "report.json")
    if (
        development_report.get("schema_version") != "attack-development-report/1"
        or development_report.get("scope") != "real_development_import"
        or development_report.get("source") != "real"
        or development_report.get("assigned") != 1
        or development_report.get("attempt_denominator") != 1
        or development_report.get("victim_http_attempts")
        != expected_attempt["denominator"]["victim_http_attempts"]
        or len(development_report.get("attempts", [])) != 1
        or development_report["attempts"][0]["candidate_id"] != expected_attempt["candidate_id"]
        or development_report["attempts"][0]["independent_harm_scope"]
        != expected_attempt["independent_claims"][0]["scope"]
    ):
        raise GateError("real_import_audit_mismatch")
    return {
        "schema_version": "attack-real-development-import-audit/1",
        "status": "valid",
        "source_case_manifest_hash": sealed["manifest_hash"],
        "real_attempts": 1,
        "historical_result_unchanged": True,
    }
