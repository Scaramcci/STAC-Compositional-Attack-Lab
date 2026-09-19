from __future__ import annotations

import json
import os
import subprocess
from pathlib import Path
from typing import Any

from stac_attack_lab.hashing import file_hash, stable_hash


def _git(root: Path, *args: str) -> str:
    try:
        return subprocess.check_output(["git", *args], cwd=root, text=True).strip()
    except (OSError, subprocess.CalledProcessError):
        return "unknown"


def prepare_revalidation(root: Path, template: Path, run_id: str | None = None) -> Path:
    """Create a fresh disabled run directory without reading historical runs."""
    if run_id is None:
        import datetime
        import uuid

        run_id = (
            "construction-cross-session-"
            + datetime.datetime.now(datetime.UTC).strftime("%Y%m%d-%H%M%S")
            + "-"
            + uuid.uuid4().hex[:8]
        )
    if Path(run_id).name != run_id or not run_id:
        raise ValueError("invalid_revalidation_run_id")
    run_root = root / "experiments" / "runs" / run_id
    run_root.mkdir(parents=True, exist_ok=False)
    config = json.loads(template.read_text(encoding="utf-8"))
    config["pipeline_id"] = run_id
    config["output_root"] = str(run_root)
    config["execution_enabled"] = False
    (run_root / "runtime_config.json").write_text(
        json.dumps(config, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    provenance = {
        "run_id": run_id,
        "head": _git(root, "rev-parse", "HEAD"),
        "dirty": bool(_git(root, "status", "--porcelain")),
        "config_sha256": file_hash(run_root / "runtime_config.json"),
        "template_sha256": file_hash(template),
        "controlled_source_sha256": stable_hash(
            {
                str(p.relative_to(root)): file_hash(p)
                for base in (root / "src", root / "integrations" / "safeclaw", root / "scripts")
                for p in sorted(base.rglob("*"))
                if p.is_file() and (p.suffix in {".py", ".sh"} or p.name == "README.md")
            }
        ),
        "command": "stac-attack-lab revalidation prepare",
        "execution_enabled": False,
    }
    (run_root / "provenance.json").write_text(
        json.dumps(provenance, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    (run_root / "configuration_review.json").write_text(
        json.dumps(
            {
                "run_id": run_id,
                "execution_status": "disabled",
                "live_authorization": "not_granted",
                "checks": {"execution_enabled": False},
            },
            indent=2,
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )
    return run_root


def launch_live_revalidation(root: Path, run_root: Path, *, authorized: bool) -> dict[str, Any]:
    """Launch exactly once inside one prepared run after explicit authorization."""
    if not authorized:
        raise ValueError("live_authorization_flag_required")
    config_path = run_root / "runtime_config.json"
    config_data = json.loads(config_path.read_text(encoding="utf-8"))
    if config_data.get("execution_enabled") is not True:
        raise ValueError("live_execution_disabled_in_runtime_config")
    live_review = {
        "run_id": run_root.name,
        "execution_status": "authorized_pending_launch",
        "live_authorization": "explicit_command_flag",
        "checks": {"execution_enabled": True, "run_root_unique": True},
        "config_sha256": file_hash(config_path),
        "head": _git(root, "rev-parse", "HEAD"),
        "dirty": bool(_git(root, "status", "--porcelain")),
    }
    (run_root / "configuration_review.live.json").write_text(
        json.dumps(live_review, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    marker = run_root / "launch.marker"
    descriptor = os.open(marker, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        os.write(descriptor, b"live launch reserved\n")
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    from stac_attack_lab.execution.sample_generation import (
        collect_sample_interactions,
        load_sample_generation_config,
    )
    from stac_attack_lab.execution.sample_preflight import run_sample_collection_preflight

    config = load_sample_generation_config(config_path)
    summary: dict[str, Any]
    try:
        preflight = run_sample_collection_preflight(root, config)
        if not preflight.passed:
            raise RuntimeError("revalidation_live_preflight_failed")
        collection = collect_sample_interactions(root, config)
        offline = offline_revalidation(root, run_root, Path(collection))
    except Exception as exc:
        summary = {
            "execution_status": "failed",
            "reason": str(exc)[:500],
            "launch_marker": str(marker),
            "official_outcome": "not_evaluated",
        }
        (run_root / "live_summary.json").write_text(
            json.dumps(summary, indent=2, sort_keys=True) + "\n", encoding="utf-8"
        )
        raise
    summary = {
        "execution_status": (
            "completed" if offline.get("overall_status") == "passed" else "completed_offline_failed"
        ),
        "collection": str(collection),
        "launch_marker": str(marker),
        "offline_status": offline.get("overall_status"),
        "offline_summary": str(run_root / "offline_summary.json"),
        "official_outcome": "not_evaluated",
    }
    (run_root / "live_summary.json").write_text(
        json.dumps(summary, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    return summary


def offline_revalidation(
    root: Path,
    run_root: Path,
    collection: Path | None = None,
    library: Path | None = None,
    bridge_responses: Path | None = None,
) -> dict[str, Any]:
    """Run only local mine/audit/admission stages and preserve stage outcomes."""
    result: dict[str, Any] = {
        "execution_status": "not_executed",
        "accepted": {"count": None, "audit_passed": None},
        "admission": "not_run",
        "runtime_review": "pending",
        "official_outcome": "not_evaluated",
        "stages": [],
    }
    if collection is None:
        candidates = sorted(run_root.glob("single-construction/interactions/raw/*"))
        collection = candidates[0] if candidates else None
    if collection is None or not collection.exists():
        result["stages"].append(
            {"stage": "mine", "status": "blocked", "reason_code": "collection_missing"}
        )
        result["overall_status"] = "failed"
        (run_root / "offline_summary.json").write_text(
            json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8"
        )
        return result
    input_hashes = {
        str(path.relative_to(root)): file_hash(path)
        for path in sorted(collection.rglob("*"))
        if path.is_file()
    }
    bridge_diagnostic: dict[str, Any] | None = None
    if bridge_responses is not None:
        input_hashes[str(bridge_responses.relative_to(root))] = file_hash(bridge_responses)
        tool_counts: dict[str, int] = {}
        observations = 0
        ordered_observations = 0
        for line in bridge_responses.read_text(encoding="utf-8").splitlines():
            try:
                record = json.loads(line)
            except json.JSONDecodeError:
                continue
            response = record.get("response", record) if isinstance(record, dict) else {}
            session = response.get("session", {}) if isinstance(response, dict) else {}
            for item in session.get("tool_observations", []):
                if not isinstance(item, dict):
                    continue
                observations += 1
                name = str(item.get("tool_name") or "unknown")
                tool_counts[name] = tool_counts.get(name, 0) + 1
                if (
                    item.get("request_line_number") is not None
                    and item.get("result_line_number") is not None
                ):
                    ordered_observations += 1
        bridge_diagnostic = {
            "input_sha256": file_hash(bridge_responses),
            "tool_observation_count": observations,
            "tool_counts": tool_counts,
            "ordered_observation_count": ordered_observations,
            "replay_outcome": (
                "ordering_available"
                if observations and ordered_observations == observations
                else "insufficient_for_causal_reconstruction"
            ),
            "missing": (
                []
                if observations and ordered_observations == observations
                else [
                    "request_line_number/result_line_number on historical tool observations",
                    "explicit file version lineage",
                    "explicit downstream use evidence",
                ]
            ),
        }
        (run_root / "bridge_replay_diagnostics.json").write_text(
            json.dumps(bridge_diagnostic, indent=2, sort_keys=True) + "\n", encoding="utf-8"
        )
    offline_provenance = {
        "command": "stac-attack-lab revalidation offline",
        "head": _git(root, "rev-parse", "HEAD"),
        "dirty": bool(_git(root, "status", "--porcelain")),
        "input_sha256": input_hashes,
        "processing_source_sha256": stable_hash(
            {
                str(path.relative_to(root)): file_hash(path)
                for path in sorted((root / "src" / "stac_attack_lab").rglob("*.py"))
            }
        ),
        "bridge_diagnostic": bridge_diagnostic,
    }
    (run_root / "offline_provenance.json").write_text(
        json.dumps(offline_provenance, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    from stac_attack_lab.execution.sample_generation import (
        audit_sample_library_stage,
        mine_sample_collection,
    )

    mining_root = run_root / "offline-mining"
    library_path: Path | None
    try:
        library_path = Path(mine_sample_collection(root, collection, output_root=mining_root))
        result["stages"].append({"stage": "mine", "status": "passed", "output": str(library_path)})
    except Exception as exc:  # diagnostics must survive partial/corrupt ledgers
        result["stages"].append({"stage": "mine", "status": "failed", "reason": str(exc)[:500]})
        library_path = library
    if library_path is not None and library_path.exists():
        try:
            audit = audit_sample_library_stage(library_path)
            result["stages"].append(
                {
                    "stage": "audit",
                    "status": "passed" if audit.passed else "failed",
                    "errors": audit.error_codes,
                }
            )
            mining_manifest = json.loads(
                (library_path.parent / "mining_stage_manifest.json").read_text(encoding="utf-8")
            )
            result["accepted"] = {
                "count": mining_manifest.get("accepted_count"),
                "audit_passed": audit.passed,
            }
        except Exception as exc:
            result["stages"].append(
                {"stage": "audit", "status": "failed", "reason": str(exc)[:500]}
            )
        try:
            from stac_attack_lab.execution.construction_admission import (
                audit_construction_collection,
            )

            report = audit_construction_collection(collection, library_path)
            result["admission"] = "passed" if report.get("pilot_admitted") else "failed"
            result["admission_report"] = report
            result["stages"].append({"stage": "admission", "status": result["admission"]})
        except Exception as exc:
            result["stages"].append(
                {"stage": "admission", "status": "failed", "reason": str(exc)[:500]}
            )
    result["overall_status"] = (
        "passed"
        if result["stages"] and all(stage.get("status") == "passed" for stage in result["stages"])
        else "failed"
    )
    (run_root / "offline_summary.json").write_text(
        json.dumps(result, indent=2, sort_keys=True, default=str) + "\n", encoding="utf-8"
    )
    return result
