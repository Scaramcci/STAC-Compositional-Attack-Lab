from __future__ import annotations

import json
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
        run_id = "construction-cross-session-" + datetime.datetime.now(datetime.UTC).strftime("%Y%m%d-%H%M%S") + "-" + uuid.uuid4().hex[:8]
    if Path(run_id).name != run_id or not run_id:
        raise ValueError("invalid_revalidation_run_id")
    run_root = root / "experiments" / "runs" / run_id
    run_root.mkdir(parents=True, exist_ok=False)
    config = json.loads(template.read_text(encoding="utf-8"))
    config["pipeline_id"] = run_id
    config["output_root"] = str(run_root)
    config["execution_enabled"] = False
    (run_root / "runtime_config.json").write_text(json.dumps(config, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    provenance = {
        "run_id": run_id,
        "head": _git(root, "rev-parse", "HEAD"),
        "dirty": bool(_git(root, "status", "--porcelain")),
        "config_sha256": file_hash(run_root / "runtime_config.json"),
        "template_sha256": file_hash(template),
        "source_tree_sha256": stable_hash({str(p.relative_to(root)): file_hash(p) for p in sorted((root / "src").rglob("*.py"))}),
        "command": "stac-attack-lab revalidation prepare",
        "execution_enabled": False,
    }
    (run_root / "provenance.json").write_text(json.dumps(provenance, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    (run_root / "configuration_review.json").write_text(json.dumps({"run_id": run_id, "execution_status": "disabled", "live_authorization": "not_granted", "checks": {"execution_enabled": False}}, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return run_root


def offline_revalidation(root: Path, run_root: Path, collection: Path | None = None, library: Path | None = None) -> dict[str, Any]:
    """Run only local mine/audit/admission stages and preserve stage outcomes."""
    result: dict[str, Any] = {"execution_status": "not_executed", "accepted": None, "admission": "not_run", "runtime_review": "pending", "official_outcome": "not_evaluated", "stages": []}
    if collection is None:
        candidates = sorted(run_root.glob("single-construction/interactions/raw/*"))
        collection = candidates[0] if candidates else None
    if collection is None or not collection.exists():
        result["stages"].append({"stage": "mine", "status": "blocked", "reason_code": "collection_missing"})
        (run_root / "offline_summary.json").write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        return result
    from stac_attack_lab.execution.sample_generation import mine_sample_collection, audit_sample_library_stage
    mining_root = run_root / "offline-mining"
    try:
        library_path = Path(mine_sample_collection(root, collection, output_root=mining_root))
        result["stages"].append({"stage": "mine", "status": "passed", "output": str(library_path)})
    except Exception as exc:  # diagnostics must survive partial/corrupt ledgers
        result["stages"].append({"stage": "mine", "status": "failed", "reason": str(exc)[:500]})
        library_path = library
    if library_path is not None and library_path.exists():
        try:
            audit = audit_sample_library_stage(library_path)
            result["stages"].append({"stage": "audit", "status": "passed" if audit.passed else "failed", "errors": audit.error_codes})
            result["accepted"] = audit.passed
        except Exception as exc:
            result["stages"].append({"stage": "audit", "status": "failed", "reason": str(exc)[:500]})
        try:
            from stac_attack_lab.execution.construction_admission import audit_construction_collection
            report = audit_construction_collection(collection, library_path)
            result["admission"] = "passed" if report.get("pilot_admitted") else "failed"
            result["admission_report"] = report
            result["stages"].append({"stage": "admission", "status": result["admission"]})
        except Exception as exc:
            result["stages"].append({"stage": "admission", "status": "failed", "reason": str(exc)[:500]})
    (run_root / "offline_summary.json").write_text(json.dumps(result, indent=2, sort_keys=True, default=str) + "\n", encoding="utf-8")
    return result
