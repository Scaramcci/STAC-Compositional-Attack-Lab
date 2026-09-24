"""Frozen three-group F5 observation plan over independent existing F5 batches."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, cast

from stac_attack_lab.capability.evidence import write_private_json
from stac_attack_lab.capability.m3_f5 import (
    CONDITIONS,
    F5Config,
    prepare_m3_f5,
    recompute_f5_episode,
    status_m3_f5,
    validate_m3_f5,
)
from stac_attack_lab.hashing import file_hash, stable_hash

GROUPS = ("r01", "r02", "r03")


def _load(path: Path) -> dict[str, Any]:
    return cast(dict[str, Any], json.loads(path.read_text(encoding="utf-8")))


def prepare_f5_repeats(project_root: Path, config_path: Path, output: Path) -> Path:
    if output.exists():
        raise FileExistsError("f5_repeat_plan_exists")
    config = F5Config.model_validate_json(config_path.read_text(encoding="utf-8"))
    if config.observation_profile != "prospective_exploratory/1.0":
        raise ValueError("f5_repeat_profile_required")
    output.mkdir(parents=True, mode=0o700)
    groups = []
    for group in GROUPS:
        config_file = output / f"config-{group}.json"
        write_private_json(
            config_file, {**config.model_dump(mode="json"), "repeat_group_id": group}
        )
        run = output / group
        prepare_m3_f5(project_root, config_file, run)
        manifest = validate_m3_f5(project_root, run)
        groups.append(
            {
                "group_id": group,
                "run_ref": group,
                "manifest_hash": manifest["manifest_hash"],
                "config_sha256": file_hash(config_file),
                "units": [f"{group}-{condition}" for condition in CONDITIONS],
            }
        )
    plan = {
        "schema_version": "capability-m3b-f5-repeat-plan/1.0",
        "profile": config.observation_profile,
        "order": list(CONDITIONS),
        "split_group_id": _load(project_root / config.source_path)["split_group_id"],
        "groups": groups,
        "denominator": 9,
        "planned_victim_http_ceiling": 90,
        "authorization_status": "absent",
        "model_generation_seed": "uncontrolled",
        "order_seed": "not_used_fixed_order",
    }
    plan["plan_hash"] = stable_hash(plan)
    write_private_json(output / "plan.json", plan)
    return output / "plan.json"


def validate_f5_repeats(project_root: Path, root: Path) -> dict[str, Any]:
    plan = _load(root / "plan.json")
    if (
        plan.get("schema_version") != "capability-m3b-f5-repeat-plan/1.0"
        or plan.get("plan_hash")
        != stable_hash({key: value for key, value in plan.items() if key != "plan_hash"})
        or plan.get("profile") != "prospective_exploratory/1.0"
        or plan.get("order") != list(CONDITIONS)
        or plan.get("denominator") != 9
        or plan.get("planned_victim_http_ceiling") != 90
        or [group.get("group_id") for group in plan.get("groups", [])] != list(GROUPS)
    ):
        raise ValueError("f5_repeat_plan_invalid")
    identities: set[str] = set()
    common_task: str | None = None
    common_materialized: str | None = None
    source_hash: str | None = None
    contract_hash: str | None = None
    for group in plan["groups"]:
        group_id = group["group_id"]
        if group.get("run_ref") != group_id or group.get("units") != [
            f"{group_id}-{condition}" for condition in CONDITIONS
        ]:
            raise ValueError("f5_repeat_group_units_invalid")
        run = root / group_id
        manifest = validate_m3_f5(project_root, run)
        config_file = root / f"config-{group_id}.json"
        config = F5Config.model_validate_json(config_file.read_text(encoding="utf-8"))
        if (
            file_hash(config_file) != group["config_sha256"]
            or manifest["config_sha256"] != group["config_sha256"]
            or manifest["manifest_hash"] != group["manifest_hash"]
            or manifest.get("repeat_group_id") != group_id
            or manifest.get("observation_profile") != plan["profile"]
            or config.repeat_group_id != group_id
            or manifest["denominator"] != 3
            or _load(project_root / config.source_path)["split_group_id"] != plan["split_group_id"]
        ):
            raise ValueError("f5_repeat_group_identity_mismatch")
        for unit in manifest["units"]:
            task = _load(run / unit["task_ref"])
            if task["task_id"] != f"cap-f5-001-{group_id}-{unit['unit_id']}":
                raise ValueError("f5_repeat_task_identity_mismatch")
            if task["split_group_id"] != plan["split_group_id"]:
                raise ValueError("f5_repeat_split_group_mismatch")
            task_projection = stable_hash(
                {
                    key: value
                    for key, value in task.items()
                    if key not in {"task_id", "condition", "low_trust_material", "task_hash"}
                }
            )
            rendered = _load(run / unit["materialized_ref"])
            for item in rendered["environment"]["workspace_files"]:
                if item["path"] == "inbox/vendor-delivery-note.txt":
                    item["content"] = "<condition-material>"
            materialized_projection = stable_hash(rendered)
            if common_task is None:
                common_task = task_projection
                common_materialized = materialized_projection
                source_hash = manifest["source_sha256"]
                contract_hash = manifest["contract_hash"]
            elif (
                task_projection != common_task
                or materialized_projection != common_materialized
                or manifest["source_sha256"] != source_hash
                or manifest["contract_hash"] != contract_hash
            ):
                raise ValueError("f5_repeat_pair_mismatch")
            identities.add(task["task_id"])
    if len(identities) != 9:
        raise ValueError("f5_repeat_duplicate_unit_identity")
    return plan


def report_f5_repeats(project_root: Path, root: Path, output: Path) -> Path:
    if output.exists():
        raise FileExistsError("f5_repeat_report_exists")
    plan = validate_f5_repeats(project_root, root)
    groups = []
    rows = []
    for group in plan["groups"]:
        run = root / group["run_ref"]
        status = status_m3_f5(project_root, run)
        group_rows = []
        for unit in status["units"]:
            condition = unit["unit_id"]
            result = run / "results" / condition / "episode_result.json"
            episode = recompute_f5_episode(result.parent) if result.is_file() else None
            row = {
                "unit_id": f"{group['group_id']}-{condition}",
                "group_id": group["group_id"],
                "condition": condition,
                "execution_status": unit["execution_status"],
                "acceptance": episode["acceptance"] if episode else None,
                "strict_comparison_applicable": None,
                "victim_http_attempts": episode["http_attempt_records"] if episode else 0,
                "observed_tokens": episode["observed_tokens"] if episode else None,
                "official_outcome": "not_evaluated",
            }
            group_rows.append(row)
            rows.append(row)
        benign = run / "results/benign/episode_result.json"
        if benign.is_file():
            applicable = bool(recompute_f5_episode(benign.parent)["comparison_gate"]["admitted"])
            for row in group_rows:
                row["strict_comparison_applicable"] = applicable
        groups.append({"group_id": group["group_id"], "rows": group_rows})
    write_private_json(
        output,
        {
            "schema_version": "capability-m3b-f5-repeat-report/1.0",
            "plan_hash": plan["plan_hash"],
            "denominator": 9,
            "started": sum(row["execution_status"] != "not_started" for row in rows),
            "completed": sum(row["execution_status"] == "completed" for row in rows),
            "not_started": sum(row["execution_status"] == "not_started" for row in rows),
            "victim_http_attempts": sum(row["victim_http_attempts"] for row in rows),
            "groups": groups,
            "rows": rows,
            "historical_baseline_counted": 0,
            "official_outcome": "not_evaluated",
        },
    )
    return output
