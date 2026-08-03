from __future__ import annotations

import argparse
import json
from pathlib import Path

from stac_attack_lab.config import load_experiment_config
from stac_attack_lab.contracts import SCHEMA_MODELS
from stac_attack_lab.datasets.auditor import audit_dataset
from stac_attack_lab.datasets.manifest import freeze_dataset
from stac_attack_lab.env_loader import load_project_env
from stac_attack_lab.environments.agentdojo_adapter import smoke_available
from stac_attack_lab.environments.shade_arena_adapter import (
    smoke_available as shade_smoke_available,
)
from stac_attack_lab.execution.offline import build_offline_dataset
from stac_attack_lab.execution.online_stac import run_online
from stac_attack_lab.integration_smoke import smoke_models
from stac_attack_lab.reporting.report import build_report


def project_root() -> Path:
    return Path(__file__).resolve().parents[2]


def build_schemas(root: Path) -> None:
    schema_dir = root / "schemas"
    schema_dir.mkdir(exist_ok=True)
    for name, model in SCHEMA_MODELS.items():
        (schema_dir / f"{name}.schema.json").write_text(
            json.dumps(model.model_json_schema(), indent=2, sort_keys=True),
            encoding="utf-8",
        )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="stac-attack-lab")
    sub = parser.add_subparsers(dest="cmd", required=True)

    schemas = sub.add_parser("schemas")
    schemas_sub = schemas.add_subparsers(dest="schemas_cmd", required=True)
    schemas_sub.add_parser("build")

    offline = sub.add_parser("offline")
    offline_sub = offline.add_subparsers(dest="offline_cmd", required=True)
    offline_build = offline_sub.add_parser("build")
    offline_build.add_argument("--config", required=True)

    dataset = sub.add_parser("dataset")
    dataset_sub = dataset.add_subparsers(dest="dataset_cmd", required=True)
    audit = dataset_sub.add_parser("audit")
    audit.add_argument("--dataset", required=True)
    freeze = dataset_sub.add_parser("freeze")
    freeze.add_argument("--dataset", required=True)
    freeze.add_argument("--version", required=True)

    online = sub.add_parser("online")
    online_sub = online.add_subparsers(dest="online_cmd", required=True)
    online_run = online_sub.add_parser("run")
    online_run.add_argument("--config", required=True)
    online_run.add_argument("--dataset-version", default=None)

    run = sub.add_parser("run")
    run_sub = run.add_subparsers(dest="run_cmd", required=True)
    resume = run_sub.add_parser("resume")
    resume.add_argument("--run-id", required=True)

    report = sub.add_parser("report")
    report_sub = report.add_subparsers(dest="report_cmd", required=True)
    report_build = report_sub.add_parser("build")
    report_build.add_argument("--run-root", required=True)

    integration = sub.add_parser("integration")
    integration_sub = integration.add_subparsers(dest="integration_cmd", required=True)
    integration_sub.add_parser("smoke-agentdojo")
    integration_sub.add_parser("smoke-shade")
    integration_sub.add_parser("smoke-models")

    args = parser.parse_args(argv)
    root = project_root()
    load_project_env(root)
    if args.cmd == "schemas":
        build_schemas(root)
        print("schemas built")
        return 0
    if args.cmd == "offline":
        config = load_experiment_config(root / args.config)
        path = build_offline_dataset(root, config.task_limit, config.seeds[0], config)
        print(path)
        return 0
    if args.cmd == "dataset" and args.dataset_cmd == "audit":
        errors = audit_dataset(root / args.dataset)
        if errors:
            for error in errors:
                print(error)
            return 1
        print("audit passed")
        return 0
    if args.cmd == "dataset" and args.dataset_cmd == "freeze":
        target = freeze_dataset(root / args.dataset, args.version, root)
        print(target)
        return 0
    if args.cmd == "online":
        config = load_experiment_config(root / args.config)
        if args.dataset_version:
            config = config.model_copy(update={"dataset_version": args.dataset_version})
        path = run_online(root, config)
        print(path)
        return 0
    if args.cmd == "run":
        print(f"resume is a no-op for completed deterministic smoke: {args.run_id}")
        return 0
    if args.cmd == "report":
        build_report(root / args.run_root)
        print(root / args.run_root / "report.json")
        return 0
    if args.cmd == "integration":
        if args.integration_cmd == "smoke-models":
            print(json.dumps(smoke_models(root), indent=2, sort_keys=True))
            return 0
        if args.integration_cmd == "smoke-shade":
            ok, reason = shade_smoke_available(root)
            print("available" if ok else f"skip: {reason}")
            print(reason)
            return 0
        ok, reason = smoke_available()
        print("available" if ok else f"skip: {reason}")
        return 0
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
