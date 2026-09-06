from __future__ import annotations

import argparse
import json
from pathlib import Path

from pydantic import BaseModel

from stac_attack_lab.env_loader import load_project_env
from stac_attack_lab.environments.safeclaw.preflight import (
    load_safeclaw_preflight_config,
    run_safeclaw_preflight,
)
from stac_attack_lab.environments.safeclaw.task_adapter import inventory_safeclaw_tasks
from stac_attack_lab.execution.safeclaw_formal import (
    load_safeclaw_formal_config,
    run_safeclaw_formal,
)
from stac_attack_lab.execution.sample_generation import (
    audit_sample_library_stage,
    collect_sample_interactions,
    freeze_audited_sample_library,
    load_sample_generation_config,
    mine_sample_collection,
)
from stac_attack_lab.execution.sample_preflight import run_sample_collection_preflight
from stac_attack_lab.recording.formal_run_recorder import FormalRunRecorder
from stac_attack_lab.reporting.formal_report import build_formal_report
from stac_attack_lab.schema_registry import SCHEMA_MODELS, validate_schema_registry
from stac_attack_lab.verification.safeclaw_official import smoke_official_pse_evaluator


def project_root() -> Path:
    return Path(__file__).resolve().parents[2]


def build_schemas(root: Path) -> None:
    validate_schema_registry()
    schema_dir = root / "schemas"
    schema_dir.mkdir(exist_ok=True)
    for name, model in SCHEMA_MODELS.items():
        _write_schema(schema_dir / f"{name}.schema.json", model)


def _write_schema(path: Path, model: type[BaseModel]) -> None:
    path.write_text(
        json.dumps(model.model_json_schema(), indent=2, sort_keys=True),
        encoding="utf-8",
    )


def _project_scoped_path(root: Path, value: str) -> Path:
    resolved_root = root.resolve()
    resolved = (root / value).resolve()
    if resolved != resolved_root and resolved_root not in resolved.parents:
        raise ValueError("path_outside_project_root")
    return resolved


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="stac-attack-lab")
    sub = parser.add_subparsers(dest="command", required=True)

    schemas = sub.add_parser("schemas")
    schemas.add_subparsers(dest="schemas_command", required=True).add_parser("build")

    sample = sub.add_parser("sample")
    sample_sub = sample.add_subparsers(dest="sample_command", required=True)
    for command in ("collect-preflight", "collect", "collect-and-mine"):
        action = sample_sub.add_parser(command)
        action.add_argument("--config", required=True)
    mine = sample_sub.add_parser("mine")
    mine.add_argument("--collection", required=True)
    audit = sample_sub.add_parser("audit")
    audit.add_argument("--library", required=True)
    freeze = sample_sub.add_parser("freeze")
    freeze.add_argument("--library", required=True)
    freeze.add_argument("--version", required=True)

    safeclaw = sub.add_parser("safeclaw")
    safeclaw_sub = safeclaw.add_subparsers(dest="safeclaw_command", required=True)
    inventory = safeclaw_sub.add_parser("inventory")
    inventory.add_argument("--upstream", required=True)
    inventory.add_argument("--task", action="append", required=True)
    preflight = safeclaw_sub.add_parser("preflight")
    preflight.add_argument("--config", required=True)
    pse_smoke = safeclaw_sub.add_parser("pse-smoke")
    pse_smoke.add_argument("--upstream", required=True)
    pse_smoke.add_argument("--task", required=True)
    run = safeclaw_sub.add_parser("run")
    run.add_argument("--config", required=True)
    run.add_argument("--run-id")
    run.add_argument("--resume", action="store_true")
    audit_run = safeclaw_sub.add_parser("audit-run")
    audit_run.add_argument("--run-root", required=True)
    report = safeclaw_sub.add_parser("report")
    report.add_argument("--run-root", required=True)
    return parser


def _main(argv: list[str] | None = None) -> int:
    args = _build_parser().parse_args(argv)
    root = project_root()
    load_project_env(root)

    if args.command == "schemas":
        build_schemas(root)
        print("schemas built")
        return 0

    if args.command == "sample":
        if args.sample_command in {"collect-preflight", "collect", "collect-and-mine"}:
            sample_config = load_sample_generation_config(root / args.config)
            preflight_report = run_sample_collection_preflight(root, sample_config)
            if args.sample_command == "collect-preflight" or not preflight_report.passed:
                print(preflight_report.model_dump_json(indent=2))
                return 0 if preflight_report.passed else 1
            collection_root = collect_sample_interactions(root, sample_config)
            if args.sample_command == "collect-and-mine":
                print(mine_sample_collection(root, collection_root))
            else:
                print(collection_root)
            return 0
        if args.sample_command == "mine":
            print(mine_sample_collection(root, _project_scoped_path(root, args.collection)))
            return 0
        library = _project_scoped_path(root, args.library)
        if args.sample_command == "audit":
            library_report = audit_sample_library_stage(library)
            print(library_report.model_dump_json(indent=2))
            return 0 if library_report.passed else 1
        print(freeze_audited_sample_library(library, args.version, root))
        return 0

    command = args.safeclaw_command
    if command == "inventory":
        descriptors = inventory_safeclaw_tasks(root / args.upstream, args.task)
        print(
            json.dumps(
                [item.model_dump(mode="json") for item in descriptors],
                indent=2,
                sort_keys=True,
            )
        )
        return 0
    if command == "preflight":
        environment_config = load_safeclaw_preflight_config(root / args.config)
        environment_report = run_safeclaw_preflight(root, environment_config)
        print(environment_report.model_dump_json(indent=2))
        return 0 if environment_report.passed else 1
    if command == "pse-smoke":
        upstream = root / args.upstream
        pse_report = smoke_official_pse_evaluator(
            upstream / "scripts/judge.py",
            upstream / args.task,
        )
        print(pse_report.model_dump_json(indent=2))
        return 0 if pse_report.passed else 1
    if command == "run":
        try:
            formal_config = load_safeclaw_formal_config(root / args.config)
            print(
                run_safeclaw_formal(
                    root,
                    formal_config,
                    run_id=args.run_id,
                    resume=args.resume,
                )
            )
            return 0
        except (ValueError, FileExistsError) as exc:
            print(str(exc))
            return 2
    if command == "audit-run":
        audit_report = FormalRunRecorder(root / args.run_root).audit()
        print(audit_report.model_dump_json(indent=2))
        return 0 if audit_report.passed else 1
    run_root = root / args.run_root
    build_formal_report(run_root)
    print(run_root / "formal_report.json")
    return 0


def main(argv: list[str] | None = None) -> int:
    try:
        return _main(argv)
    except ValueError as exc:
        print(str(exc))
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
