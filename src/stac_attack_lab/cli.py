from __future__ import annotations

import argparse
import json
from pathlib import Path

from pydantic import BaseModel

from stac_attack_lab.config import StartupValidationError, load_experiment_config
from stac_attack_lab.datasets.auditor import audit_dataset
from stac_attack_lab.datasets.manifest import freeze_dataset
from stac_attack_lab.env_loader import load_project_env
from stac_attack_lab.environments.agentdojo_adapter import smoke_available
from stac_attack_lab.environments.safeclaw.preflight import (
    load_safeclaw_preflight_config,
    run_safeclaw_preflight,
)
from stac_attack_lab.environments.safeclaw.task_adapter import inventory_safeclaw_tasks
from stac_attack_lab.environments.shade_arena_adapter import (
    smoke_available as shade_smoke_available,
)
from stac_attack_lab.execution.offline import build_offline_dataset
from stac_attack_lab.execution.online_stac import resume_online, run_online
from stac_attack_lab.execution.safeclaw_formal import (
    load_safeclaw_formal_config,
    run_safeclaw_formal,
)
from stac_attack_lab.execution.sample_generation import (
    audit_sample_library_stage,
    build_sample_library,
    collect_sample_interactions,
    freeze_audited_sample_library,
    load_sample_generation_config,
    mine_sample_collection,
)
from stac_attack_lab.execution.sample_preflight import run_sample_collection_preflight
from stac_attack_lab.integration_smoke import smoke_models
from stac_attack_lab.models.discovery import ModelDiscoveryError, discover_huihui_model
from stac_attack_lab.recording.conversations import (
    ConversationEvent,
    TranscriptAuditReport,
    audit_transcript,
)
from stac_attack_lab.recording.formal_run_recorder import FormalRunRecorder
from stac_attack_lab.recording.progress import ExperimentProgress
from stac_attack_lab.reporting.formal_report import build_formal_report
from stac_attack_lab.reporting.report import build_report
from stac_attack_lab.schema_registry import SCHEMA_MODELS, validate_schema_registry
from stac_attack_lab.verification.safeclaw_official import smoke_official_pse_evaluator


def project_root() -> Path:
    return Path(__file__).resolve().parents[2]


def build_schemas(root: Path) -> None:
    validate_schema_registry()
    schema_dir = root / "schemas"
    schema_dir.mkdir(exist_ok=True)
    models: dict[str, type[BaseModel]] = {
        **SCHEMA_MODELS,
        "conversation_event": ConversationEvent,
        "experiment_progress": ExperimentProgress,
        "transcript_audit_report": TranscriptAuditReport,
    }
    for name, model in models.items():
        (schema_dir / f"{name}.schema.json").write_text(
            json.dumps(model.model_json_schema(), indent=2, sort_keys=True),
            encoding="utf-8",
        )


def _project_scoped_path(root: Path, value: str) -> Path:
    resolved_root = root.resolve()
    resolved = (root / value).resolve()
    if resolved != resolved_root and resolved_root not in resolved.parents:
        raise ValueError("path_outside_project_root")
    return resolved


def _main(argv: list[str] | None = None) -> int:
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

    sample = sub.add_parser("sample")
    sample_sub = sample.add_subparsers(dest="sample_cmd", required=True)
    sample_attack_build = sample_sub.add_parser("attack-build")
    sample_attack_build.add_argument("--config", required=True)
    sample_build = sample_sub.add_parser("build")
    sample_build.add_argument("--config", required=True)
    sample_collect_preflight = sample_sub.add_parser("collect-preflight")
    sample_collect_preflight.add_argument("--config", required=True)
    sample_collect = sample_sub.add_parser("collect")
    sample_collect.add_argument("--config", required=True)
    sample_mine = sample_sub.add_parser("mine")
    sample_mine.add_argument("--collection", required=True)
    sample_audit = sample_sub.add_parser("audit")
    sample_audit.add_argument("--library", required=True)
    sample_freeze = sample_sub.add_parser("freeze")
    sample_freeze.add_argument("--library", required=True)
    sample_freeze.add_argument("--version", required=True)

    safeclaw = sub.add_parser("safeclaw")
    safeclaw_sub = safeclaw.add_subparsers(dest="safeclaw_cmd", required=True)
    safeclaw_inventory = safeclaw_sub.add_parser("inventory")
    safeclaw_inventory.add_argument("--upstream", required=True)
    safeclaw_inventory.add_argument("--task", action="append", required=True)
    safeclaw_preflight = safeclaw_sub.add_parser("preflight")
    safeclaw_preflight.add_argument("--config", required=True)
    safeclaw_pse_smoke = safeclaw_sub.add_parser("pse-smoke")
    safeclaw_pse_smoke.add_argument("--upstream", required=True)
    safeclaw_pse_smoke.add_argument("--task", required=True)
    safeclaw_run = safeclaw_sub.add_parser("run")
    safeclaw_run.add_argument("--config", required=True)
    safeclaw_run.add_argument("--run-id", default=None)
    safeclaw_run.add_argument("--resume", action="store_true")
    safeclaw_audit_run = safeclaw_sub.add_parser("audit-run")
    safeclaw_audit_run.add_argument("--run-root", required=True)
    safeclaw_report = safeclaw_sub.add_parser("formal-report")
    safeclaw_report.add_argument("--run-root", required=True)

    online = sub.add_parser("online")
    online_sub = online.add_subparsers(dest="online_cmd", required=True)
    online_run = online_sub.add_parser("run")
    online_run.add_argument("--config", required=True)
    online_run.add_argument("--dataset-version", default=None)
    online_run.add_argument("--run-id", default=None)

    run = sub.add_parser("run")
    run_sub = run.add_subparsers(dest="run_cmd", required=True)
    resume = run_sub.add_parser("resume")
    resume.add_argument("--run-id", required=True)

    report = sub.add_parser("report")
    report_sub = report.add_subparsers(dest="report_cmd", required=True)
    report_build = report_sub.add_parser("build")
    report_build.add_argument("--run-root", required=True)

    transcript = sub.add_parser("transcript")
    transcript_sub = transcript.add_subparsers(dest="transcript_cmd", required=True)
    transcript_audit = transcript_sub.add_parser("audit")
    transcript_audit.add_argument("--run-root", required=True)

    models = sub.add_parser("models")
    models_sub = models.add_subparsers(dest="models_cmd", required=True)
    models_sub.add_parser("discover-huihui")

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
    if args.cmd == "sample" and args.sample_cmd in {"attack-build", "build"}:
        sample_config = load_sample_generation_config(root / args.config)
        print(build_sample_library(root, sample_config))
        return 0
    if args.cmd == "sample" and args.sample_cmd == "collect-preflight":
        sample_config = load_sample_generation_config(root / args.config)
        collection_preflight = run_sample_collection_preflight(root, sample_config)
        print(collection_preflight.model_dump_json(indent=2))
        return 0 if collection_preflight.passed else 1
    if args.cmd == "sample" and args.sample_cmd == "collect":
        sample_config = load_sample_generation_config(root / args.config)
        collection_preflight = run_sample_collection_preflight(root, sample_config)
        if not collection_preflight.passed:
            print(collection_preflight.model_dump_json(indent=2))
            return 1
        print(collect_sample_interactions(root, sample_config))
        return 0
    if args.cmd == "sample" and args.sample_cmd == "mine":
        collection_root = _project_scoped_path(root, args.collection)
        print(mine_sample_collection(root, collection_root))
        return 0
    if args.cmd == "sample" and args.sample_cmd == "audit":
        library_root = _project_scoped_path(root, args.library)
        sample_audit_report = audit_sample_library_stage(library_root)
        print(sample_audit_report.model_dump_json(indent=2))
        if not sample_audit_report.passed:
            for error in sample_audit_report.error_codes:
                print(error)
            return 1
        return 0
    if args.cmd == "sample" and args.sample_cmd == "freeze":
        library_root = _project_scoped_path(root, args.library)
        print(
            freeze_audited_sample_library(
                library_root,
                args.version,
                root,
            )
        )
        return 0

    if args.cmd == "safeclaw" and args.safeclaw_cmd == "inventory":
        descriptors = inventory_safeclaw_tasks(root / args.upstream, args.task)
        print(
            json.dumps(
                [item.model_dump(mode="json") for item in descriptors],
                indent=2,
                sort_keys=True,
            )
        )
        return 0
    if args.cmd == "safeclaw" and args.safeclaw_cmd == "preflight":
        preflight_config = load_safeclaw_preflight_config(root / args.config)
        preflight_report = run_safeclaw_preflight(root, preflight_config)
        print(preflight_report.model_dump_json(indent=2))
        return 0 if preflight_report.passed else 1
    if args.cmd == "safeclaw" and args.safeclaw_cmd == "pse-smoke":
        upstream = root / args.upstream
        pse_report = smoke_official_pse_evaluator(
            upstream / "scripts/judge.py",
            upstream / args.task,
        )
        print(pse_report.model_dump_json(indent=2))
        return 0 if pse_report.passed else 1
    if args.cmd == "safeclaw" and args.safeclaw_cmd == "run":
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
    if args.cmd == "safeclaw" and args.safeclaw_cmd == "audit-run":
        audit_report = FormalRunRecorder(root / args.run_root).audit()
        print(audit_report.model_dump_json(indent=2))
        return 0 if audit_report.passed else 1
    if args.cmd == "safeclaw" and args.safeclaw_cmd == "formal-report":
        target_root = root / args.run_root
        build_formal_report(target_root)
        print(target_root / "formal_report.json")
        return 0

    if args.cmd == "online":
        config = load_experiment_config(root / args.config)
        if args.dataset_version:
            config = config.model_copy(update={"dataset_version": args.dataset_version})
        path = run_online(root, config, run_id=args.run_id)
        print(path)
        return 0
    if args.cmd == "run":
        print(resume_online(root, args.run_id))
        return 0
    if args.cmd == "report":
        build_report(root / args.run_root)
        print(root / args.run_root / "report.json")
        return 0
    if args.cmd == "transcript":
        run_root = root / args.run_root
        manifest = json.loads((run_root / "run_manifest.json").read_text(encoding="utf-8"))
        report_value = audit_transcript(
            run_root / "conversations.jsonl", expected_run_id=str(manifest["run_id"])
        )
        target = run_root / "transcript_audit.json"
        target.write_text(report_value.model_dump_json(indent=2), encoding="utf-8")
        print(target)
        return 0 if report_value.passed else 1
    if args.cmd == "models":
        print(discover_huihui_model(root))
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


def main(argv: list[str] | None = None) -> int:
    try:
        return _main(argv)
    except (StartupValidationError, ModelDiscoveryError) as exc:
        print(str(exc))
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
