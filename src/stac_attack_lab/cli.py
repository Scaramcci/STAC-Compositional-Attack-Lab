from __future__ import annotations

import argparse
import json
from pathlib import Path

from pydantic import BaseModel

from stac_attack_lab.config import StartupValidationError, load_experiment_config
from stac_attack_lab.contracts import SCHEMA_MODELS
from stac_attack_lab.datasets.auditor import audit_dataset
from stac_attack_lab.datasets.manifest import freeze_dataset
from stac_attack_lab.env_loader import load_project_env
from stac_attack_lab.environments.agentdojo_adapter import smoke_available
from stac_attack_lab.environments.shade_arena_adapter import (
    smoke_available as shade_smoke_available,
)
from stac_attack_lab.execution.offline import build_offline_dataset
from stac_attack_lab.execution.online_stac import resume_online, run_online
from stac_attack_lab.integration_smoke import smoke_models
from stac_attack_lab.models.discovery import ModelDiscoveryError, discover_huihui_model
from stac_attack_lab.recording.conversations import (
    ConversationEvent,
    TranscriptAuditReport,
    audit_transcript,
)
from stac_attack_lab.recording.progress import ExperimentProgress
from stac_attack_lab.reporting.report import build_report


def project_root() -> Path:
    return Path(__file__).resolve().parents[2]


def build_schemas(root: Path) -> None:
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
