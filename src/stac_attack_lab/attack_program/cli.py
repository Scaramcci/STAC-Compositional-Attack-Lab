"""Offline attack program entry point. All writes use fresh output directories."""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path

from stac_attack_lab.attack_program.demo_r2 import demo as r2_demo
from stac_attack_lab.attack_program.demo_r3 import demo as r3_demo
from stac_attack_lab.attack_program.development import (
    audit_library,
    develop,
    freeze_synthetic,
    replay,
)
from stac_attack_lab.attack_program.file_io import write_json_exclusive as _save
from stac_attack_lab.attack_program.models import (
    AttackCandidate,
    Catalog,
    DevelopmentInput,
    R3Config,
    Split,
)
from stac_attack_lab.attack_program.pipeline import (
    GateError,
    build_catalog,
    make_split,
    validate_catalog,
    validate_split,
)
from stac_attack_lab.attack_program.r3 import ScriptedTransport
from stac_attack_lab.attack_program.r3 import replay as r3_replay
from stac_attack_lab.attack_program.r3 import run as r3_run
from stac_attack_lab.attack_program.r4 import replay_case
from stac_attack_lab.attack_program.r4_batch import (
    authorization_text,
    batch_status,
    bind_disabled,
    generate_candidate,
    load_candidate,
    prepare_disabled,
    run_disabled,
    validate_prepared,
)
from stac_attack_lab.attack_program.r4_generation import (
    generation_authorization_preview,
    generation_status,
    prepare_generation,
    prepare_victim_candidates,
    run_generation,
)
from stac_attack_lab.attack_program.r4_real_import import audit_real_attempt, import_real_attempt
from stac_attack_lab.attack_program.r4_runtime import _upstream_preflight, run_local_fake_batch

ROOT = Path(__file__).resolve().parents[3]


def _new_dir(path: Path) -> Path:
    path.mkdir(mode=0o700, parents=True, exist_ok=False)
    return path


def _load_catalog(path: Path) -> Catalog:
    return Catalog.model_validate_json(path.read_text(encoding="utf-8"))


def _load_split(path: Path) -> Split:
    return Split.model_validate_json(path.read_text(encoding="utf-8"))


def main() -> int:
    parser = argparse.ArgumentParser(
        description="R1–R4 attack program tools; R4 live execution remains disabled"
    )
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("doctor")
    cat = sub.add_parser("catalog")
    cat.add_argument("--output", type=Path, required=True)
    spl = sub.add_parser("split")
    spl.add_argument("--catalog", type=Path, required=True)
    spl.add_argument("--output", type=Path, required=True)
    show = sub.add_parser("status")
    show.add_argument("--catalog", type=Path, required=True)
    show.add_argument("--split", type=Path, required=True)
    imp = sub.add_parser("develop")
    imp.add_argument("--input", type=Path, required=True)
    imp.add_argument("--output", type=Path, required=True)
    new_demo = sub.add_parser("r2-demo")
    new_demo.add_argument("--output", type=Path, required=True)
    r3_demo_cmd = sub.add_parser("r3-demo")
    r3_demo_cmd.add_argument("--output", type=Path, required=True)
    r3_run_cmd = sub.add_parser("r3-scripted")
    r3_run_cmd.add_argument("--library", type=Path, required=True)
    r3_run_cmd.add_argument("--config", type=Path, required=True)
    r3_run_cmd.add_argument("--output", type=Path, required=True)
    r3_replay_cmd = sub.add_parser("r3-replay")
    r3_replay_cmd.add_argument("--library", type=Path, required=True)
    r3_replay_cmd.add_argument("--run", type=Path, required=True)
    r3_replay_cmd.add_argument("--output", type=Path, required=True)
    r3_replay_cmd.add_argument("--compare", action="store_true")
    replay_cmd = sub.add_parser("replay")
    replay_cmd.add_argument("--run", type=Path, required=True)
    replay_cmd.add_argument("--output", type=Path, required=True)
    replay_cmd.add_argument("--compare", action="store_true")
    freeze_cmd = sub.add_parser("freeze-synthetic")
    freeze_cmd.add_argument("--run", type=Path, required=True)
    freeze_cmd.add_argument("--output", type=Path, required=True)
    audit_cmd = sub.add_parser("audit-library")
    audit_cmd.add_argument("--library", type=Path, required=True)
    audit_cmd.add_argument("--output", type=Path, required=True)
    st = sub.add_parser("status-r2")
    st.add_argument("--run", type=Path, required=True)
    sub.add_parser("r4-doctor")
    r4_fake = sub.add_parser("r4-local-fake")
    r4_fake.add_argument("--candidate", type=Path, required=True)
    r4_fake.add_argument("--output", type=Path, required=True)
    r4_prepare = sub.add_parser("r4-prepare")
    r4_prepare.add_argument("--candidate", type=Path, required=True)
    r4_prepare.add_argument("--output", type=Path, required=True)
    r4_prepare.add_argument("--local-fake-mode", choices=("normal", "harm", "reject"))
    for name in ("r4-validate", "r4-status", "r4-bind", "r4-run-batch", "r4-authorization-preview"):
        command = sub.add_parser(name)
        command.add_argument("--batch", type=Path, required=True)
        if name in {"r4-bind", "r4-run-batch"}:
            command.add_argument("--authorization", type=Path)
            command.add_argument("--authorization-sha256")
            command.add_argument("--acknowledge-real-authorization", action="store_true")
            command.add_argument("--local-fake-authorized", action="store_true")
    for name in ("r4-review", "r4-replay"):
        command = sub.add_parser(name)
        command.add_argument("--case", type=Path, required=True)
        command.add_argument("--output", type=Path, required=True)
    r4_import = sub.add_parser("r4-import-real-development")
    r4_import.add_argument("--batch", type=Path, required=True)
    r4_import.add_argument("--review", type=Path, required=True)
    r4_import.add_argument("--audit", type=Path, required=True)
    r4_import_audit = sub.add_parser("r4-audit-real-development")
    r4_import_audit.add_argument("--batch", type=Path, required=True)
    r4_import_audit.add_argument("--review", type=Path, required=True)
    r4_import_audit.add_argument("--audit", type=Path, required=True)
    r4_generate = sub.add_parser("r4-generate-local-fake")
    r4_generate.add_argument("--task-id", required=True)
    r4_generate.add_argument("--model-id", required=True)
    r4_generate.add_argument("--base-url", required=True)
    r4_generate.add_argument("--api-key-env", required=True)
    r4_generate.add_argument("--batch-id", required=True)
    r4_generate.add_argument("--output", type=Path, required=True)
    r4_gen_prepare = sub.add_parser("r4-generation-prepare")
    r4_gen_prepare.add_argument("--plan", type=Path, required=True)
    r4_gen_prepare.add_argument("--prompt", type=Path, required=True)
    r4_gen_prepare.add_argument("--output", type=Path, required=True)
    r4_gen_prepare.add_argument("--model-id")
    r4_gen_prepare.add_argument("--base-url")
    r4_gen_run = sub.add_parser("r4-generation-run")
    r4_gen_run.add_argument("--plan", type=Path, required=True)
    r4_gen_run.add_argument("--prompt", type=Path, required=True)
    r4_gen_run.add_argument("--output", type=Path, required=True)
    r4_gen_run.add_argument("--model-id")
    r4_gen_run.add_argument("--base-url")
    r4_gen_run.add_argument("--api-key-env", default="STAC_R4_ATTACKER_KEY")
    r4_gen_run.add_argument("--local-fake", action="store_true")
    r4_gen_run.add_argument("--authorization", type=Path)
    r4_gen_run.add_argument("--authorization-sha256")
    r4_gen_run.add_argument("--acknowledge-real-authorization", action="store_true")
    r4_gen_prepare_victim = sub.add_parser("r4-generation-prepare-victim")
    r4_gen_prepare_victim.add_argument("--generation", type=Path, required=True)
    r4_gen_prepare_victim.add_argument("--output", type=Path, required=True)
    r4_gen_prepare_victim.add_argument("--local-fake-mode", choices=("normal", "harm", "reject"))
    r4_gen_preview = sub.add_parser("r4-generation-authorization-preview")
    r4_gen_preview.add_argument("--plan", type=Path, required=True)
    r4_gen_preview.add_argument("--prompt", type=Path, required=True)
    r4_gen_status = sub.add_parser("r4-generation-status")
    r4_gen_status.add_argument("--generation", type=Path, required=True)
    args = parser.parse_args()
    try:
        if args.command == "doctor":
            catalog = build_catalog(ROOT)
            print(
                json.dumps(
                    {
                        "status": "offline_ready",
                        "commit": catalog.upstream_commit,
                        "audited_tasks": len(catalog.entries),
                        "model_requests": 0,
                        "docker": False,
                    }
                )
            )
        elif args.command == "catalog":
            catalog = build_catalog(ROOT)
            _new_dir(args.output)
            _save(args.output / "catalog.json", catalog.model_dump(mode="json"))
            print(args.output / "catalog.json")
        elif args.command == "split":
            catalog = _load_catalog(args.catalog)
            validate_catalog(catalog, ROOT)
            split = make_split(catalog)
            validate_split(split, catalog)
            _new_dir(args.output)
            _save(args.output / "split.json", split.model_dump(mode="json"))
            print(args.output / "split.json")
        elif args.command == "status":
            catalog = _load_catalog(args.catalog)
            split = _load_split(args.split)
            validate_catalog(catalog, ROOT)
            validate_split(split, catalog)
            groups = sorted(set(split.group_assignments.values()))
            print(
                json.dumps(
                    {
                        "status": "valid",
                        "groups": groups,
                        "unseen_test_available": "test" in groups,
                        "next": (
                            "Run 10_demo_r2.sh for synthetic development and library audit; "
                            "audit held-out groups before R3 test."
                        ),
                    }
                )
            )
        elif args.command == "develop":
            config = DevelopmentInput.model_validate_json(args.input.read_text(encoding="utf-8"))
            report = develop(ROOT, config, args.output)
            print(
                json.dumps(
                    {"report": str(args.output / "report.json"), "assigned": report["assigned"]}
                )
            )
        elif args.command == "r2-demo":
            result = r2_demo(ROOT, args.output)
            print(
                json.dumps(
                    {
                        "report": str(args.output / "development/report.json"),
                        "library": str(args.output / "library"),
                        "audit": str(args.output / "audit/report.json"),
                        "assigned": result["development"]["assigned"],
                        "scope": "synthetic_only",
                    }
                )
            )
        elif args.command == "r3-demo":
            print(json.dumps(r3_demo(ROOT, args.output)))
        elif args.command == "r3-scripted":
            r3_config = R3Config.model_validate_json(args.config.read_text(encoding="utf-8"))
            report = r3_run(ROOT, args.library, r3_config, args.output, ScriptedTransport())
            print(
                json.dumps(
                    {"report": str(args.output / "report.json"), "assigned": report["assigned"]}
                )
            )
        elif args.command == "r3-replay":
            report = r3_replay(ROOT, args.library, args.run, args.output, compare=args.compare)
            print(
                json.dumps(
                    {"audit": str(args.output / "audit.json"), "assigned": report["assigned"]}
                )
            )
        elif args.command == "replay":
            report = replay(ROOT, args.run, args.output, compare=args.compare)
            print(
                json.dumps(
                    {"report": str(args.output / "report.json"), "assigned": report["assigned"]}
                )
            )
        elif args.command == "freeze-synthetic":
            library = freeze_synthetic(ROOT, args.run, args.output)
            print(json.dumps({"library": str(args.output), "library_id": library["library_id"]}))
        elif args.command == "audit-library":
            report = audit_library(ROOT, args.library, args.output)
            print(
                json.dumps(
                    {
                        "report": str(args.output / "report.json"),
                        "sample_count": report["sample_count"],
                    }
                )
            )
        elif args.command == "status-r2":
            manifest = json.loads((args.run / "manifest.json").read_text(encoding="utf-8"))
            report = json.loads((args.run / "report.json").read_text(encoding="utf-8"))
            if manifest.get("schema_version") != "attack-development/1":
                raise GateError("unsupported_development_representation")
            print(
                json.dumps(
                    {
                        "status": "development_recorded",
                        "assigned": report["assigned"],
                        "next": "Replay with --compare, then freeze-synthetic in a new directory.",
                    }
                )
            )
        elif args.command == "r4-doctor":
            preflight = _upstream_preflight(ROOT)
            print(json.dumps({"status": "offline_runtime_preflight_valid", **preflight}))
        elif args.command == "r4-local-fake":
            candidate = load_candidate(args.candidate)
            report = run_local_fake_batch(ROOT, candidate, args.output)
            print(json.dumps(report))
            if report["completed"] != report["assigned"]:
                return 2
        elif args.command == "r4-prepare":
            manifest = prepare_disabled(
                ROOT, args.candidate, args.output, local_fake=args.local_fake_mode
            )
            print(
                json.dumps(
                    {
                        "status": "prepared_disabled",
                        "manifest": str(args.output / "manifest.json"),
                        "batch_id": manifest["batch_id"],
                    }
                )
            )
        elif args.command == "r4-validate":
            print(json.dumps(validate_prepared(ROOT, args.batch)))
        elif args.command == "r4-status":
            print(json.dumps(batch_status(ROOT, args.batch)))
        elif args.command == "r4-authorization-preview":
            validate_prepared(ROOT, args.batch)
            manifest = json.loads((args.batch / "manifest.json").read_text())
            print(
                json.dumps(
                    {
                        "status": "preview_only_not_authorization",
                        "authorization_record": {
                            "schema_version": "attack-r4-authorization/1",
                            "scope": manifest["scope"],
                            "manifest_hash": manifest["manifest_hash"],
                            "text": authorization_text(manifest),
                        },
                        "next": (
                            "User authorization required; save approved original record, "
                            "compute file SHA256, then bind/run with explicit flag."
                        ),
                    }
                )
            )
        elif args.command in {"r4-bind", "r4-run-batch"}:
            if args.acknowledge_real_authorization and args.local_fake_authorized:
                raise GateError("runtime_authorization_flags_conflict")
            operation = bind_disabled if args.command == "r4-bind" else run_disabled
            print(
                json.dumps(
                    operation(
                        ROOT,
                        args.batch,
                        authorization=args.authorization,
                        authorization_sha256=args.authorization_sha256,
                        acknowledge=args.acknowledge_real_authorization
                        or args.local_fake_authorized,
                        local_fake=args.local_fake_authorized,
                    )
                )
            )
        elif args.command in {"r4-review", "r4-replay"}:
            print(json.dumps(replay_case(ROOT, args.case, args.output)))
        elif args.command == "r4-import-real-development":
            print(
                json.dumps(
                    import_real_attempt(
                        ROOT,
                        args.batch,
                        args.review,
                        args.audit,
                        ROOT / "experiments/runs/attack-program/r4-real-development-imports",
                    )
                )
            )
        elif args.command == "r4-audit-real-development":
            print(
                json.dumps(
                    audit_real_attempt(
                        ROOT,
                        args.batch,
                        args.review,
                        args.audit,
                        ROOT / "experiments/runs/attack-program/r4-real-development-imports",
                    )
                )
            )
        elif args.command == "r4-generate-local-fake":
            key = os.environ.get(args.api_key_env)
            if not key:
                raise GateError("attacker_api_key_env_missing")
            generated_candidate: AttackCandidate = generate_candidate(
                ROOT,
                task_id=args.task_id,
                model_id=args.model_id,
                base_url=args.base_url,
                api_key=key,
                output=args.output,
                batch_id=args.batch_id,
            )
            print(
                json.dumps(
                    {
                        "candidate": str(args.output / "candidate.json"),
                        "candidate_id": generated_candidate.candidate_id,
                    }
                )
            )
        elif args.command == "r4-generation-prepare":
            print(
                json.dumps(
                    prepare_generation(
                        ROOT,
                        args.plan,
                        args.prompt,
                        args.output,
                        model_id=args.model_id,
                        base_url=args.base_url,
                    )
                )
            )
        elif args.command == "r4-generation-run":
            key = os.environ.get(args.api_key_env) if args.local_fake else None
            print(
                json.dumps(
                    run_generation(
                        ROOT,
                        args.plan,
                        args.prompt,
                        args.output,
                        model_id=args.model_id,
                        base_url=args.base_url,
                        api_key=key,
                        local_fake=args.local_fake,
                        authorization=args.authorization,
                        authorization_sha256=args.authorization_sha256,
                        acknowledge_real_authorization=args.acknowledge_real_authorization,
                    )
                )
            )
        elif args.command == "r4-generation-prepare-victim":
            print(
                json.dumps(
                    prepare_victim_candidates(
                        ROOT,
                        args.generation,
                        args.output,
                        local_fake_mode=args.local_fake_mode,
                    )
                )
            )
        elif args.command == "r4-generation-authorization-preview":
            print(json.dumps(generation_authorization_preview(ROOT, args.plan, args.prompt)))
        elif args.command == "r4-generation-status":
            print(json.dumps(generation_status(args.generation)))
        return 0
    except (GateError, FileExistsError, FileNotFoundError) as exc:
        print(
            json.dumps(
                {
                    "status": "error",
                    "reason": str(exc),
                    "next": "Inspect the named input/output; choose a fresh output directory.",
                }
            )
        )
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
