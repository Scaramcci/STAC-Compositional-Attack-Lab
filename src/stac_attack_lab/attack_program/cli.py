"""Offline attack program entry point. All writes use fresh output directories."""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
from typing import Any

from stac_attack_lab.attack_program.demo_r2 import demo as r2_demo
from stac_attack_lab.attack_program.demo_r3 import demo as r3_demo
from stac_attack_lab.attack_program.development import (
    audit_library,
    develop,
    freeze_synthetic,
    replay,
)
from stac_attack_lab.attack_program.models import Catalog, DevelopmentInput, R3Config, Split
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

ROOT = Path(__file__).resolve().parents[3]


def _save(path: Path, data: Any, *, private: bool = False) -> None:
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    fd = os.open(path, flags, 0o600 if private else 0o644)
    with os.fdopen(fd, "w", encoding="utf-8") as stream:
        json.dump(data, stream, ensure_ascii=False, indent=2)
        stream.write("\n")


def _new_dir(path: Path) -> Path:
    path.mkdir(mode=0o700, parents=True, exist_ok=False)
    return path


def _load_catalog(path: Path) -> Catalog:
    return Catalog.model_validate_json(path.read_text(encoding="utf-8"))


def _load_split(path: Path) -> Split:
    return Split.model_validate_json(path.read_text(encoding="utf-8"))


def main() -> int:
    parser = argparse.ArgumentParser(
        description="R1–R3 offline attack program tools; demos make zero model requests"
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
