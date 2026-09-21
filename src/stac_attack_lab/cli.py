from __future__ import annotations

import argparse
import json
from pathlib import Path

from pydantic import BaseModel

from stac_attack_lab.capability.compiler import (
    compile_cases,
    inventory_upstream,
    validate_compatibility_config,
    validate_compilation,
)
from stac_attack_lab.capability.reporting import build_capability_report
from stac_attack_lab.capability.runner import replay_episode, run_fake_pipeline
from stac_attack_lab.env_loader import load_project_env
from stac_attack_lab.environments.safeclaw.preflight import (
    load_safeclaw_preflight_config,
    run_safeclaw_preflight,
)
from stac_attack_lab.environments.safeclaw.task_adapter import inventory_safeclaw_tasks
from stac_attack_lab.execution.benign_collection import (
    collect_benign_fixture,
    collect_benign_live,
    prepare_benign_collection,
    validate_benign_collection_config,
)
from stac_attack_lab.execution.construction_admission import audit_construction_collection
from stac_attack_lab.execution.flow_reanalysis import (
    reanalyze_flow_v3,
    validate_flow_analysis,
)
from stac_attack_lab.execution.readiness import diagnose_workflow
from stac_attack_lab.execution.revalidation import (
    launch_live_revalidation,
    offline_revalidation,
    prepare_revalidation,
)
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
from stac_attack_lab.extraction.flow_slice import slice_dependency_graph
from stac_attack_lab.flow.analysis import AdmissionProfile, FlowAnalysisReport, SliceBudget
from stac_attack_lab.flow.models import EffectGraph
from stac_attack_lab.flow.profile import load_observation_profile
from stac_attack_lab.flow.registry import load_flow_registry
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


def _resolve_safeclaw_task_path(root: Path, upstream: Path, value: str) -> Path:
    candidate = Path(value)
    if candidate.is_absolute():
        resolved = candidate.resolve()
    else:
        root_candidate = (root / candidate).resolve()
        resolved = (
            root_candidate
            if root_candidate.is_file()
            or candidate.parts[:3] == ("integrations", "safeclaw", "upstream")
            else (upstream / candidate).resolve()
        )
    # Keep repository-relative upstream paths stable when the optional pinned
    # checkout is absent; the command that consumes the path reports its own
    # actionable missing-input error.
    if not resolved.is_file() and not candidate.parts[:3] == (
        "integrations",
        "safeclaw",
        "upstream",
    ):
        raise ValueError("safeclaw_task_path_missing")
    return resolved


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

    capability = sub.add_parser("capability", help="nine-primitive offline experiment")
    capability_sub = capability.add_subparsers(dest="capability_command", required=True)
    capability_inventory = capability_sub.add_parser("inventory")
    capability_inventory.add_argument(
        "--upstream", default="integrations/safeclaw/upstream/SafeClawArena"
    )
    capability_compile = capability_sub.add_parser("compile")
    capability_compile.add_argument("--config", required=True)
    capability_compile.add_argument("--output", required=True)
    capability_validate = capability_sub.add_parser("validate")
    capability_validate.add_argument("--manifest", required=True)
    compatibility_validate = capability_sub.add_parser("compatibility-validate")
    compatibility_validate.add_argument(
        "--config", default="configs/capability/provider_compatibility.disabled.json"
    )
    capability_replay = capability_sub.add_parser("replay")
    capability_replay.add_argument("--episode", required=True)
    capability_replay.add_argument("--output", required=True)
    capability_report = capability_sub.add_parser("report")
    capability_report.add_argument("--manifest", required=True)
    capability_report.add_argument("--output", required=True)
    capability_demo = capability_sub.add_parser("demo")
    capability_demo.add_argument("--config", required=True)
    capability_demo.add_argument("--output", required=True)

    benign = sub.add_parser("benign", help="benign pre-evaluation collection")
    benign_sub = benign.add_subparsers(dest="benign_command", required=True)
    for command in ("validate", "prepare", "collect-fixture", "collect-live"):
        action = benign_sub.add_parser(command)
        action.add_argument(
            "--config",
            default="configs/benign_collection/synthetic_stage_a.disabled.json",
        )
        if command == "collect-live":
            action.add_argument("--authorize-live", action="store_true")
            action.add_argument("--run-id", required=True)
        elif command == "prepare":
            action.add_argument("--run-id")

    doctor = sub.add_parser("doctor", help="offline workflow readiness diagnosis")
    doctor.add_argument("--config", required=True)
    doctor.add_argument(
        "--workflow-kind",
        choices=[
            "fixture",
            "compatibility_probe",
            "benign_collection",
            "legacy_attack_collection",
            "formal",
        ],
    )
    doctor.add_argument("--run-root")

    flow = sub.add_parser("flow", help="explicit Primitive v3 offline analysis")
    flow_sub = flow.add_subparsers(dest="flow_command", required=True)
    profile_validate = flow_sub.add_parser("profile-validate")
    profile_validate.add_argument("--profile", default="configs/flow/observation_profile_v3.json")
    profile_validate.add_argument("--registry", default="configs/flow/registry_v3.json")
    reanalyze = flow_sub.add_parser("reanalyze")
    reanalyze.add_argument("--input", required=True)
    reanalyze.add_argument("--output-root", required=True)
    reanalyze.add_argument("--profile", default="configs/flow/observation_profile_v3.json")
    reanalyze.add_argument("--registry", default="configs/flow/registry_v3.json")
    reanalyze.add_argument("--sink-port", action="append", default=[])
    reanalyze.add_argument("--terminal-outputs", action="store_true")
    reanalyze.add_argument("--require-profile", choices=[item.value for item in AdmissionProfile])
    validate = flow_sub.add_parser("analysis-validate")
    validate.add_argument("--analysis", required=True)
    slice_parser = flow_sub.add_parser("slice")
    slice_parser.add_argument("--graph", required=True)
    slice_parser.add_argument("--sink-port", action="append", required=True)
    slice_parser.add_argument("--output", required=True)
    slice_parser.add_argument("--max-nodes", type=int, default=256)
    slice_parser.add_argument("--max-edges", type=int, default=512)
    inspect_parser = flow_sub.add_parser("inspect")
    inspect_parser.add_argument("--analysis", required=True)

    sample = sub.add_parser("sample")
    sample_sub = sample.add_subparsers(dest="sample_command", required=True)
    for command in ("collect-preflight", "collect", "collect-and-mine"):
        action = sample_sub.add_parser(command)
        action.add_argument("--config", required=True)
    mine = sample_sub.add_parser("mine")
    mine.add_argument("--collection", required=True)
    mine.add_argument("--output")
    admission = sample_sub.add_parser("admission")
    admission.add_argument("--collection", required=True)
    admission.add_argument("--library", required=True)
    audit = sample_sub.add_parser("audit")
    audit.add_argument("--library", required=True)
    freeze = sample_sub.add_parser("freeze")
    freeze.add_argument("--library", required=True)
    freeze.add_argument("--version", required=True)

    revalidation = sub.add_parser("revalidation", help="offline preparation and evidence replay")
    rv_sub = revalidation.add_subparsers(dest="revalidation_command", required=True)
    rv_prepare = rv_sub.add_parser("prepare")
    rv_prepare.add_argument(
        "--template", default="configs/sample_generation/cross_session_revalidation.disabled.json"
    )
    rv_prepare.add_argument("--run-id")
    rv_offline = rv_sub.add_parser("offline")
    rv_offline.add_argument("--run-root", required=True)
    rv_offline.add_argument("--collection")
    rv_offline.add_argument("--library")
    rv_offline.add_argument("--bridge-responses")
    rv_live = rv_sub.add_parser("live")
    rv_live.add_argument("--run-root", required=True)
    rv_live.add_argument("--authorize-live", action="store_true")

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

    if args.command == "capability":
        if args.capability_command == "inventory":
            report = inventory_upstream(_project_scoped_path(root, args.upstream))
            print(json.dumps(report, indent=2, sort_keys=True))
            return 0
        if args.capability_command == "compile":
            compiled_path = compile_cases(
                _project_scoped_path(root, args.config),
                _project_scoped_path(root, args.output),
            )
            print(compiled_path)
            return 0
        if args.capability_command == "validate":
            manifest_path = _project_scoped_path(root, args.manifest)
            compilation_root = manifest_path.parent if manifest_path.is_file() else manifest_path
            capability_manifest = validate_compilation(compilation_root)
            print(capability_manifest.model_dump_json(indent=2))
            return 0
        if args.capability_command == "compatibility-validate":
            compatibility_config = validate_compatibility_config(
                _project_scoped_path(root, args.config)
            )
            print(compatibility_config.model_dump_json(indent=2))
            return 0
        if args.capability_command == "replay":
            replay_result = replay_episode(
                _project_scoped_path(root, args.episode),
                _project_scoped_path(root, args.output),
            )
            print(replay_result.model_dump_json(indent=2))
            return 0
        if args.capability_command == "report":
            report_path = build_capability_report(
                _project_scoped_path(root, args.manifest),
                _project_scoped_path(root, args.output),
            )
            print(report_path)
            return 0
        compilation = _project_scoped_path(root, args.output) / "compiled"
        episodes = _project_scoped_path(root, args.output) / "episodes"
        reports = _project_scoped_path(root, args.output) / "report"
        upstream = root / "integrations/safeclaw/upstream/SafeClawArena"
        compile_cases(_project_scoped_path(root, args.config), compilation)
        validate_compilation(compilation)
        run_fake_pipeline(compilation, episodes)
        compatibility_report = {
            "inventory": inventory_upstream(upstream),
            "official_pse_smoke": smoke_official_pse_evaluator(
                upstream / "scripts/judge.py",
                upstream / "tasks/pse/pse-2.1-002.json",
            ).model_dump(mode="json"),
            "network_requests_performed": False,
        }
        output_root = _project_scoped_path(root, args.output)
        (output_root / "compatibility_report.json").write_text(
            json.dumps(compatibility_report, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        print(build_capability_report(episodes, reports))
        return 0

    if args.command == "doctor":
        readiness_report = diagnose_workflow(
            root,
            Path(args.config),
            workflow_kind=args.workflow_kind,
            run_root=_project_scoped_path(root, args.run_root) if args.run_root else None,
        )
        print(readiness_report.model_dump_json(indent=2))
        return 10 if readiness_report.all_independent_blockers else 0

    if args.command == "benign":
        config_path = _project_scoped_path(root, args.config)
        if args.benign_command == "validate":
            config, scenarios = validate_benign_collection_config(root, config_path)
            print(
                json.dumps(
                    {
                        "status": "passed",
                        "study_id": config.study_id,
                        "source_mode": config.source_mode,
                        "execution_enabled": config.execution_enabled,
                        "scenario_count": len(scenarios.scenarios),
                        "network_requests_performed": False,
                    },
                    indent=2,
                    sort_keys=True,
                )
            )
            return 0
        if args.benign_command == "prepare":
            print(prepare_benign_collection(root, config_path, args.run_id))
            return 0
        if args.benign_command == "collect-live":
            collection, analysis = collect_benign_live(
                root,
                config_path,
                authorized=args.authorize_live,
                run_id=args.run_id,
            )
        else:
            collection, analysis = collect_benign_fixture(root, config_path)
        print(json.dumps({"collection": str(collection), "analysis": str(analysis)}, indent=2))
        return 0

    if args.command == "flow":
        if args.flow_command == "profile-validate":
            profile = load_observation_profile(_project_scoped_path(root, args.profile))
            registry = load_flow_registry(_project_scoped_path(root, args.registry))
            print(
                json.dumps(
                    {
                        "status": "passed",
                        "profile_id": profile.profile_id,
                        "profile_version": profile.profile_version,
                        "registry_id": registry.registry_id,
                        "registry_version": registry.registry_version,
                    },
                    indent=2,
                    sort_keys=True,
                )
            )
            return 0
        if args.flow_command == "reanalyze":
            analysis_root = reanalyze_flow_v3(
                root,
                input_path=_project_scoped_path(root, args.input),
                output_root=_project_scoped_path(root, args.output_root),
                profile_path=_project_scoped_path(root, args.profile),
                registry_path=_project_scoped_path(root, args.registry),
                sink_port_ids=args.sink_port,
                terminal_outputs=args.terminal_outputs,
            )
            print(analysis_root)
            if args.require_profile:
                flow_report = FlowAnalysisReport.model_validate_json(
                    (analysis_root / "report.json").read_text(encoding="utf-8")
                )
                matched = next(
                    (
                        item
                        for item in flow_report.profiles
                        if item.profile.value == args.require_profile
                    ),
                    None,
                )
                return 0 if matched is not None and matched.status.value == "passed" else 10
            return 0
        if args.flow_command == "analysis-validate":
            flow_manifest = validate_flow_analysis(_project_scoped_path(root, args.analysis))
            print(flow_manifest.model_dump_json(indent=2))
            return 0
        if args.flow_command == "slice":
            graph = EffectGraph.model_validate_json(
                _project_scoped_path(root, args.graph).read_text(encoding="utf-8")
            )
            slice_result = slice_dependency_graph(
                graph,
                sink_port_ids=args.sink_port,
                budget=SliceBudget(max_nodes=args.max_nodes, max_edges=args.max_edges),
            )
            output = _project_scoped_path(root, args.output)
            output.parent.mkdir(parents=True, exist_ok=True)
            output.write_text(slice_result.model_dump_json(indent=2) + "\n", encoding="utf-8")
            print(output)
            return 10 if slice_result.truncated else 0
        analysis_root = _project_scoped_path(root, args.analysis)
        flow_report = FlowAnalysisReport.model_validate_json(
            (analysis_root / "report.json").read_text(encoding="utf-8")
        )
        print(flow_report.model_dump_json(indent=2))
        return 0

    if args.command == "revalidation":
        if args.revalidation_command == "prepare":
            run_root = prepare_revalidation(
                root, _project_scoped_path(root, args.template), args.run_id
            )
            print(run_root)
            return 0
        if args.revalidation_command == "live":
            report = launch_live_revalidation(
                root,
                _project_scoped_path(root, args.run_root),
                authorized=args.authorize_live,
            )
            print(json.dumps(report, indent=2, sort_keys=True, default=str))
            return int(report.get("exit_code", 30))
        report = offline_revalidation(
            root,
            _project_scoped_path(root, args.run_root),
            _project_scoped_path(root, args.collection) if args.collection else None,
            _project_scoped_path(root, args.library) if args.library else None,
            _project_scoped_path(root, args.bridge_responses) if args.bridge_responses else None,
        )
        print(json.dumps(report, indent=2, sort_keys=True, default=str))
        return int(report.get("exit_code", 30))

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
            collection = _project_scoped_path(root, args.collection)
            if args.output is None:
                print(mine_sample_collection(root, collection))
            else:
                print(
                    mine_sample_collection(
                        root,
                        collection,
                        output_root=_project_scoped_path(root, args.output),
                    )
                )
            return 0
        if args.sample_command == "admission":
            report = audit_construction_collection(
                _project_scoped_path(root, args.collection),
                _project_scoped_path(root, args.library),
            )
            print(json.dumps(report, indent=2))
            return 0 if report.get("structural_admission", {}).get("status") == "passed" else 10
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
            _resolve_safeclaw_task_path(root, upstream, args.task),
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
