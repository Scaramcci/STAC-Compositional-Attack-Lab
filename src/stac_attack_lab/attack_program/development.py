"""Bounded offline development attempts, sealed replay and synthetic engineering library."""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any

from stac_attack_lab.attack_program.models import (
    AttackCandidate,
    Catalog,
    DevelopmentInput,
    LibraryManifest,
    RawExampleView,
    RawObservation,
    Split,
    StructuredExampleView,
    TaskEntry,
)
from stac_attack_lab.attack_program.observation import (
    RULE_VERSION,
    independent_verdict,
    official_checks,
    validate_graph,
)
from stac_attack_lab.attack_program.pipeline import (
    GateError,
    _read,
    build_catalog,
    make_split,
    materialize,
    validate_catalog,
    validate_split,
)
from stac_attack_lab.attack_program.redaction import scan_for_secrets
from stac_attack_lab.hashing import file_hash, stable_hash

VERSION = "attack-development/1"
LIBRARY_VERSION = "primitive-attack-library/1"


def _read_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def _write(path: Path, value: Any, *, private: bool = False) -> None:
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600 if private else 0o644)
    with os.fdopen(fd, "w", encoding="utf-8") as stream:
        json.dump(value, stream, ensure_ascii=False, indent=2)
        stream.write("\n")


def _new(path: Path) -> None:
    path.mkdir(parents=True, mode=0o700, exist_ok=False)


def _entry(catalog: Catalog, task_id: str) -> TaskEntry | None:
    return next((e for e in catalog.entries if e.task_id == task_id), None)


def _decision(
    candidate: AttackCandidate,
    observation: RawObservation | None,
    root: Path,
    catalog: Catalog,
    split: Split,
    attempt_id: str,
) -> tuple[dict[str, Any], dict[str, Any] | None]:
    base: dict[str, Any] = {
        "attempt_id": attempt_id,
        "candidate_id": candidate.candidate_id,
        "task_id": candidate.task_id,
        "task_group_id": candidate.task_group_id,
        "source_split": candidate.source_split,
        "status": "not_started",
        "reason_codes": [],
        "execution_source": observation.source if observation else None,
        "evidence_class": "unexecuted",
        "official": None,
        "independent": None,
        "occurrences": [],
        "relations": [],
        "materialized_hash": None,
    }
    try:
        task = materialize(root, catalog, split, candidate)
    except GateError as exc:
        base.update(
            status="invalid_candidate", reason_codes=[str(exc)], evidence_class="unexecuted"
        )
        return base, None
    base["materialized_hash"] = stable_hash(task)
    if observation is None:
        base.update(
            status="incomplete",
            reason_codes=["observation_missing"],
            evidence_class="feasibility_only",
        )
        return base, task
    if (
        observation.candidate_id != candidate.candidate_id
        or observation.task_id != candidate.task_id
    ):
        base.update(
            status="error",
            reason_codes=["observation_identity_mismatch"],
            evidence_class="indeterminate",
        )
        return base, task
    if observation.schema_version == "attack-observation/2" and (
        observation.materialized_task_hash != base["materialized_hash"]
    ):
        base.update(
            status="error",
            reason_codes=["observation_materialized_hash_mismatch"],
            evidence_class="indeterminate",
        )
        return base, task
    official = official_checks(root, task, observation)
    independent, occurrences, relations = independent_verdict(task, observation, official)
    validate_graph(occurrences, relations, observation)
    base["official"] = official
    base["independent"] = independent
    base["occurrences"] = [x.model_dump(mode="json") for x in occurrences]
    base["relations"] = [x.model_dump(mode="json") for x in relations]
    if official["status"] != "evaluated":
        base.update(
            status="incomplete",
            reason_codes=official["reason_codes"],
            evidence_class="indeterminate",
        )
    else:
        harm = independent["harm"]
        classification = (
            "verified_success"
            if harm.startswith("observed_harm")
            else "verified_negative"
            if harm.startswith("observed_safe")
            else "promising"
            if any(n["status"] == "observed" for n in base["occurrences"])
            else "indeterminate"
        )
        if observation.source != "real" and classification.startswith("verified"):
            classification += "_synthetic"
        base.update(status="completed", evidence_class=classification)
    return base, task


def _provenance(root: Path) -> dict[str, str]:
    names = [
        "src/stac_attack_lab/attack_program/development.py",
        "src/stac_attack_lab/attack_program/observation.py",
        "src/stac_attack_lab/attack_program/pipeline.py",
        "src/stac_attack_lab/attack_program/models.py",
        "src/stac_attack_lab/attack_program/redaction.py",
    ]
    return {name: file_hash(root / name) for name in names}


def _not_started(candidate: AttackCandidate, attempt_id: str) -> dict[str, Any]:
    return {
        "attempt_id": attempt_id,
        "candidate_id": candidate.candidate_id,
        "status": "not_started",
        "reason_codes": ["attempt_budget_exhausted"],
        "evidence_class": "unexecuted",
        "execution_source": None,
        "task_id": candidate.task_id,
        "task_group_id": candidate.task_group_id,
        "source_split": candidate.source_split,
        "official": None,
        "independent": None,
        "occurrences": [],
        "relations": [],
        "materialized_hash": None,
    }


def develop(root: Path, configuration: DevelopmentInput, output: Path) -> dict[str, Any]:
    if configuration.source == "real":
        raise GateError("real_source_requires_sealed_runtime_adapter")
    catalog = build_catalog(root)
    split = make_split(catalog)
    validate_catalog(catalog, root)
    validate_split(split, catalog)
    if configuration.max_candidates < 1 or configuration.max_attempts < 1:
        raise GateError("development_limits_invalid")
    if not configuration.candidates or len(configuration.candidates) > configuration.max_candidates:
        raise GateError("development_candidate_count_invalid")
    ids = [c.candidate_id for c in configuration.candidates]
    if len(ids) != len(set(ids)) or any(not x or "/" in x or ".." in x for x in ids):
        raise GateError("development_candidate_identity_invalid")
    if any(c.task_id != configuration.task_id for c in configuration.candidates):
        raise GateError("development_task_mismatch")
    if any(c.source_split != "development" for c in configuration.candidates):
        raise GateError("development_split_required")
    if any(o.source != configuration.source for o in configuration.observations.values()):
        raise GateError("development_source_mismatch")
    if set(configuration.observations) - set(ids):
        raise GateError("observation_without_candidate")
    entry = _entry(catalog, configuration.task_id)
    if entry is None or split.group_assignments.get(entry.template_group_id) != "development":
        raise GateError("development_task_not_assigned")
    _new(output)
    private = output / "private"
    _new(private)
    records: list[dict[str, Any]] = []
    files: dict[str, str] = {}

    def sealed(name: str, value: Any) -> None:
        path = private / name
        _write(path, value, private=True)
        files[f"private/{name}"] = file_hash(path)

    sealed("catalog.json", catalog.model_dump(mode="json"))
    sealed("split.json", split.model_dump(mode="json"))
    sealed("configuration.json", configuration.model_dump(mode="json"))
    for index, candidate in enumerate(configuration.candidates):
        attempt_id = f"attempt-{index + 1:04d}"
        observation = configuration.observations.get(candidate.candidate_id)
        sealed(f"{attempt_id}.candidate.json", candidate.model_dump(mode="json"))
        if observation is not None:
            sealed(f"{attempt_id}.observation.json", observation.model_dump(mode="json"))
        if index >= configuration.max_attempts:
            record = _not_started(candidate, attempt_id)
            task = None
        else:
            record, task = _decision(candidate, observation, root, catalog, split, attempt_id)
        if task is not None:
            sealed(f"{attempt_id}.task.json", task)
        sealed(f"{attempt_id}.result.json", record)
        records.append(record)
    manifest = {
        "schema_version": VERSION,
        "scope": "offline_development",
        "source": configuration.source,
        "task_id": configuration.task_id,
        "catalog_hash": catalog.catalog_hash,
        "split_hash": split.split_hash,
        "assigned_candidate_ids": ids,
        "attempt_ids": [r["attempt_id"] for r in records],
        "attempt_denominator": len(ids),
        "files": files,
        "rule_version": RULE_VERSION,
        "processing_sources": _provenance(root),
    }
    manifest["manifest_hash"] = stable_hash(manifest)
    _write(output / "manifest.json", manifest)
    summary = _summary(records)
    _write(output / "report.json", summary)
    return summary


def _summary(records: list[dict[str, Any]]) -> dict[str, Any]:
    return {
        "schema_version": "attack-development-report/1",
        "scope": "offline_synthetic_engineering_only",
        "assigned": len(records),
        "statuses": {
            name: sum(r["status"] == name for r in records)
            for name in ("not_started", "invalid_candidate", "incomplete", "error", "completed")
        },
        "evidence_classes": {
            name: sum(r["evidence_class"] == name for r in records)
            for name in sorted({r["evidence_class"] for r in records})
        },
        "attempts": [
            {
                "attempt_id": r["attempt_id"],
                "candidate_id": r["candidate_id"],
                "status": r["status"],
                "reason_codes": r["reason_codes"],
                "evidence_class": r["evidence_class"],
                "official_success": ((r["official"] or {}).get("score") or {}).get(
                    "attack_succeeded"
                ),
                "independent_harm": (r["independent"] or {}).get("harm", "unknown"),
            }
            for r in records
        ],
    }


def replay(root: Path, run: Path, output: Path, *, compare: bool = False) -> dict[str, Any]:
    manifest = _read(run / "manifest.json")
    check_hash = stable_hash({k: v for k, v in manifest.items() if k != "manifest_hash"})
    if manifest.get("schema_version") != VERSION or manifest.get("manifest_hash") != check_hash:
        raise GateError("development_manifest_invalid")
    if manifest.get("processing_sources") != _provenance(root):
        raise GateError("development_processing_source_mismatch")
    files = manifest.get("files")
    if not isinstance(files, dict):
        raise GateError("development_file_index_invalid")
    for relative, expected_hash in files.items():
        if not isinstance(relative, str) or not relative.startswith("private/") or ".." in relative:
            raise GateError("development_file_path_invalid")
        path = run / relative
        if not path.is_file() or file_hash(path) != expected_hash:
            raise GateError("development_file_hash_mismatch")
    catalog = Catalog.model_validate(_read(run / "private/catalog.json"))
    split = Split.model_validate(_read(run / "private/split.json"))
    configuration = DevelopmentInput.model_validate(_read(run / "private/configuration.json"))
    if configuration.source != manifest["source"] or configuration.task_id != manifest["task_id"]:
        raise GateError("development_source_or_task_mismatch")
    validate_catalog(catalog, root)
    validate_split(split, catalog)
    if (
        manifest["catalog_hash"] != catalog.catalog_hash
        or manifest["split_hash"] != split.split_hash
    ):
        raise GateError("development_catalog_split_mismatch")
    ids = [c.candidate_id for c in configuration.candidates]
    if ids != manifest["assigned_candidate_ids"] or len(ids) != manifest["attempt_denominator"]:
        raise GateError("development_denominator_mismatch")
    if manifest["attempt_ids"] != [f"attempt-{i + 1:04d}" for i in range(len(ids))]:
        raise GateError("development_attempt_index_mismatch")
    expected_files = {"private/catalog.json", "private/split.json", "private/configuration.json"}
    records: list[dict[str, Any]] = []
    for index, candidate in enumerate(configuration.candidates):
        aid = f"attempt-{index + 1:04d}"
        expected_files.update({f"private/{aid}.candidate.json", f"private/{aid}.result.json"})
        actual_candidate = AttackCandidate.model_validate(
            _read(run / f"private/{aid}.candidate.json")
        )
        if actual_candidate != candidate:
            raise GateError("development_candidate_semantics_mismatch")
        observation = configuration.observations.get(candidate.candidate_id)
        if observation is not None:
            expected_files.add(f"private/{aid}.observation.json")
            actual_observation = RawObservation.model_validate(
                _read(run / f"private/{aid}.observation.json")
            )
            if actual_observation != observation:
                raise GateError("development_observation_semantics_mismatch")
        if index >= configuration.max_attempts:
            record = _not_started(candidate, aid)
        else:
            record, task = _decision(candidate, observation, root, catalog, split, aid)
            if task is not None:
                expected_files.add(f"private/{aid}.task.json")
                if _read(run / f"private/{aid}.task.json") != task:
                    raise GateError("development_materialization_mismatch")
        if compare and _read(run / f"private/{aid}.result.json") != record:
            raise GateError("development_result_semantics_mismatch")
        records.append(record)
    if set(files) != expected_files:
        raise GateError("development_file_set_mismatch")
    if compare and _read(run / "report.json") != _summary(records):
        raise GateError("development_report_mismatch")
    _new(output)
    result = _summary(records)
    result["replay_of"] = str(run)
    result["source_manifest_hash"] = manifest["manifest_hash"]
    _write(output / "report.json", result)
    return result


def freeze_synthetic(root: Path, run: Path, output: Path) -> dict[str, Any]:
    if output.exists():
        raise GateError("library_output_exists")
    # Semantic audit first, in a fresh derived directory.
    audit_dir = output.parent / (output.name + "-preaudit")
    replay(root, run, audit_dir, compare=True)
    manifest = _read(run / "manifest.json")
    if manifest["source"] == "real":
        raise GateError("synthetic_library_requires_synthetic_source")
    catalog = Catalog.model_validate(_read(run / "private/catalog.json"))
    split = Split.model_validate(_read(run / "private/split.json"))
    records = [_read(run / f"private/{aid}.result.json") for aid in manifest["attempt_ids"]]
    config = DevelopmentInput.model_validate(_read(run / "private/configuration.json"))
    if any(c.source_split != "development" for c in config.candidates):
        raise GateError("library_requires_development_split")
    raw: list[dict[str, Any]] = []
    structured: list[dict[str, Any]] = []
    private: list[dict[str, Any]] = []
    for candidate, record in zip(config.candidates, records, strict=True):
        if record["status"] != "completed" or record["evidence_class"] in {
            "unexecuted",
            "indeterminate",
        }:
            continue
        value = candidate.patches[0].value
        if scan_for_secrets(value) or "CANARY_" in value:
            raise GateError("library_public_secret_scan_failed")
        sid = stable_hash(
            {
                "candidate_id": candidate.candidate_id,
                "attempt_id": record["attempt_id"],
                "materialized_hash": record["materialized_hash"],
            }
        )[:24]
        common = {
            "sample_id": sid,
            "source_task_group_id": candidate.task_group_id,
            "source_split": "development",
            "validation_class": record["evidence_class"],
            "raw_example": value,
        }
        raw.append(
            RawExampleView.model_validate({**common, "view": "raw_examples"}).model_dump(
                mode="json"
            )
        )
        structured.append(
            StructuredExampleView.model_validate(
                {
                    **common,
                    "view": "primitive_examples",
                    "occurrences": record["occurrences"],
                    "relations": record["relations"],
                    "primitive_status": record["independent"]["primitive_evidence"],
                    "preconditions": ["audited mirrored low-trust email surface"],
                    "evidence_boundary": "synthetic runtime fixture; no real victim success",
                }
            ).model_dump(mode="json")
        )
        private.append(
            {
                "sample_id": sid,
                "attempt_id": record["attempt_id"],
                "candidate_id": candidate.candidate_id,
                "official": record["official"],
                "independent": record["independent"],
            }
        )
    if [x["sample_id"] for x in raw] != [x["sample_id"] for x in structured]:
        raise GateError("library_view_id_mismatch")
    _new(output)
    _new(output / "private")
    _write(output / "raw.json", raw)
    _write(output / "structured.json", structured)
    _write(output / "private/evidence.json", private, private=True)
    lib = {
        "schema_version": LIBRARY_VERSION,
        "scope": "synthetic_only",
        "library_id": stable_hash({"run": manifest["manifest_hash"], "policy": "synthetic-only/1"})[
            :24
        ],
        "source_run": str(run.resolve()),
        "source_manifest_hash": manifest["manifest_hash"],
        "catalog_hash": catalog.catalog_hash,
        "split_hash": split.split_hash,
        "attempt_denominator": manifest["attempt_denominator"],
        "attempt_ids": manifest["attempt_ids"],
        "sample_ids": [x["sample_id"] for x in raw],
        "policy": "synthetic-only/1",
        "rule_version": RULE_VERSION,
        "file_hashes": {
            name: file_hash(output / name)
            for name in ("raw.json", "structured.json", "private/evidence.json")
        },
    }
    lib["manifest_hash"] = stable_hash(lib)
    LibraryManifest.model_validate(lib)
    _write(output / "manifest.json", lib)
    return lib


def audit_library(root: Path, library: Path, output: Path) -> dict[str, Any]:
    lib = _read(library / "manifest.json")
    LibraryManifest.model_validate(lib)
    if lib.get("scope") != "synthetic_only" or lib.get("schema_version") != LIBRARY_VERSION:
        raise GateError("library_scope_or_version_invalid")
    if stable_hash({k: v for k, v in lib.items() if k != "manifest_hash"}) != lib.get(
        "manifest_hash"
    ):
        raise GateError("library_manifest_hash_mismatch")
    source = Path(lib["source_run"])
    if source.resolve() == library.resolve():
        raise GateError("library_source_self_reference")
    replay(root, source, output.parent / (output.name + "-source-audit"), compare=True)
    expected = output.parent / (output.name + "-rebuild")
    rebuilt = freeze_synthetic(root, source, expected)
    for name in ("raw.json", "structured.json", "private/evidence.json"):
        if file_hash(library / name) != lib["file_hashes"].get(name) or _read_json(
            library / name
        ) != _read_json(expected / name):
            raise GateError("library_view_semantics_mismatch")
    if {k: v for k, v in lib.items() if k != "source_run"} != {
        k: v for k, v in rebuilt.items() if k != "source_run"
    }:
        raise GateError("library_manifest_semantics_mismatch")
    if lib["sample_ids"] != [x["sample_id"] for x in _read_json(library / "raw.json")]:
        raise GateError("library_member_index_mismatch")
    _new(output)
    report = {
        "status": "valid",
        "scope": "synthetic_only",
        "sample_count": len(lib["sample_ids"]),
        "attempt_denominator": lib["attempt_denominator"],
        "library_id": lib["library_id"],
    }
    _write(output / "report.json", report)
    return report
