from __future__ import annotations

import json
from pathlib import Path

import pytest

import stac_attack_lab.execution.sample_generation as sample_generation
from stac_attack_lab import cli as cli_module
from stac_attack_lab.datasets.library import (
    PrimitiveChainLibrary,
    audit_primitive_library,
    freeze_primitive_library,
)
from stac_attack_lab.execution.sample_generation import (
    SampleGenerationConfig,
    SampleLibraryAuditReport,
    audit_sample_library_stage,
    build_sample_library,
    collect_sample_interactions,
    freeze_audited_sample_library,
    load_sample_generation_config,
    mine_sample_collection,
)

ROOT = Path(__file__).resolve().parents[2]


def _build(tmp_path: Path, version: str = "formal-test-v1") -> Path:
    base = load_sample_generation_config(ROOT / "tests/fixtures/sample_generation.json")
    config = base.model_copy(
        update={
            "library_version": version,
            "output_root": str(tmp_path / "generated"),
        }
    )
    assert isinstance(config, SampleGenerationConfig)
    return build_sample_library(ROOT, config)


def test_raw_to_library_build_has_physically_separated_views(tmp_path: Path) -> None:
    library_path = _build(tmp_path)
    assert audit_primitive_library(library_path) == []
    library = PrimitiveChainLibrary(library_path)
    public = library.public_index()

    assert library.manifest.accepted_count == 6
    assert library.manifest.negative_count == 0
    assert library.manifest.attempted_count == 2
    assert library.manifest.blocked_count == 1
    assert len(public) == 6
    sample_id = public[0].sample_id
    public_payload = (library_path / "planner_public_index.jsonl").read_text(encoding="utf-8")
    assert "private_oracle" not in public_payload
    assert "snapshot:memory-post" not in public_payload
    assert "occ-" not in public_payload
    assert "prompt" not in public_payload.lower()
    execution_payload = (library_path / "execution_views.jsonl").read_text(encoding="utf-8")
    assert "prompt" not in execution_payload.lower()
    assert "SYNTHETIC_MARKER" not in execution_payload
    accepted_payload = (library_path / "accepted_samples.jsonl").read_text(encoding="utf-8")
    assert '"planner_view":' not in accepted_payload
    assert '"execution_view":' not in accepted_payload
    assert '"private_evidence_view":' not in accepted_payload
    assert "snapshot:memory-post" not in accepted_payload
    assert library.execution_view(sample_id).sample_id == sample_id
    assert "snapshot:memory-post" in library.private_evidence_view(sample_id).hard_verifier_refs


def test_library_audit_detects_tampering_before_loading(tmp_path: Path) -> None:
    library_path = _build(tmp_path)
    public_path = library_path / "planner_public_index.jsonl"
    public_path.write_text(
        public_path.read_text(encoding="utf-8").replace("Authorized", "Changed"),
        encoding="utf-8",
    )

    assert audit_primitive_library(library_path) == [
        "library_content_hash_mismatch:planner_public_index.jsonl"
    ]
    with pytest.raises(ValueError, match="primitive_library_audit_failed"):
        PrimitiveChainLibrary(library_path)


def test_freeze_is_atomic_immutable_and_idempotent(tmp_path: Path) -> None:
    version = "formal-freeze-v1"
    library_path = _build(tmp_path, version=version)
    project_root = tmp_path / "project"
    first = freeze_primitive_library(library_path, version, project_root)
    second = freeze_primitive_library(library_path, version, project_root)
    manifest = json.loads((first / "library_manifest.json").read_text(encoding="utf-8"))

    assert first == second
    assert manifest["frozen"] is True
    assert audit_primitive_library(first) == []
    with pytest.raises(ValueError, match="library_version_does_not_match_freeze_target"):
        freeze_primitive_library(library_path, "different-version", project_root)


def test_test_split_is_rejected_before_collection(tmp_path: Path) -> None:
    base = load_sample_generation_config(ROOT / "tests/fixtures/sample_generation.json")
    config = base.model_copy(
        update={
            "allowed_source_splits": ["test"],
            "output_root": str(tmp_path / "generated"),
        }
    )
    with pytest.raises(ValueError, match="formal_test_split"):
        build_sample_library(ROOT, config)


def test_explicit_sample_stages_are_hash_bound_resume_safe_and_model_free(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    version = "formal-explicit-stages-v1"
    base = load_sample_generation_config(ROOT / "tests/fixtures/sample_generation.json")
    config = base.model_copy(
        update={
            "library_version": version,
            "output_root": str(tmp_path / "generated"),
        }
    )
    collection_root = collect_sample_interactions(ROOT, config)
    collection_stage = collection_root / "collection_stage_manifest.json"
    assert collection_stage.is_file()

    def reject_collection_components(*args: object, **kwargs: object) -> object:
        del args, kwargs
        raise AssertionError("post-collection stage initialized collection components")

    monkeypatch.setattr(
        sample_generation,
        "_collection_components",
        reject_collection_components,
    )
    assert collect_sample_interactions(ROOT, config) == collection_root
    library_root = mine_sample_collection(ROOT, collection_root)
    mining_manifest = library_root.parent / "mining_stage_manifest.json"
    first_mining_manifest = mining_manifest.read_bytes()

    assert mine_sample_collection(ROOT, collection_root) == library_root
    assert mining_manifest.read_bytes() == first_mining_manifest
    report = audit_sample_library_stage(library_root)
    assert report.passed is True
    assert report.library_tree_hash
    assert report.mining_manifest_hash

    project_root = tmp_path / "freeze-project"
    frozen = freeze_audited_sample_library(library_root, version, project_root)
    assert frozen == project_root / "data/primitive_libraries/frozen" / version
    assert audit_primitive_library(frozen) == []


def test_mining_rejects_tampered_collection(tmp_path: Path) -> None:
    base = load_sample_generation_config(ROOT / "tests/fixtures/sample_generation.json")
    config = base.model_copy(
        update={
            "library_version": "formal-tampered-collection-v1",
            "output_root": str(tmp_path / "generated"),
        }
    )
    collection_root = collect_sample_interactions(ROOT, config)
    source_events = next(collection_root.glob("trajectories/*/source_events.jsonl"))
    source_events.write_text(
        source_events.read_text(encoding="utf-8") + "{}\n",
        encoding="utf-8",
    )

    with pytest.raises(ValueError, match="sample_collection_content_hash_mismatch"):
        mine_sample_collection(ROOT, collection_root)


def test_freeze_requires_current_explicit_audit_report(tmp_path: Path) -> None:
    version = "formal-audit-gated-freeze-v1"
    base = load_sample_generation_config(ROOT / "tests/fixtures/sample_generation.json")
    config = base.model_copy(
        update={
            "library_version": version,
            "output_root": str(tmp_path / "generated"),
        }
    )
    collection_root = collect_sample_interactions(ROOT, config)
    library_root = mine_sample_collection(ROOT, collection_root)

    with pytest.raises(ValueError, match="sample_library_audit_report_missing"):
        freeze_audited_sample_library(library_root, version, tmp_path / "project")

    audit_sample_library_stage(library_root)
    public_path = library_root / "planner_public_index.jsonl"
    public_path.write_text(
        public_path.read_text(encoding="utf-8").replace("Authorized", "Changed"),
        encoding="utf-8",
    )
    with pytest.raises(ValueError, match="sample_library_audit_report_stale"):
        freeze_audited_sample_library(library_root, version, tmp_path / "project")


def test_audit_and_freeze_require_preregistered_accepted_sample_target(
    tmp_path: Path,
) -> None:
    version = "formal-target-gate-v1"
    base = load_sample_generation_config(ROOT / "tests/fixtures/sample_generation.json")
    config = base.model_copy(
        update={
            "library_version": version,
            "output_root": str(tmp_path / "generated"),
            "target_accepted_samples": 7,
        }
    )
    collection_root = collect_sample_interactions(ROOT, config)
    library_root = mine_sample_collection(ROOT, collection_root)

    report = audit_sample_library_stage(library_root)

    assert report.passed is False
    assert report.error_codes == ["accepted_sample_target_not_met:6:7"]
    with pytest.raises(ValueError, match="accepted_sample_target_not_met:6:7"):
        freeze_audited_sample_library(library_root, version, tmp_path / "project")


def test_sample_stage_cli_routes_project_scoped_paths(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root = tmp_path / "project"
    collection_root = root / "generated/collection"
    library_root = root / "generated/library"
    collection_root.mkdir(parents=True)
    library_root.mkdir(parents=True)
    calls: list[tuple[str, Path]] = []
    monkeypatch.setattr(cli_module, "project_root", lambda: root)
    monkeypatch.setattr(cli_module, "load_project_env", lambda value: None)
    monkeypatch.setattr(
        cli_module,
        "mine_sample_collection",
        lambda project, collection: (
            calls.append(("mine", collection)),
            library_root,
        )[1],
    )
    monkeypatch.setattr(
        cli_module,
        "audit_sample_library_stage",
        lambda library: (
            calls.append(("audit", library)),
            SampleLibraryAuditReport(
                library_tree_hash="tree-hash",
                mining_manifest_hash="mining-hash",
                passed=True,
            ),
        )[1],
    )
    monkeypatch.setattr(
        cli_module,
        "freeze_audited_sample_library",
        lambda library, version, project: (
            calls.append(("freeze", library)),
            project / "data/primitive_libraries/frozen" / version,
        )[1],
    )

    assert cli_module._main(["sample", "mine", "--collection", "generated/collection"]) == 0
    assert cli_module._main(["sample", "audit", "--library", "generated/library"]) == 0
    assert (
        cli_module._main(["sample", "freeze", "--library", "generated/library", "--version", "v1"])
        == 0
    )
    assert calls == [
        ("mine", collection_root.resolve()),
        ("audit", library_root.resolve()),
        ("freeze", library_root.resolve()),
    ]
    with pytest.raises(ValueError, match="path_outside_project_root"):
        cli_module._main(["sample", "mine", "--collection", "../outside"])
