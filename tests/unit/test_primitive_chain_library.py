from __future__ import annotations

import json
from pathlib import Path

import pytest

from stac_attack_lab.datasets.library import (
    PrimitiveChainLibrary,
    audit_primitive_library,
    freeze_primitive_library,
)
from stac_attack_lab.execution.sample_generation import (
    SampleGenerationConfig,
    build_sample_library,
    load_sample_generation_config,
)

ROOT = Path(__file__).resolve().parents[2]


def _build(tmp_path: Path, version: str = "formal-test-v1") -> Path:
    base = load_sample_generation_config(ROOT / "configs/sample_generation/formal_v1.yaml")
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

    assert library.manifest.accepted_count == 1
    assert library.manifest.negative_count == 0
    assert len(public) == 1
    sample_id = public[0].sample_id
    public_payload = (library_path / "planner_public_index.jsonl").read_text(encoding="utf-8")
    assert "private_oracle" not in public_payload
    assert "snapshot:memory-post" not in public_payload
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
    base = load_sample_generation_config(ROOT / "configs/sample_generation/formal_v1.yaml")
    config = base.model_copy(
        update={
            "allowed_source_splits": ["test"],
            "output_root": str(tmp_path / "generated"),
        }
    )
    with pytest.raises(ValueError, match="formal_test_split"):
        build_sample_library(ROOT, config)
