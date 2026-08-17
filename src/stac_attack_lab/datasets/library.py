from __future__ import annotations

import json
import shutil
import tempfile
from collections.abc import Sequence
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, TypeVar

from pydantic import BaseModel

from stac_attack_lab.datasets.chain_builder import (
    build_primitive_chain_sample,
    calculate_sample_hash,
)
from stac_attack_lab.datasets.primitive_chain import (
    ExecutionBindingView,
    PlannerSampleView,
    PrimitiveChainCandidate,
    PrimitiveChainSample,
    PrivateEvidenceView,
    SampleLibraryManifest,
)
from stac_attack_lab.extraction.filtering import CandidateFilterRecord
from stac_attack_lab.hashing import file_hash, stable_hash
from stac_attack_lab.interactions.models import PrimitiveOccurrence
from stac_attack_lab.planning.formal_base import PublicSampleIndexEntry
from stac_attack_lab.primitives.formal_registry import FormalPrimitiveRegistry

ModelT = TypeVar("ModelT", bound=BaseModel)

LIBRARY_FILES = (
    "candidates.jsonl",
    "accepted_samples.jsonl",
    "negative_samples.jsonl",
    "filter_decisions.jsonl",
    "planner_public_index.jsonl",
    "execution_views.jsonl",
    "private_evidence.jsonl",
)

PUBLIC_FORBIDDEN_KEYS = (
    "private_oracle",
    "canary_id",
    "success_condition",
    "safe_condition",
    "api_key",
    "authorization",
    "password",
    "secret",
)


def _atomic_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(json.dumps(value, indent=2, sort_keys=True), encoding="utf-8")
    temporary.replace(path)


def _atomic_jsonl(path: Path, values: Sequence[BaseModel]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(
        "".join(item.model_dump_json() + "\n" for item in values), encoding="utf-8"
    )
    temporary.replace(path)


def _load_jsonl(path: Path, model: type[ModelT]) -> list[ModelT]:
    values: list[ModelT] = []
    for line_number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
        if not line.strip():
            continue
        try:
            values.append(model.model_validate_json(line))
        except Exception as exc:
            raise ValueError(f"schema_error:{path.name}:{line_number}:{exc}") from exc
    return values


def _content_hashes(path: Path) -> dict[str, str]:
    return {name: file_hash(path / name) for name in LIBRARY_FILES}


def build_primitive_chain_library(
    output_dir: Path,
    *,
    accepted_candidates: list[PrimitiveChainCandidate],
    negative_candidates: list[PrimitiveChainCandidate],
    filter_records: list[CandidateFilterRecord],
    occurrences_by_graph_id: dict[str, list[PrimitiveOccurrence]],
    registry: FormalPrimitiveRegistry,
    library_id: str,
    library_version: str,
    formal_exclusion_hash: str,
) -> Path:
    output_dir.mkdir(parents=True, exist_ok=True)
    samples = [
        build_primitive_chain_sample(
            candidate,
            occurrences_by_graph_id[candidate.interaction_graph_id],
            registry,
            library_version=library_version,
        )
        for candidate in accepted_candidates
    ]
    _atomic_jsonl(output_dir / "candidates.jsonl", [*accepted_candidates, *negative_candidates])
    _atomic_jsonl(output_dir / "accepted_samples.jsonl", samples)
    _atomic_jsonl(output_dir / "negative_samples.jsonl", negative_candidates)
    _atomic_jsonl(output_dir / "filter_decisions.jsonl", filter_records)
    _atomic_jsonl(
        output_dir / "planner_public_index.jsonl", [sample.planner_view for sample in samples]
    )
    _atomic_jsonl(
        output_dir / "execution_views.jsonl", [sample.execution_view for sample in samples]
    )
    _atomic_jsonl(
        output_dir / "private_evidence.jsonl",
        [sample.private_evidence_view for sample in samples],
    )
    content_hashes = _content_hashes(output_dir)
    split_summary: dict[str, int] = {}
    for sample in samples:
        split_summary[sample.source_split] = split_summary.get(sample.source_split, 0) + 1
    manifest = SampleLibraryManifest(
        library_id=library_id,
        library_version=library_version,
        registry_version=registry.registry_version,
        registry_hash=registry.registry_hash,
        observation_schema_version=registry.observable_projection_version,
        construction_pipeline_version="formal-sample-generation-v1",
        source_split_summary=split_summary,
        formal_exclusion_hash=formal_exclusion_hash,
        filter_policy_hash=stable_hash(
            [record.model_dump(mode="json") for record in filter_records]
        ),
        accepted_count=len(samples),
        negative_count=len(negative_candidates),
        candidate_count=len(accepted_candidates) + len(negative_candidates),
        content_hashes=content_hashes,
        tree_hash=stable_hash(content_hashes),
        frozen=False,
        created_at=datetime.now(UTC).isoformat(),
    )
    _atomic_json(output_dir / "library_manifest.json", manifest.model_dump(mode="json"))
    errors = audit_primitive_library(output_dir)
    if errors:
        raise ValueError("primitive_library_audit_failed:" + ",".join(errors))
    return output_dir


def audit_primitive_library(path: Path) -> list[str]:
    errors: list[str] = []
    manifest_path = path / "library_manifest.json"
    if not manifest_path.is_file():
        return ["missing_library_manifest"]
    try:
        manifest = SampleLibraryManifest.model_validate_json(
            manifest_path.read_text(encoding="utf-8")
        )
    except Exception as exc:
        return [f"library_manifest_schema_error:{exc}"]
    for name in LIBRARY_FILES:
        file_path = path / name
        if not file_path.is_file():
            errors.append(f"missing_library_file:{name}")
            continue
        expected = manifest.content_hashes.get(name)
        if expected is None or file_hash(file_path) != expected:
            errors.append(f"library_content_hash_mismatch:{name}")
    if errors:
        return errors
    if stable_hash(manifest.content_hashes) != manifest.tree_hash:
        errors.append("library_tree_hash_mismatch")
    try:
        samples = _load_jsonl(path / "accepted_samples.jsonl", PrimitiveChainSample)
        negatives = _load_jsonl(path / "negative_samples.jsonl", PrimitiveChainCandidate)
        candidates = _load_jsonl(path / "candidates.jsonl", PrimitiveChainCandidate)
        public_views = _load_jsonl(path / "planner_public_index.jsonl", PlannerSampleView)
        execution_views = _load_jsonl(path / "execution_views.jsonl", ExecutionBindingView)
        private_views = _load_jsonl(path / "private_evidence.jsonl", PrivateEvidenceView)
        records = _load_jsonl(path / "filter_decisions.jsonl", CandidateFilterRecord)
    except ValueError as exc:
        return [str(exc)]
    if len(samples) != manifest.accepted_count:
        errors.append("accepted_count_mismatch")
    if len(negatives) != manifest.negative_count:
        errors.append("negative_count_mismatch")
    if len(candidates) != manifest.candidate_count:
        errors.append("candidate_count_mismatch")
    if len(records) != manifest.candidate_count:
        errors.append("filter_record_count_mismatch")
    sample_ids = [sample.sample_id for sample in samples]
    if len(sample_ids) != len(set(sample_ids)):
        errors.append("duplicate_sample_id")
    for sample in samples:
        if calculate_sample_hash(sample) != sample.sample_hash:
            errors.append(f"sample_hash_mismatch:{sample.sample_id}")
        if sample.registry_hash != manifest.registry_hash:
            errors.append(f"sample_registry_hash_mismatch:{sample.sample_id}")
        if sample.source_split == "test":
            errors.append(f"formal_test_source_leak:{sample.sample_id}")
        if not all(decision.passed for decision in sample.validation.gate_decisions):
            errors.append(f"unaccepted_sample_in_accepted_pool:{sample.sample_id}")
    expected_ids = set(sample_ids)
    view_sets = {
        "public": {item.sample_id for item in public_views},
        "execution": {item.sample_id for item in execution_views},
        "private": {item.sample_id for item in private_views},
    }
    for name, view_ids in view_sets.items():
        if view_ids != expected_ids:
            errors.append(f"{name}_view_identity_mismatch")
    public_payload = (path / "planner_public_index.jsonl").read_text(encoding="utf-8").lower()
    for forbidden in PUBLIC_FORBIDDEN_KEYS:
        if forbidden in public_payload:
            errors.append(f"planner_public_view_forbidden_field:{forbidden}")
    return errors


class PrimitiveChainLibrary:
    def __init__(self, path: Path) -> None:
        errors = audit_primitive_library(path)
        if errors:
            raise ValueError("primitive_library_audit_failed:" + ",".join(errors))
        self.path = path
        self.manifest = SampleLibraryManifest.model_validate_json(
            (path / "library_manifest.json").read_text(encoding="utf-8")
        )
        self._public = {
            item.sample_id: item
            for item in _load_jsonl(path / "planner_public_index.jsonl", PlannerSampleView)
        }

    def public_index(self) -> list[PublicSampleIndexEntry]:
        sample_hashes = {
            sample.sample_id: sample.sample_hash
            for sample in _load_jsonl(self.path / "accepted_samples.jsonl", PrimitiveChainSample)
        }
        return [
            PublicSampleIndexEntry(
                sample_id=sample_id,
                sample_hash=sample_hashes[sample_id],
                planner_view=view,
            )
            for sample_id, view in sorted(self._public.items())
        ]

    def execution_view(self, sample_id: str) -> ExecutionBindingView:
        values = {
            item.sample_id: item
            for item in _load_jsonl(self.path / "execution_views.jsonl", ExecutionBindingView)
        }
        return values[sample_id]

    def private_evidence_view(self, sample_id: str) -> PrivateEvidenceView:
        values = {
            item.sample_id: item
            for item in _load_jsonl(self.path / "private_evidence.jsonl", PrivateEvidenceView)
        }
        return values[sample_id]


def freeze_primitive_library(generated_library: Path, version: str, project_root: Path) -> Path:
    errors = audit_primitive_library(generated_library)
    if errors:
        raise ValueError("primitive_library_audit_failed:" + ",".join(errors))
    manifest = SampleLibraryManifest.model_validate_json(
        (generated_library / "library_manifest.json").read_text(encoding="utf-8")
    )
    if manifest.library_version != version:
        raise ValueError("library_version_does_not_match_freeze_target")
    frozen_root = project_root / "data/primitive_libraries/frozen"
    frozen_root.mkdir(parents=True, exist_ok=True)
    target = frozen_root / version
    if target.exists():
        existing = SampleLibraryManifest.model_validate_json(
            (target / "library_manifest.json").read_text(encoding="utf-8")
        )
        if existing.frozen and existing.tree_hash == manifest.tree_hash:
            return target
        raise FileExistsError(f"frozen_primitive_library_version_exists:{version}")
    staging_parent = Path(tempfile.mkdtemp(prefix="primitive-library-", dir=frozen_root))
    staging = staging_parent / version
    try:
        shutil.copytree(generated_library, staging)
        frozen_manifest = manifest.model_copy(update={"frozen": True})
        _atomic_json(staging / "library_manifest.json", frozen_manifest.model_dump(mode="json"))
        post_copy_errors = audit_primitive_library(staging)
        if post_copy_errors:
            raise ValueError("frozen_primitive_library_audit_failed:" + ",".join(post_copy_errors))
        staging.replace(target)
    finally:
        if staging_parent.exists():
            shutil.rmtree(staging_parent)
    return target
