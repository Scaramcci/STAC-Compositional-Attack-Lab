from __future__ import annotations

import json
import shutil
from pathlib import Path

from stac_attack_lab.hashing import file_hash, stable_hash


def freeze_dataset(dataset: Path, version: str, project_root: Path) -> Path:
    target = project_root / "data/frozen" / version
    source_samples = dataset / "samples.jsonl"
    if target.exists():
        target_samples = target / "samples.jsonl"
        if target_samples.is_file() and file_hash(source_samples) == file_hash(target_samples):
            return target
        raise FileExistsError(f"frozen_dataset_version_exists:{version}")
    shutil.copytree(dataset, target)
    samples = target / "samples.jsonl"
    manifest = {
        "dataset_version": version,
        "samples_hash": file_hash(samples),
        "manifest_hash_input": stable_hash(
            {"version": version, "samples_hash": file_hash(samples)}
        ),
    }
    (target / "dataset_manifest.json").write_text(
        json.dumps(manifest, indent=2, sort_keys=True), encoding="utf-8"
    )
    return target
