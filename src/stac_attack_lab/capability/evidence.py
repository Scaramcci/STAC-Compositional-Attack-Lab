from __future__ import annotations

import json
import os
from pathlib import Path

from stac_attack_lab.capability.models import EvidenceBundleManifest
from stac_attack_lab.hashing import file_hash, stable_hash

EVIDENCE_FILES = (
    "runtime_task.json",
    "runtime_events.jsonl",
    "checkpoints/initial.json",
    "checkpoints/final.json",
    "provider_attempt_ledger.jsonl",
    "runtime_review.json",
)


def seal_episode_evidence(episode_root: Path, *, episode_id: str) -> EvidenceBundleManifest:
    manifest_path = episode_root / "evidence_bundle.json"
    if manifest_path.exists():
        raise FileExistsError("capability_evidence_bundle_exists")
    hashes: dict[str, str] = {}
    for relative in EVIDENCE_FILES:
        path = episode_root / relative
        if not path.is_file():
            raise ValueError(f"capability_evidence_input_missing:{relative}")
        hashes[relative] = file_hash(path)
        os.chmod(path, 0o600)
    event_count = sum(
        bool(line.strip())
        for line in (episode_root / "runtime_events.jsonl").read_text(encoding="utf-8").splitlines()
    )
    payload = {
        "schema_version": "capability-evidence-bundle/1.0",
        "episode_id": episode_id,
        "input_hashes": hashes,
        "event_count": event_count,
        "processing_version": "capability-evidence-v2",
    }
    manifest = EvidenceBundleManifest.model_validate(
        {**payload, "bundle_hash": stable_hash(payload)}
    )
    manifest_path.write_text(manifest.model_dump_json(indent=2) + "\n", encoding="utf-8")
    os.chmod(manifest_path, 0o600)
    return manifest


def verify_episode_evidence(episode_root: Path) -> EvidenceBundleManifest:
    manifest_path = episode_root / "evidence_bundle.json"
    if not manifest_path.is_file():
        raise ValueError("capability_evidence_bundle_missing")
    manifest = EvidenceBundleManifest.model_validate_json(manifest_path.read_text(encoding="utf-8"))
    if set(manifest.input_hashes) != set(EVIDENCE_FILES):
        raise ValueError("capability_evidence_bundle_file_set_mismatch")
    for relative, expected in manifest.input_hashes.items():
        path = episode_root / relative
        if not path.is_file() or file_hash(path) != expected:
            raise ValueError(f"capability_evidence_bundle_input_mismatch:{relative}")
    actual_count = sum(
        bool(line.strip())
        for line in (episode_root / "runtime_events.jsonl").read_text(encoding="utf-8").splitlines()
    )
    if actual_count != manifest.event_count:
        raise ValueError("capability_evidence_bundle_event_count_mismatch")
    return manifest


def write_private_json(path: Path, value: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    os.chmod(path, 0o600)
