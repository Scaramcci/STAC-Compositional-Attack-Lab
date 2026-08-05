from __future__ import annotations

import json
from pathlib import Path

from stac_attack_lab.contracts import OfflineSample
from stac_attack_lab.hashing import stable_hash

DANGEROUS_STRINGS = [
    "BEGIN RSA PRIVATE KEY",
    "OPENAI_API_KEY=",
    "subprocess",
    "curl http",
    "rm -rf",
]


def audit_dataset(path: Path) -> list[str]:
    errors: list[str] = []
    samples_path = path / "samples.jsonl"
    if not samples_path.exists():
        return ["missing_samples_jsonl"]
    manifest_path = path / "dataset_manifest.json"
    manifest = (
        json.loads(manifest_path.read_text(encoding="utf-8")) if manifest_path.exists() else {}
    )
    requires_selection = manifest.get("selection_policy") == "offline_hard_success_only"
    seen_hashes: set[str] = set()
    sample_count = 0
    for idx, line in enumerate(samples_path.read_text(encoding="utf-8").splitlines(), start=1):
        if not line.strip():
            continue
        try:
            sample = OfflineSample.model_validate_json(line)
        except Exception as exc:
            errors.append(f"schema_error_line_{idx}:{exc}")
            continue
        sample_count += 1
        if sample.sample_hash in seen_hashes:
            errors.append(f"duplicate_sample_hash:{sample.sample_id}")
        seen_hashes.add(sample.sample_hash)
        payload = line
        for needle in DANGEROUS_STRINGS:
            if needle in payload:
                errors.append(f"dangerous_string:{needle}")
        if sample.seed_task.get("canary_id", "") in "\n".join(
            o.victim_message for o in sample.victim_messages
        ):
            errors.append(f"hidden_answer_leak:{sample.sample_id}")
        if not sample.expected_predicates:
            errors.append(f"missing_expected_predicates:{sample.sample_id}")
        if requires_selection:
            if sample.selection is None:
                errors.append(f"missing_selection_evidence:{sample.sample_id}")
            else:
                graph_hash = stable_hash(sample.attack_graph.model_dump(mode="json"))
                prompt_hash = stable_hash(
                    [item.model_dump(mode="json") for item in sample.victim_messages]
                )
                if graph_hash != sample.selection.verified_graph_hash:
                    errors.append(f"verified_graph_hash_mismatch:{sample.sample_id}")
                if prompt_hash != sample.selection.verified_prompt_hash:
                    errors.append(f"verified_prompt_hash_mismatch:{sample.sample_id}")
                if (
                    stable_hash(sample.verified_call_params)
                    != sample.selection.verified_call_params_hash
                ):
                    errors.append(f"verified_call_params_hash_mismatch:{sample.sample_id}")
    if requires_selection:
        target = int(manifest.get("successful_sample_target", 0))
        if not manifest.get("collection_complete"):
            errors.append("sample_collection_incomplete")
        if not manifest.get("transcript_audit_passed"):
            errors.append("transcript_audit_not_passed")
        if sample_count != target:
            errors.append(f"successful_sample_target_mismatch:{sample_count}/{target}")
    return errors
