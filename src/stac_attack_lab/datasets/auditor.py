from __future__ import annotations

from pathlib import Path

from stac_attack_lab.contracts import OfflineSample

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
    seen_hashes: set[str] = set()
    for idx, line in enumerate(samples_path.read_text(encoding="utf-8").splitlines(), start=1):
        if not line.strip():
            continue
        try:
            sample = OfflineSample.model_validate_json(line)
        except Exception as exc:
            errors.append(f"schema_error_line_{idx}:{exc}")
            continue
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
    return errors
