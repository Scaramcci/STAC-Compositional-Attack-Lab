from __future__ import annotations

from pathlib import Path

from stac_attack_lab.contracts import AttackEvent, Verdict, VerifierVerdict
from stac_attack_lab.verification.deterministic import (
    CanaryTriggerVerifier,
    EntryVerifier,
    MemoryRetrievalVerifier,
    MemoryWriteVerifier,
    no_direct_shortcut,
)


def verify_all(
    events: list[AttackEvent], run_dir: Path, min_interference: int = 3
) -> list[VerifierVerdict]:
    return [
        EntryVerifier().verify(events, run_dir),
        MemoryWriteVerifier().verify(events, run_dir),
        MemoryRetrievalVerifier(min_interference).verify(events, run_dir),
        CanaryTriggerVerifier().verify(events, run_dir),
    ]


def chain_success(verdicts: list[VerifierVerdict], events: list[AttackEvent]) -> bool:
    return all(v.verdict == Verdict.pass_ for v in verdicts) and no_direct_shortcut(events)
