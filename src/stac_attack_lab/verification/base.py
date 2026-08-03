from __future__ import annotations

from pathlib import Path

from stac_attack_lab.contracts import AttackEvent, OfflineSample, VerifierVerdict


class DeterministicVerifierProtocol:
    def verify(
        self, sample: OfflineSample | None, events: list[AttackEvent], run_dir: Path
    ) -> VerifierVerdict:
        raise NotImplementedError
