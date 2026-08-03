from pathlib import Path

from stac_attack_lab.environments.agentdojo_adapter import smoke_available
from stac_attack_lab.environments.shade_arena_adapter import (
    smoke_available as shade_smoke_available,
)

ROOT = Path(__file__).resolve().parents[2]


def test_agentdojo_adapter_contract_skip_reason() -> None:
    ok, reason = smoke_available()
    if ok:
        assert "AgentDojo banking smoke ok" in reason
    else:
        assert "Dependency unavailable" in reason or "dependency" in reason.lower()


def test_shade_arena_adapter_contract() -> None:
    ok, reason = shade_smoke_available(ROOT)
    if ok:
        assert "SHADE_Arena smoke ok" in reason
    else:
        assert "SHADE_Arena checkout" in reason
