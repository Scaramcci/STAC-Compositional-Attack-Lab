from __future__ import annotations

from pathlib import Path

from stac_attack_lab.flow.analysis import FlowRegistry


def load_flow_registry(path: Path) -> FlowRegistry:
    return FlowRegistry.model_validate_json(path.read_text(encoding="utf-8"))
