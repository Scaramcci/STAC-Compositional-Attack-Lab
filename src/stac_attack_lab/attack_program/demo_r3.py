"""Single-command R2-to-R3 synthetic engineering demonstration."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from stac_attack_lab.attack_program.demo_r2 import demo as r2_demo
from stac_attack_lab.attack_program.models import R3Config
from stac_attack_lab.attack_program.pipeline import GateError
from stac_attack_lab.attack_program.r3 import ScriptedTransport, replay, run


def demo(root: Path, output: Path) -> dict[str, Any]:
    if output.exists():
        raise GateError("r3_demo_output_exists")
    output.mkdir(parents=True, mode=0o700, exist_ok=False)
    r2 = r2_demo(root, output / "r2")
    library = output / "r2/library"
    config = R3Config(
        task_id="pse-2.1-001",
        repeats=1,
        top_k=2,
        planner_model_id="scripted-synthetic",
        planner_request_budget=3,
        victim_request_budget=0,
    )
    matrix = run(root, library, config, output / "r3", ScriptedTransport())
    replay(root, library, output / "r3", output / "r3-replay", compare=True)
    return {
        "scope": "engineering_only_synthetic",
        "r2_assigned": r2["development"]["assigned"],
        "r3_assigned": matrix["assigned"],
        "r3_status_counts": matrix["status_counts"],
        "library": str(library),
        "report": str(output / "r3/report.json"),
        "audit": str(output / "r3-replay/audit.json"),
    }
