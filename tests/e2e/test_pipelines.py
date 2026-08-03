from __future__ import annotations

from pathlib import Path

from stac_attack_lab.config import load_experiment_config
from stac_attack_lab.datasets.auditor import audit_dataset
from stac_attack_lab.datasets.manifest import freeze_dataset
from stac_attack_lab.execution.offline import build_offline_dataset
from stac_attack_lab.execution.online_stac import run_online
from stac_attack_lab.reporting.report import build_report

ROOT = Path(__file__).resolve().parents[2]


def test_offline_online_report_smoke() -> None:
    build = build_offline_dataset(ROOT, task_limit=2, seed=1)
    assert audit_dataset(build) == []
    frozen = freeze_dataset(build, "test-v0.1", ROOT)
    assert (frozen / "samples.jsonl").exists()
    config = load_experiment_config(ROOT / "configs/experiments/mvp_online.yaml")
    config = config.model_copy(update={"dataset_version": "test-v0.1"})
    run_root = run_online(ROOT, config)
    report = build_report(run_root)
    assert report["run_count"] == 18
    fixed = report["conditions"]["fixed_full"]  # type: ignore[index]
    clean = report["conditions"]["clean"]  # type: ignore[index]
    defense = report["conditions"]["llm_planner_full_defense_on"]  # type: ignore[index]
    assert fixed["numerator"] == 2
    assert clean["numerator"] == 0
    assert defense["numerator"] == 0
