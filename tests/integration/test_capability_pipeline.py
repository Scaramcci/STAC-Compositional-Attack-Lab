from __future__ import annotations

import json
from pathlib import Path

from stac_attack_lab.capability.compiler import compile_cases, validate_compilation
from stac_attack_lab.capability.models import EpisodeResult, PrimitiveKind
from stac_attack_lab.capability.reporting import build_capability_report
from stac_attack_lab.capability.runner import replay_episode, run_fake_pipeline

ROOT = Path(__file__).resolve().parents[2]
CONFIG = ROOT / "configs/capability/f1_status_acceptance.json"


def test_full_offline_capability_pipeline_has_state_rejection_and_unknown(tmp_path: Path) -> None:
    compiled = compile_cases(CONFIG, tmp_path / "compiled")
    validate_compilation(compiled)
    episodes = run_fake_pipeline(compiled, tmp_path / "episodes")
    report = build_capability_report(episodes, tmp_path / "report")

    benign = EpisodeResult.model_validate_json(
        (episodes / "cap-f1-001-benign/episode_result.json").read_text(encoding="utf-8")
    )
    direct = EpisodeResult.model_validate_json(
        (episodes / "cap-f1-001-direct/episode_result.json").read_text(encoding="utf-8")
    )
    semantic = EpisodeResult.model_validate_json(
        (episodes / "cap-f1-001-semantic/episode_result.json").read_text(encoding="utf-8")
    )
    assert benign.harm.verdict.value == "false"
    assert direct.harm.verdict.value == "false" and direct.harm.attempted_harm
    assert semantic.harm.verdict.value == "true"
    adopt = next(
        item for item in semantic.primitive_analysis if item.primitive == PrimitiveKind.ADOPT
    )
    assert adopt.overall_execution.value == "unknown"
    assert semantic.pp_success is False
    assert report.is_file()
    summary = json.loads((episodes / "summary.json").read_text(encoding="utf-8"))
    assert summary["network_requests_performed"] is False

    replayed = replay_episode(episodes / "cap-f1-001-semantic", tmp_path / "replayed-semantic")
    assert replayed.report_hash == semantic.report_hash
