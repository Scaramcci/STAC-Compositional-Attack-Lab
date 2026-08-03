from __future__ import annotations

from pathlib import Path

from stac_attack_lab.config import load_experiment_config
from stac_attack_lab.models.factory import build_model_client
from stac_attack_lab.models.fake import FakeModelClient
from stac_attack_lab.models.gemini import GeminiClient
from stac_attack_lab.models.huihui import HuihuiLocalClient
from stac_attack_lab.models.openai_compatible import OpenAICompatibleClient

ROOT = Path(__file__).resolve().parents[2]


def test_role_configs_load_for_current_and_future_runs() -> None:
    configs = [
        "configs/experiments/stac_sample_build_gemini.yaml",
        "configs/experiments/stac_sample_build_gpt_gemini.yaml",
        "configs/experiments/evaluation_gpt_huihui_4090.yaml",
    ]
    for config_path in configs:
        config = load_experiment_config(ROOT / config_path)
        assert {"planner", "attacker", "victim", "prompt_writer", "verifier", "judge"} <= set(
            config.models
        )


def test_model_factory_resolves_supported_providers() -> None:
    fake = load_experiment_config(ROOT / "configs/experiments/mvp_online.yaml")
    gemini = load_experiment_config(ROOT / "configs/experiments/stac_sample_build_gemini.yaml")
    future = load_experiment_config(ROOT / "configs/experiments/evaluation_gpt_huihui_4090.yaml")

    assert isinstance(build_model_client(fake.models["planner"]), FakeModelClient)
    assert isinstance(build_model_client(gemini.models["victim"]), GeminiClient)
    assert isinstance(build_model_client(future.models["planner"]), OpenAICompatibleClient)
    assert isinstance(build_model_client(future.models["victim"]), HuihuiLocalClient)
