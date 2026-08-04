from __future__ import annotations

import shutil
from pathlib import Path

import pytest

from stac_attack_lab.config import (
    GPT_MODEL_ID,
    StartupValidationError,
    configured_openai_models,
    load_experiment_config,
    validate_startup,
)
from stac_attack_lab.contracts import ActorRole
from stac_attack_lab.execution import online_stac
from stac_attack_lab.models.base import ModelCallError
from stac_attack_lab.models.discovery import discover_huihui_model
from stac_attack_lab.recording.conversations import (
    ConversationEvent,
    ConversationEventType,
    ConversationRecorder,
    SchemaValidationRecord,
    audit_transcript,
)
from stac_attack_lab.recording.events import read_jsonl
from stac_attack_lab.recording.progress import AttackProgressStatus, ExperimentProgress

ROOT = Path(__file__).resolve().parents[2]


def test_required_model_profiles_are_explicit() -> None:
    offline = load_experiment_config(ROOT / "configs/experiments/stac_sample_build_gpt_gemini.yaml")
    evaluation = load_experiment_config(
        ROOT / "configs/experiments/evaluation_gpt_huihui_4090.yaml"
    )
    for config in (offline, evaluation):
        for role in {"planner", "attacker", "prompt_writer", "verifier", "judge"}:
            assert config.models[role].provider == "openai_compatible"
            assert config.models[role].model == GPT_MODEL_ID
    assert offline.models["victim"].provider == "gemini"
    assert evaluation.models["victim"].provider == "huihui_local"
    assert evaluation.models["victim"].model == "huihui-qwen3-14b-abliterated-v2"


def test_openai_model_list_lowercase_spelling_takes_precedence() -> None:
    environment = {
        "OPENAI_MODEL_list": '["gpt-5.5"]',
        "OPENAI_MODEL_LIST": '["wrong-model"]',
    }
    assert configured_openai_models(environment) == ["gpt-5.5"]


def test_startup_validation_fails_closed_without_revealing_secrets() -> None:
    config = load_experiment_config(ROOT / "configs/experiments/stac_sample_build_gpt_gemini.yaml")
    secret = "never-print-this-secret"
    environment = {
        "OPENAI_BASE_URL": "https://example.invalid/v1",
        "OPENAI_API_KEY": secret,
        "OPENAI_MODEL_list": '["wrong-model"]',
        "GEMINI_API_KEY": secret,
    }
    with pytest.raises(StartupValidationError) as captured:
        validate_startup(config, environment)
    assert "gpt-5.5_not_configured" in str(captured.value)
    assert secret not in str(captured.value)


def test_huihui_discovery_override_and_parent_search(tmp_path: Path) -> None:
    override = tmp_path / "override"
    override.mkdir()
    for name in ("config.json", "tokenizer.json", "model-00001-of-00001.safetensors"):
        (override / name).write_text("{}", encoding="utf-8")
    assert discover_huihui_model(tmp_path, {"HUIHUI_MODEL_PATH": str(override)}) == override

    project_root = tmp_path / "workspace" / "nested" / "project"
    project_root.mkdir(parents=True)
    candidate = tmp_path / "models" / "huihui-qwen3-14b-abliterated-v2"
    candidate.mkdir(parents=True)
    for name in ("config.json", "tokenizer_config.json", "weights.safetensors"):
        (candidate / name).write_text("{}", encoding="utf-8")
    assert discover_huihui_model(project_root, {}) == candidate


def _append_request(
    recorder: ConversationRecorder,
    *,
    content: str,
    recipient: ActorRole = ActorRole.planner,
) -> ConversationEvent:
    return recorder.append(
        event_id="call-1-request",
        call_id="call-1",
        run_id="run-1",
        attack_id="attack-1",
        idempotency_key="key-1",
        phase="evaluation",
        condition="fixed_full",
        seed=1,
        attempt_no=1,
        event_type=ConversationEventType.model_request,
        sender_role=ActorRole.recorder,
        recipient_role=recipient,
        model_provider="fake",
        model_id="fake-deterministic-v1",
        model_config_hash="hash",
        prompt_id="runtime.adaptive_planner",
        prompt_version="1.0.0",
        prompt_hash="prompt-hash",
        input_schema_id="PlannerInput",
        output_schema_id="PlannerDecision",
        request_messages=[{"role": "user", "content": content}],
        raw_model_response=None,
        parsed_structured_response=None,
        schema_validation=SchemaValidationRecord(schema_id="PlannerDecision", valid=None),
        token_metadata={},
        related_event_ids=[],
        artifact_refs=[],
        snapshot_refs=[],
        hard_verdict_refs=[],
    )


def test_conversation_round_trip_redaction_and_audit(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    secret = "gemini-secret-value"
    monkeypatch.setenv("GEMINI_API_KEY", secret)
    path = tmp_path / "conversations.jsonl"
    event = _append_request(ConversationRecorder(path), content=f"safe {secret} text")
    assert secret not in path.read_text(encoding="utf-8")
    round_trip = ConversationEvent.model_validate_json(event.model_dump_json())
    assert round_trip.event_id == event.event_id
    report = audit_transcript(path, expected_run_id="run-1")
    assert report.passed


def test_transcript_audit_detects_victim_information_leak(tmp_path: Path) -> None:
    path = tmp_path / "conversations.jsonl"
    _append_request(
        ConversationRecorder(path),
        content="private_oracle must stay hidden",
        recipient=ActorRole.victim,
    )
    report = audit_transcript(path, expected_run_id="run-1")
    assert not report.passed
    assert {finding.code for finding in report.findings} == {"victim_role_leak"}


def _temporary_project(tmp_path: Path) -> Path:
    project = tmp_path / "project"
    frozen = project / "data/frozen/mvp-v0.1"
    frozen.mkdir(parents=True)
    shutil.copy(ROOT / "data/frozen/mvp-v0.1/samples.jsonl", frozen / "samples.jsonl")
    shutil.copytree(ROOT / "prompts", project / "prompts")
    return project


def _small_fake_config() -> object:
    config = load_experiment_config(ROOT / "configs/experiments/mvp_online.yaml")
    return config.model_copy(update={"conditions": ["clean"], "task_limit": 2, "seeds": [1]})


def test_crash_between_attacks_resumes_without_duplicates(tmp_path: Path) -> None:
    project = _temporary_project(tmp_path)
    run_root = project / "experiments/runs/recovery"
    config = _small_fake_config()

    def crash_after_first(completed: int) -> None:
        if completed == 1:
            raise RuntimeError("simulated_process_crash")

    with pytest.raises(RuntimeError, match="simulated_process_crash"):
        online_stac.run_online(
            project,
            config,
            run_root=run_root,
            run_id="recovery-run",
            after_attack=crash_after_first,
        )
    interrupted = ExperimentProgress.model_validate_json(
        (run_root / "progress.json").read_text(encoding="utf-8")
    )
    assert interrupted.completed == 1

    online_stac.run_online(project, config, resume=True, run_root=run_root, run_id="recovery-run")
    resumed = ExperimentProgress.model_validate_json(
        (run_root / "progress.json").read_text(encoding="utf-8")
    )
    results = read_jsonl(run_root / "results.jsonl")
    assert resumed.completed == 2
    assert len(results) == 2
    assert len({item["run_id"] for item in results}) == 2
    assert sum(item.attempts for item in resumed.attacks) == 2


def test_quota_pause_is_resumable(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    project = _temporary_project(tmp_path)
    run_root = project / "experiments/runs/quota"
    config = _small_fake_config().model_copy(update={"task_limit": 1})
    real_run_one = online_stac.run_one

    def quota_failure(*args: object, **kwargs: object) -> object:
        raise ModelCallError("quota")

    monkeypatch.setattr(online_stac, "run_one", quota_failure)
    online_stac.run_online(project, config, run_root=run_root, run_id="quota-run")
    paused = ExperimentProgress.model_validate_json(
        (run_root / "progress.json").read_text(encoding="utf-8")
    )
    assert paused.attacks[0].status == AttackProgressStatus.paused_quota
    assert paused.pause_reason == "quota"

    monkeypatch.setattr(online_stac, "run_one", real_run_one)
    online_stac.run_online(project, config, resume=True, run_root=run_root, run_id="quota-run")
    resumed = ExperimentProgress.model_validate_json(
        (run_root / "progress.json").read_text(encoding="utf-8")
    )
    assert resumed.completed == 1
    assert len(read_jsonl(run_root / "results.jsonl")) == 1
