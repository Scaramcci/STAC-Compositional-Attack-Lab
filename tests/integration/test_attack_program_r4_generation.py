"""Bounded generation through the loopback provider and frozen handoff."""

from __future__ import annotations

import json
import threading
from pathlib import Path

import pytest

from stac_attack_lab.attack_program.pipeline import GateError
from stac_attack_lab.attack_program.r4_fake_provider import FakeServer
from stac_attack_lab.attack_program.r4_generation import (
    prepare_generation,
    prepare_victim_candidates,
    run_generation,
)

ROOT = Path(__file__).resolve().parents[2]
PLAN = ROOT / "configs/attack_program/r4_generation_plan_v1.json"
PROMPT = ROOT / "configs/attack_program/r4_attacker_prompt_v1.txt"
CANDIDATE = ROOT / "configs/attack_program/r4_development_candidate.json"


def _run(
    tmp_path: Path, candidate_file: Path, *, usage: dict[str, int] | None | object = "default"
) -> tuple[Path, dict]:
    config = {"mode": "generation", "candidate_path": str(candidate_file)}
    if usage != "default":
        config["usage"] = usage
    server = FakeServer(config, 0)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    output = tmp_path / "generation"
    try:
        summary = run_generation(
            ROOT,
            PLAN,
            PROMPT,
            output,
            model_id="attacker-local-fake",
            base_url=f"http://127.0.0.1:{server.server_address[1]}/v1",
            api_key="local-only",
            local_fake=True,
        )
        assert server.requests == 3
        return output, summary
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


def test_duplicate_payload_keeps_all_attempts_and_victim_preparation(tmp_path: Path):
    output, summary = _run(tmp_path, CANDIDATE)
    assert (summary["assigned_slots"], summary["attacker_http_attempts"]) == (3, 3)
    assert (summary["valid_candidates"], summary["duplicate_candidates"]) == (1, 2)
    assert all(slot["usage"]["total_tokens"] == 20 for slot in summary["slots"])
    prepared = prepare_victim_candidates(ROOT, output, tmp_path / "victim", local_fake_mode="harm")
    assert prepared["prepared"] == 1
    assert prepared["victim_planned"] == 1
    assert prepared["planned"] == 1
    assert prepared["started"] == 0
    assert prepared["completed"] == 0
    assert prepared["not_started"] == 1
    assert prepared["victim_not_started"] == 1
    assert prepared["unselected_generation_slots"] == 2
    with pytest.raises(GateError, match="already_reserved"):
        run_generation(ROOT, PLAN, PROMPT, output, local_fake=True)


@pytest.mark.parametrize("change", ["task_id", "task_group_id", "source_split", "patch"])
def test_invalid_candidate_never_enters_victim_queue(tmp_path: Path, change: str):
    candidate = json.loads(CANDIDATE.read_text())
    if change == "patch":
        candidate["patches"][0]["pointer"] = "/outside"
    else:
        candidate[change] = "test" if change == "source_split" else "wrong"
    source = tmp_path / "candidate.json"
    source.write_text(json.dumps(candidate))
    output, summary = _run(tmp_path, source)
    assert summary["invalid_candidates"] == 3
    assert summary["valid_candidates"] == 0
    prepared = prepare_victim_candidates(ROOT, output, tmp_path / "victim", local_fake_mode="harm")
    assert prepared["prepared"] == 0


@pytest.mark.parametrize(
    "target", ["plan.json", "prompt.txt", "public_request.json", "candidates/slot-001.json"]
)
def test_tampered_generation_artifact_rejected(tmp_path: Path, target: str):
    output, _ = _run(tmp_path, CANDIDATE)
    path = output / target
    path.write_text(path.read_text() + " ")
    with pytest.raises((GateError, ValueError)):
        prepare_victim_candidates(ROOT, output, tmp_path / "victim", local_fake_mode="harm")


def test_real_generation_disabled_without_authorization(tmp_path: Path):
    with pytest.raises(GateError, match="real_not_authorized"):
        run_generation(ROOT, PLAN, PROMPT, tmp_path / "generation")
    assert not (tmp_path / "generation").exists()


def test_public_generation_view_excludes_private_task_fields(tmp_path: Path):
    summary = prepare_generation(ROOT, PLAN, PROMPT, tmp_path / "prepared")
    request = json.loads((tmp_path / "prepared/public_request.json").read_text())
    assert set(request["public_task"]) == {
        "task_id",
        "task_group_id",
        "normal_user_instructions",
        "allowed_materials",
    }
    assert "evaluator" not in request["public_task"]
    assert "private_oracle" not in request
    assert "credentials" not in request["public_task"]
    assert summary["status"] == "prepared_disabled"


def test_generation_missing_usage_is_unknown(tmp_path: Path):
    _, summary = _run(tmp_path, CANDIDATE, usage=None)
    assert all(
        slot["usage"] is None and slot["usage_observation"] == "unknown"
        for slot in summary["slots"]
    )
