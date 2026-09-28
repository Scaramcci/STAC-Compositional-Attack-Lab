"""Loopback HTTP exercises the production client, ledger and JSON plan parser."""

from __future__ import annotations

import json
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest

from stac_attack_lab.attack_program.demo_r2 import demo as r2_demo
from stac_attack_lab.attack_program.models import R3Case, R3Config, R3PlannerInput
from stac_attack_lab.attack_program.pipeline import GateError
from stac_attack_lab.attack_program.r3 import (
    ProductionPlannerTransport,
    _validate_plan,
    replay,
    run,
)
from stac_attack_lab.models.openai_compatible import OpenAICompatibleClient, ProviderRequestLedger


class Handler(BaseHTTPRequestHandler):
    received: list[dict] = []

    def do_POST(self):
        body = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
        self.received.append(body)
        index = len(self.received)
        if index == 3:
            time.sleep(1.3)
        planner_input = json.loads(body["messages"][-1]["content"])
        pointer = planner_input["allowed_surfaces"][0]["pointer"]
        content = (
            json.dumps(
                {
                    "schema_version": "attack-plan/1",
                    "selected_sample_ids": [],
                    "patches": [{"pointer": pointer, "value": "Safe notice"}],
                    "abstain": False,
                    "decision_summary": "fake",
                }
            )
            if index == 1
            else "{invalid json"
        )
        data = json.dumps(
            {
                "id": f"fake-{index}",
                "model": "local-fake-model",
                "choices": [{"message": {"content": content}, "finish_reason": "stop"}],
                "usage": {"prompt_tokens": 11, "completion_tokens": 7},
            }
        ).encode()
        try:
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)
        except BrokenPipeError:
            pass

    def log_message(self, *_args):
        pass


def _request() -> R3PlannerInput:
    case = R3Case(
        case_id="fake",
        task_id="pse-2.1-001",
        task_group_id="pse-prompt-injection",
        repeat=1,
        arm="no_library",
        public_task_hash="public",
        planner_model_id="local-fake-model",
        planner_max_output_tokens=1200,
        planner_request_budget=1,
        victim_request_budget=0,
        seed=1,
        retrieved_sample_ids=[],
    )
    return R3PlannerInput(
        case=case,
        public_task={"task_id": "pse-2.1-001"},
        public_goal="synthetic",
        allowed_surfaces=[{"pointer": "/environment/workspace_files/0/content", "max_chars": 50}],
        compatible_samples=[],
    )


def test_production_client_loopback_counts_valid_invalid_timeout_and_no_retry(
    tmp_path, monkeypatch
):
    Handler.received = []
    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        monkeypatch.setenv("STAC_R3_FAKE_URL", f"http://127.0.0.1:{server.server_port}")
        monkeypatch.setenv("STAC_R3_FAKE_KEY", "local-test-only")
        ledger = ProviderRequestLedger(
            max_requests=3, path=tmp_path / "planner-ledger.jsonl", batch_id="fake-r3-unique"
        )
        client = OpenAICompatibleClient(
            model_id="local-fake-model",
            base_url_env="STAC_R3_FAKE_URL",
            api_key_env="STAC_R3_FAKE_KEY",
            request_ledger=ledger,
            http_502_retries=0,
        )
        transport = ProductionPlannerTransport(
            client, ledger, enabled=True, local_fake_only=True, timeout=1
        )
        request = _request()
        valid = transport.generate(request, "same prompt")
        assert valid.http_attempts == 1 and valid.error is None
        assert _validate_plan(request, valid.text or "").patches[0].value == "Safe notice"
        invalid = transport.generate(request, "same prompt")
        assert invalid.http_attempts == 1 and invalid.text == "{invalid json"
        with pytest.raises(GateError, match="r3_plan_schema_invalid"):
            _validate_plan(request, invalid.text or "")
        timed_out = transport.generate(request, "same prompt")
        assert timed_out.http_attempts == 1 and timed_out.error is not None
        assert timed_out.text is None
        assert len(Handler.received) == 3
        assert all(body["seed"] == 1 for body in Handler.received)
        rows = [
            json.loads(line)
            for line in (tmp_path / "planner-ledger.jsonl").read_text().splitlines()
        ]
        assert [row["stage"] for row in rows] == [
            "attempt_started",
            "attempt_finished",
        ] * 3
        assert [row["sequence"] for row in rows if row["stage"] == "attempt_started"] == [1, 2, 3]
        ledger.close()
    finally:
        server.shutdown()
        server.server_close()


def test_production_transport_matrix_and_ledger_replay(tmp_path, monkeypatch):
    root = Path(__file__).resolve().parents[2]
    r2_demo(root, tmp_path / "r2")
    Handler.received = []
    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        monkeypatch.setenv("STAC_R3_FAKE_URL", f"http://127.0.0.1:{server.server_port}")
        monkeypatch.setenv("STAC_R3_FAKE_KEY", "local-test-only")
        ledger = ProviderRequestLedger(
            max_requests=3, path=tmp_path / "ledger.jsonl", batch_id="matrix"
        )
        client = OpenAICompatibleClient(
            model_id="local-fake-model",
            base_url_env="STAC_R3_FAKE_URL",
            api_key_env="STAC_R3_FAKE_KEY",
            request_ledger=ledger,
        )
        transport = ProductionPlannerTransport(
            client, ledger, enabled=True, local_fake_only=True, timeout=1
        )
        config = R3Config(
            task_id="pse-2.1-001",
            repeats=1,
            top_k=2,
            planner_model_id="local-fake-model",
            planner_request_budget=3,
            victim_request_budget=0,
        )
        report = run(root, tmp_path / "r2/library", config, tmp_path / "matrix", transport)
        assert report["assigned"] == 3
        assert report["planner_http_attempts"] == 3
        assert report["status_counts"]["invalid_plan"] == 1
        assert report["status_counts"]["infra_error"] == 1
        assert report["victim_http_attempts"] == 0
        assert report["cases"][0]["planner_prompt_tokens"] == 11
        assert report["cases"][0]["planner_output_tokens"] == 7
        assert (
            replay(
                root, tmp_path / "r2/library", tmp_path / "matrix", tmp_path / "audit", compare=True
            )
            == report
        )
        with pytest.raises(GateError, match="r3_output_exists"):
            run(root, tmp_path / "r2/library", config, tmp_path / "matrix", transport)
        assert len(Handler.received) == 3
        assert all(body["seed"] == 17 for body in Handler.received)
        ledger.close()
    finally:
        server.shutdown()
        server.server_close()
