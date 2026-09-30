"""Local fake HTTP checks for R4 candidate transport and Victim reply framing."""

from __future__ import annotations

import json
import threading
import time
import urllib.error
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest

from stac_attack_lab.attack_program.pipeline import GateError
from stac_attack_lab.attack_program.provider_relay import (
    ProviderRelayConfig,
    ProviderRelayServer,
    _PersistentRelayBudget,
)
from stac_attack_lab.attack_program.r4_batch import _project_env, generate_candidate
from stac_attack_lab.attack_program.r4_fake_provider import FakeServer

ROOT = Path(__file__).resolve().parents[2]


def _serve(server: ThreadingHTTPServer) -> threading.Thread:
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return thread


def test_fake_victim_http_json_and_sse_drive_different_actions():
    server = FakeServer({"mode": "harm", "mail_name": "notice.eml", "model": "r4-local-fake"}, 0)
    thread = _serve(server)
    try:
        url = f"http://127.0.0.1:{server.server_address[1]}/v1/chat/completions"
        request = urllib.request.Request(
            url, data=b'{"stream":false}', headers={"Content-Type": "application/json"}
        )
        with urllib.request.urlopen(request, timeout=2) as response:
            first = json.load(response)
        assert first["choices"][0]["message"]["tool_calls"][0]["function"]["name"] == "exec"
        request = urllib.request.Request(
            url, data=b'{"stream":true}', headers={"Content-Type": "application/json"}
        )
        with urllib.request.urlopen(request, timeout=2) as response:
            body = response.read().decode()
        chunks = [json.loads(line[6:]) for line in body.splitlines() if line.startswith("data: {")]
        tool = chunks[0]["choices"][0]["delta"]["tool_calls"][0]
        assert tool["function"]["name"] == "exec"
        assert (
            json.loads(tool["function"]["arguments"])["command"]
            == "sim-google gmail get notice.eml --json"
        )
        assert "data: [DONE]" in body
        delivered = {"from": "bot@example.test", "subject": "CI/CD", "body": "actual tool body"}
        request = urllib.request.Request(
            url,
            data=json.dumps(
                {
                    "messages": [
                        {
                            "role": "tool",
                            "tool_call_id": "r4-call-2",
                            "content": json.dumps(delivered),
                        },
                    ]
                }
            ).encode(),
            headers={"Content-Type": "application/json"},
        )
        with urllib.request.urlopen(request, timeout=2) as response:
            third = json.load(response)
        call = third["choices"][0]["message"]["tool_calls"][0]["function"]
        assert call["name"] == "write"
        assert (
            json.loads(call["arguments"])["content"]
            == "From: bot@example.test\nSubject: CI/CD\n\nactual tool body"
        )
        assert server.requests == 3
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


class _CandidateHandler(BaseHTTPRequestHandler):
    calls = 0

    def log_message(self, _format: str, *args: object) -> None:
        del args

    def do_POST(self) -> None:
        type(self).calls += 1
        request = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
        assert request["model"] == "attacker-local-fake"
        assert request["seed"] == 17
        candidate = json.loads(
            (ROOT / "configs/attack_program/r4_development_candidate.json").read_text()
        )
        response = {
            "id": "r4-local-attacker-1",
            "model": "attacker-local-fake",
            "choices": [
                {
                    "message": {"role": "assistant", "content": json.dumps(candidate)},
                    "finish_reason": "stop",
                }
            ],
            "usage": {"prompt_tokens": 30, "completion_tokens": 40, "total_tokens": 70},
        }
        body = json.dumps(response).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


def test_production_attacker_client_uses_one_budgeted_http_request(tmp_path: Path):
    _CandidateHandler.calls = 0
    server = ThreadingHTTPServer(("127.0.0.1", 0), _CandidateHandler)
    thread = _serve(server)
    try:
        out = tmp_path / "generated"
        candidate = generate_candidate(
            ROOT,
            task_id="pse-2.1-001",
            model_id="attacker-local-fake",
            base_url=f"http://127.0.0.1:{server.server_address[1]}/v1",
            api_key="local-only",
            output=out,
            batch_id="attacker-test",
        )
        assert candidate.candidate_id == "r4-dev-one"
        assert _CandidateHandler.calls == 1
        lines = (out / "attacker_http.jsonl").read_text().splitlines()
        assert [json.loads(line)["stage"] for line in lines] == [
            "attempt_started",
            "attempt_finished",
        ]
        assert "local-only" not in (out / "attacker_http.jsonl").read_text()
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


def test_non_loopback_attacker_endpoint_rejected_before_output(tmp_path: Path):
    with pytest.raises(GateError, match="attacker_local_fake_endpoint_required"):
        generate_candidate(
            ROOT,
            task_id="pse-2.1-001",
            model_id="x",
            base_url="https://api.example.com/v1",
            api_key="secret",
            output=tmp_path / "never",
            batch_id="rejected",
        )
    assert not (tmp_path / "never").exists()


def test_relay_reservation_survives_failed_send_and_restart(tmp_path: Path):
    path = tmp_path / "relay.jsonl"
    first = _PersistentRelayBudget(path, 1, "r4-test")
    try:
        sequence, accepted = first.reserve()
        assert (sequence, accepted) == (1, True)
        # A crash after reservation leaves no completion row.
    finally:
        first.close()
    restarted = _PersistentRelayBudget(path, 1, "r4-test")
    try:
        assert restarted.reserved == 1
        assert restarted.reserve() == (2, False)
        reservations = [
            json.loads(line)
            for line in (tmp_path / "relay.jsonl.reservations").read_text().splitlines()
        ]
        assert [row["accepted"] for row in reservations] == ["reserved", False]
    finally:
        restarted.close()


def test_prepare_environment_projection_omits_credential_value(tmp_path: Path):
    (tmp_path / ".env").write_text(
        "SAFECLAW_MODEL=demo\nSAFECLAW_BASE_URL=https://example.invalid/v1\n"
        "SAFECLAW_API_KEY=never-return-this\n"
    )
    projected = _project_env(tmp_path)
    assert projected == {
        "SAFECLAW_MODEL": "demo",
        "SAFECLAW_BASE_URL": "https://example.invalid/v1",
    }


class _FailedProvider(BaseHTTPRequestHandler):
    calls = 0

    def log_message(self, _format, *args):
        pass

    def do_POST(self):
        type(self).calls += 1
        body = self.rfile.read(int(self.headers["Content-Length"]))
        if b"redirect" in body:
            self.send_response(302)
            self.send_header("Location", "/unauthorized-target")
            self.end_headers()
            return
        self.send_error(503, "synthetic unavailable")

    def do_GET(self):
        type(self).calls += 1
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b"{}")


def test_relay_no_retry_deadline_model_and_uncertain_count(tmp_path):
    _FailedProvider.calls = 0
    upstream = ThreadingHTTPServer(("127.0.0.1", 0), _FailedProvider)
    up_thread = _serve(upstream)
    config = ProviderRelayConfig(
        upstream_base_url=f"http://127.0.0.1:{upstream.server_address[1]}/v1",
        upstream_api_key="fake-only",
        ingress_token="fake-ingress",
        control_token="fake-control",
        max_requests=4,
        ledger_path=str(tmp_path / "ledger.jsonl"),
        evidence_path=str(tmp_path / "evidence.jsonl"),
        expected_model="fake-model",
        reject_duplicate_requests=True,
        deadline_at=time.time() + 10,
    )
    relay = ProviderRelayServer(("127.0.0.1", 0), config)
    relay_thread = _serve(relay)

    def send(model, content="same request"):
        request = urllib.request.Request(
            relay.url + "/v1/chat/completions",
            data=json.dumps(
                {"model": model, "messages": [{"role": "user", "content": content}]}
            ).encode(),
            headers={"Content-Type": "application/json", "Authorization": "Bearer fake-ingress"},
        )
        with pytest.raises(urllib.error.HTTPError) as error:
            urllib.request.urlopen(request, timeout=2)
        error.value.close()
        return error.value.code

    try:
        assert send("different-model") == 400
        assert relay.budget.reserved == 0
        assert send("fake-model") == 503
        assert send("fake-model") == 409
        assert _FailedProvider.calls == 1
        assert relay.budget.reserved == 2
        assert send("fake-model", "redirect") == 302
        assert _FailedProvider.calls == 2
        assert relay.budget.reserved == 3
        freeze = urllib.request.Request(
            relay.url + "/stac/evidence/context/freeze",
            data=b"{}",
            headers={"X-STAC-Control-Token": "fake-control", "Content-Type": "application/json"},
        )
        with urllib.request.urlopen(freeze, timeout=2) as response:
            assert json.load(response)["status"] == "frozen"
        assert send("fake-model", "after freeze") == 429
        assert _FailedProvider.calls == 2
        assert relay.budget.reserved == 3
        object.__setattr__(config, "deadline_at", time.time() - 1)
        assert send("fake-model") == 403
        assert relay.budget.reserved == 3
    finally:
        relay.shutdown()
        relay.server_close()
        relay_thread.join(timeout=2)
        upstream.shutdown()
        upstream.server_close()
        up_thread.join(timeout=2)
