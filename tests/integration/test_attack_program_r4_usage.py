"""Provider usage is evidence, not an estimate; absent values stay unknown."""

from __future__ import annotations

import json
import threading
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest

from stac_attack_lab.attack_program.provider_relay import ProviderRelayConfig, ProviderRelayServer
from stac_attack_lab.attack_program.r4_runtime import _provider_compat_for_endpoint


def test_ark_endpoint_selects_usage_request_compatibility():
    assert _provider_compat_for_endpoint("https://ark.cn-beijing.volces.com/api/v3") == "ark"
    assert _provider_compat_for_endpoint("https://example.test/v1") == "openai"


class _UsageProvider(BaseHTTPRequestHandler):
    requests: list[dict] = []
    body = b"{}"
    content_type = "application/json"

    def log_message(self, _format: str, *args: object) -> None:
        del args

    def do_POST(self) -> None:
        type(self).requests.append(json.loads(self.rfile.read(int(self.headers["Content-Length"]))))
        self.send_response(200)
        self.send_header("Content-Type", type(self).content_type)
        self.send_header("Content-Length", str(len(type(self).body)))
        self.end_headers()
        self.wfile.write(type(self).body)


@pytest.mark.parametrize(
    "body,content_type,expected_usage,expected_status",
    [
        (
            b'{"choices":[],"usage":{"prompt_tokens":2,"completion_tokens":3,"total_tokens":5}}',
            "application/json",
            {"input_tokens": 2, "output_tokens": 3, "total_tokens": 5},
            "complete",
        ),
        (
            b'data: {"choices":[{"delta":{"content":"ok"}}]}\n\n'
            b'data: {"choices":[],"usage":{"prompt_tokens":2,'
            b'"completion_tokens":3,"total_tokens":5}}\n\n'
            b"data: [DONE]\n\n",
            "text/event-stream",
            {"input_tokens": 2, "output_tokens": 3, "total_tokens": 5},
            "complete",
        ),
        (b'{"choices":[]}', "application/json", None, "partial"),
        (
            b'{"choices":[],"usage":{"prompt_tokens":2}}',
            "application/json",
            None,
            "partial",
        ),
        (
            b'data: {"choices":[],"usage":{"prompt_tokens":2,'
            b'"completion_tokens":3,"total_tokens":5}}\n\n',
            "text/event-stream",
            None,
            "truncated",
        ),
    ],
)
def test_relay_usage_projection_from_fake_http(
    tmp_path: Path,
    body: bytes,
    content_type: str,
    expected_usage: dict[str, int] | None,
    expected_status: str,
):
    _UsageProvider.requests = []
    _UsageProvider.body = body
    _UsageProvider.content_type = content_type
    upstream = ThreadingHTTPServer(("127.0.0.1", 0), _UsageProvider)
    upstream_thread = threading.Thread(target=upstream.serve_forever, daemon=True)
    upstream_thread.start()
    relay = ProviderRelayServer(
        ("127.0.0.1", 0),
        ProviderRelayConfig(
            upstream_base_url=f"http://127.0.0.1:{upstream.server_address[1]}/v1",
            upstream_api_key="fake-key",
            ingress_token="fake-ingress",
            provider_compat="ark",
            max_requests=1,
            ledger_path=str(tmp_path / "ledger.jsonl"),
            evidence_path=str(tmp_path / "evidence.jsonl"),
        ),
    )
    relay_thread = threading.Thread(target=relay.serve_forever, daemon=True)
    relay_thread.start()
    try:
        request = urllib.request.Request(
            relay.url + "/v1/chat/completions",
            data=json.dumps({"model": "fake", "stream": True, "messages": []}).encode(),
            headers={"Authorization": "Bearer fake-ingress", "Content-Type": "application/json"},
        )
        with urllib.request.urlopen(request, timeout=2) as response:
            assert response.status == 200
            response.read()
        assert _UsageProvider.requests[0]["stream_options"]["include_usage"] is True
        record = [r for r in relay.state.records if r.get("accepted") is True][-1]
        assert record["provider_usage"] == expected_usage
        assert record["provider_usage_observation"] == expected_status
        persisted = [
            json.loads(line) for line in (tmp_path / "ledger.jsonl").read_text().splitlines()
        ]
        assert persisted[-1]["provider_usage"] == expected_usage
        assert persisted[-1]["provider_usage_observation"] == expected_status
    finally:
        relay.shutdown()
        relay.server_close()
        relay_thread.join(timeout=2)
        upstream.shutdown()
        upstream.server_close()
        upstream_thread.join(timeout=2)
