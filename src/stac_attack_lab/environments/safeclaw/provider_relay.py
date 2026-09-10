from __future__ import annotations

import argparse
import hashlib
import hmac
import json
import subprocess
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid
from dataclasses import dataclass, field
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, cast


def chat_completions_url(base_url: str) -> str:
    """Append only the Chat Completions resource to an explicit API root."""
    normalized = base_url.rstrip("/")
    if normalized.endswith("/chat/completions"):
        return normalized
    return normalized + "/chat/completions"


def _tool_name(tool: object) -> str | None:
    if not isinstance(tool, dict):
        return None
    function = tool.get("function")
    if not isinstance(function, dict):
        return None
    name = function.get("name")
    return str(name) if name else None


@dataclass(frozen=True)
class ProviderRelayConfig:
    upstream_base_url: str
    upstream_api_key: str
    ingress_token: str
    max_requests: int = 8
    timeout_seconds: int = 90
    allowed_tools: tuple[str, ...] | None = None
    ledger_path: str = "/tmp/stac-provider-ledger.jsonl"

    @classmethod
    def from_mapping(cls, value: dict[str, Any]) -> ProviderRelayConfig:
        allowed = value.get("allowed_tools")
        if allowed is not None and not isinstance(allowed, list):
            raise ValueError("provider_relay_allowed_tools_must_be_list_or_null")
        config = cls(
            upstream_base_url=str(value.get("upstream_base_url") or ""),
            upstream_api_key=str(value.get("upstream_api_key") or ""),
            ingress_token=str(value.get("ingress_token") or ""),
            max_requests=int(value.get("max_requests", 8)),
            timeout_seconds=int(value.get("timeout_seconds", 90)),
            allowed_tools=(tuple(str(item) for item in allowed) if allowed is not None else None),
            ledger_path=str(value.get("ledger_path") or "/tmp/stac-provider-ledger.jsonl"),
        )
        if not config.upstream_base_url or not config.upstream_api_key or not config.ingress_token:
            raise ValueError("provider_relay_missing_required_config")
        if config.max_requests < 1 or config.timeout_seconds < 1:
            raise ValueError("provider_relay_limits_must_be_positive")
        if config.allowed_tools is not None and len(config.allowed_tools) != len(
            set(config.allowed_tools)
        ):
            raise ValueError("provider_relay_duplicate_allowed_tool")
        return config


@dataclass
class ProviderRelayState:
    accepted_requests: int = 0
    total_attempts: int = 0
    records: list[dict[str, Any]] = field(default_factory=list)
    lock: threading.Lock = field(default_factory=threading.Lock)


def _filtered_payload(
    payload: dict[str, Any], allowed_tools: tuple[str, ...] | None
) -> tuple[dict[str, Any], list[str]]:
    copied = dict(payload)
    tools = copied.get("tools")
    observed = [_tool_name(tool) for tool in tools] if isinstance(tools, list) else []
    observed_names = [name for name in observed if name is not None]
    if allowed_tools is None:
        return copied, observed_names
    allowed = set(allowed_tools)
    filtered = (
        [tool for tool in tools if _tool_name(tool) in allowed] if isinstance(tools, list) else []
    )
    if filtered:
        copied["tools"] = filtered
    else:
        copied.pop("tools", None)
        copied.pop("tool_choice", None)
    choice = copied.get("tool_choice")
    if isinstance(choice, dict):
        chosen = _tool_name(choice)
        if chosen not in allowed:
            raise ValueError("provider_relay_disallowed_tool_choice")
    return copied, [_tool_name(tool) or "unknown" for tool in filtered]


class _RelayHandler(BaseHTTPRequestHandler):
    server: ProviderRelayServer

    def log_message(self, format: str, *args: object) -> None:
        del format, args

    def _write(self, status: int, body: bytes, content_type: str) -> None:
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self) -> None:  # noqa: N802
        if self.path != "/health":
            self._write(404, b'{"error":{"message":"not_found"}}', "application/json")
            return
        state = self.server.state
        with state.lock:
            payload = {
                "status": "ok",
                "accepted_requests": state.accepted_requests,
                "total_attempts": state.total_attempts,
                "max_requests": self.server.config.max_requests,
            }
        self._write(200, json.dumps(payload).encode(), "application/json")

    def do_POST(self) -> None:  # noqa: N802
        config = self.server.config
        started = time.monotonic()
        if self.path not in {"/chat/completions", "/v1/chat/completions"}:
            self._write(404, b'{"error":{"message":"unsupported_path"}}', "application/json")
            return
        supplied = self.headers.get("Authorization", "")
        if not hmac.compare_digest(supplied, f"Bearer {config.ingress_token}"):
            self._write(401, b'{"error":{"message":"relay_auth_failed"}}', "application/json")
            return
        try:
            size = int(self.headers.get("Content-Length", "0"))
            if size < 1 or size > 2_000_000:
                raise ValueError("provider_relay_invalid_body_size")
            raw = self.rfile.read(size)
            parsed = json.loads(raw)
            if not isinstance(parsed, dict):
                raise ValueError("provider_relay_body_not_object")
            payload, final_tools = _filtered_payload(parsed, config.allowed_tools)
        except (ValueError, json.JSONDecodeError) as exc:
            self._write(
                400,
                json.dumps({"error": {"message": str(exc)}}).encode(),
                "application/json",
            )
            return

        with self.server.state.lock:
            self.server.state.total_attempts += 1
            sequence = self.server.state.total_attempts
            accepted = self.server.state.accepted_requests < config.max_requests
            if accepted:
                self.server.state.accepted_requests += 1
        if not accepted:
            self.server.record(
                {
                    "sequence": sequence,
                    "accepted": False,
                    "status": 429,
                    "error_category": "provider_request_budget_exhausted",
                    "final_tools": final_tools,
                    "duration_ms": 0,
                }
            )
            self._write(
                429,
                b'{"error":{"message":"provider_request_budget_exhausted"}}',
                "application/json",
            )
            return

        encoded = json.dumps(payload, separators=(",", ":")).encode()
        target = chat_completions_url(config.upstream_base_url)
        request = urllib.request.Request(
            target,
            data=encoded,
            headers={
                "Authorization": f"Bearer {config.upstream_api_key}",
                "Content-Type": "application/json",
                "Accept": self.headers.get("Accept", "application/json, text/event-stream"),
                "User-Agent": "stac-openclaw-relay/1",
            },
            method="POST",
        )
        status = 502
        content_type = "application/json"
        body = b'{"error":{"message":"provider_transport_error"}}'
        error_category: str | None = None
        try:
            with urllib.request.urlopen(request, timeout=config.timeout_seconds) as response:
                status = response.status
                content_type = response.headers.get("Content-Type", "application/json")
                body = response.read()
        except urllib.error.HTTPError as exc:
            status = exc.code
            content_type = exc.headers.get("Content-Type", "application/json")
            body = exc.read()
            error_category = f"provider_http_{exc.code}"
        except Exception as exc:  # relay must return a bounded, observable failure
            error_category = type(exc).__name__
        self.server.record(
            {
                "sequence": sequence,
                "accepted": True,
                "status": status,
                "error_category": error_category,
                "upstream_path": urllib.parse.urlparse(target).path,
                "request_sha256": hashlib.sha256(encoded).hexdigest(),
                "final_tools": final_tools,
                "stream": bool(payload.get("stream")),
                "duration_ms": round((time.monotonic() - started) * 1000, 3),
            }
        )
        self._write(status, body, content_type)


class ProviderRelayServer(ThreadingHTTPServer):
    allow_reuse_address = True
    daemon_threads = True

    def __init__(
        self,
        address: tuple[str, int],
        config: ProviderRelayConfig,
    ) -> None:
        self.config = config
        self.state = ProviderRelayState()
        super().__init__(address, _RelayHandler)

    @property
    def url(self) -> str:
        host, port = cast(tuple[str, int], self.server_address)
        return f"http://{host}:{port}"

    def record(self, value: dict[str, Any]) -> None:
        with self.state.lock:
            self.state.records.append(dict(value))
            path = Path(self.config.ledger_path)
            path.parent.mkdir(parents=True, exist_ok=True)
            with path.open("a", encoding="utf-8") as stream:
                stream.write(json.dumps(value, sort_keys=True) + "\n")


class RunningProviderRelay:
    def __init__(self, server: ProviderRelayServer) -> None:
        self.server = server
        self.thread = threading.Thread(target=server.serve_forever, daemon=True)

    def __enter__(self) -> ProviderRelayServer:
        self.thread.start()
        return self.server

    def __exit__(self, *args: object) -> None:
        del args
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=5)


class ContainerProviderRelay:
    """A relay isolated from the Victim container and removed by its owning bridge."""

    def __init__(self, *, image: str, victim_container: str, runtime: dict[str, Any]) -> None:
        token = uuid.uuid4().hex
        suffix = uuid.uuid4().hex[:12]
        self.image = image
        self.victim_container = victim_container
        self.network = f"stac-net-{suffix}"
        self.container = f"stac-provider-{suffix}"
        self.ingress_token = token
        self.runtime = dict(runtime)
        self.started = False

    @staticmethod
    def _docker(
        *args: str,
        check: bool = True,
        input_data: bytes | None = None,
    ) -> subprocess.CompletedProcess[bytes]:
        return subprocess.run(
            ["docker", *args],
            input=input_data,
            capture_output=True,
            check=check,
            timeout=30,
        )

    def start(self) -> dict[str, Any]:
        source = str(self.runtime.pop("source"))
        upstream_key = str(self.runtime.pop("upstream_api_key"))
        config = {
            **self.runtime,
            "upstream_api_key": upstream_key,
            "ingress_token": self.ingress_token,
        }
        try:
            self._docker("network", "create", self.network)
            self._docker("network", "connect", self.network, self.victim_container)
            self._docker(
                "run",
                "-d",
                "--name",
                self.container,
                "--network",
                self.network,
                self.image,
                "sleep",
                "infinity",
            )
            self._docker(
                "exec",
                "-i",
                self.container,
                "sh",
                "-c",
                "umask 077; cat > /tmp/stac_provider_relay.py",
                input_data=source.encode(),
            )
            self._docker(
                "exec",
                "-i",
                self.container,
                "sh",
                "-c",
                "umask 077; cat > /tmp/stac_provider_relay.json",
                input_data=json.dumps(config).encode(),
            )
            self._docker(
                "exec",
                "-d",
                self.container,
                "python3",
                "/tmp/stac_provider_relay.py",
                "--config",
                "/tmp/stac_provider_relay.json",
                "--host",
                "0.0.0.0",
                "--port",
                "18791",
            )
            deadline = time.monotonic() + 10
            while time.monotonic() < deadline:
                health = self._docker(
                    "exec",
                    self.victim_container,
                    "python3",
                    "-c",
                    "import urllib.request; urllib.request.urlopen('http://"
                    + self.container
                    + ":18791/health',timeout=1).close()",
                    check=False,
                )
                if health.returncode == 0:
                    self.started = True
                    return {
                        "api_base_url": f"http://{self.container}:18791/v1",
                        "api_key": self.ingress_token,
                    }
                time.sleep(0.1)
            raise RuntimeError("provider_relay_health_timeout")
        except Exception:
            self.stop()
            raise

    def records(self) -> list[dict[str, Any]]:
        if not self.started:
            return []
        result = self._docker(
            "exec",
            self.container,
            "sh",
            "-c",
            "cat /tmp/stac-provider-ledger.jsonl 2>/dev/null || true",
            check=False,
        )
        records = []
        for line in result.stdout.decode(errors="replace").splitlines():
            try:
                item = json.loads(line)
            except json.JSONDecodeError:
                continue
            if isinstance(item, dict):
                records.append(item)
        return records

    def stop(self) -> None:
        self._docker("rm", "-f", self.container, check=False)
        self._docker("network", "disconnect", self.network, self.victim_container, check=False)
        self._docker("network", "rm", self.network, check=False)
        self.started = False


def relay_runtime_from_model_config(value: dict[str, Any]) -> dict[str, Any] | None:
    source = value.pop("provider_relay_source", None)
    if source is None:
        return None
    allowed_tools = value.pop("provider_allowed_tools", None)
    if allowed_tools is not None:
        value["openclaw_allowed_tools"] = allowed_tools
    return {
        "source": source,
        "upstream_base_url": value.pop("provider_upstream_base_url"),
        "upstream_api_key": value.pop("provider_upstream_api_key"),
        "max_requests": value.pop("provider_request_budget", 8),
        "timeout_seconds": value.pop("provider_timeout_seconds", 90),
        "allowed_tools": allowed_tools,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--config", required=True)
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=18791)
    args = parser.parse_args(argv)
    value = json.loads(Path(args.config).read_text(encoding="utf-8"))
    config = ProviderRelayConfig.from_mapping(value)
    server = ProviderRelayServer((args.host, args.port), config)
    try:
        server.serve_forever()
    finally:
        server.server_close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
