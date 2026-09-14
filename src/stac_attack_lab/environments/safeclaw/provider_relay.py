from __future__ import annotations

import argparse
import hashlib
import hmac
import json
import os
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


def _normalize_provider_usage(value: object) -> tuple[dict[str, int] | None, list[str]]:
    """Normalize provider usage without treating missing/invalid fields as zero."""
    if not isinstance(value, dict):
        return None, ["usage_missing"]
    aliases = {
        "input_tokens": ("input_tokens", "prompt_tokens", "promptTokenCount"),
        "output_tokens": ("output_tokens", "completion_tokens", "candidatesTokenCount"),
        "total_tokens": ("total_tokens", "totalTokenCount"),
    }
    projected: dict[str, int] = {}
    invalid: list[str] = []
    for canonical, names in aliases.items():
        present = False
        for name in names:
            if name not in value:
                continue
            present = True
            candidate = value[name]
            if isinstance(candidate, bool) or not isinstance(candidate, int) or candidate < 0:
                invalid.append(canonical)
            else:
                projected[canonical] = candidate
            break
        if not present:
            invalid.append(canonical)
    if "total_tokens" not in projected and {"input_tokens", "output_tokens"} <= set(projected):
        projected["total_tokens"] = projected["input_tokens"] + projected["output_tokens"]
    if set(projected) != {"input_tokens", "output_tokens", "total_tokens"}:
        return None, sorted(
            set(invalid) | (set({"input_tokens", "output_tokens", "total_tokens"}) - set(projected))
        )
    if projected["total_tokens"] != projected["input_tokens"] + projected["output_tokens"]:
        return None, ["total_tokens_inconsistent"]
    return projected, []


def _extract_provider_usage(
    body: bytes, content_type: str
) -> tuple[dict[str, int] | None, str, list[str]]:
    """Extract complete usage from JSON or SSE without retaining response bodies."""
    text = body.decode("utf-8", errors="replace")
    if "text/event-stream" in content_type.lower() or text.lstrip().startswith("data:"):
        usage_values: list[object] = []
        done = False
        for line in text.splitlines():
            line = line.strip()
            if not line or not line.startswith("data:"):
                continue
            payload = line[5:].strip()
            if payload == "[DONE]":
                done = True
                continue
            try:
                value = json.loads(payload)
            except json.JSONDecodeError:
                return None, "invalid", ["sse_event_invalid_json"]
            if isinstance(value, dict) and "usage" in value:
                usage_values.append(value.get("usage"))
        if not done:
            return None, "truncated", ["sse_done_missing"]
        if not usage_values:
            return None, "missing", ["usage_missing"]
        usage, reasons = _normalize_provider_usage(usage_values[-1])
        return usage, ("complete" if usage is not None else "partial"), reasons
    try:
        value = json.loads(text)
    except json.JSONDecodeError:
        return None, "invalid", ["json_invalid"]
    if not isinstance(value, dict):
        return None, "invalid", ["json_not_object"]
    usage, reasons = _normalize_provider_usage(value.get("usage"))
    return usage, ("complete" if usage is not None else "partial"), reasons


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
    provider_compat: str = "openai"
    ledger_path: str = "/tmp/stac-provider-ledger.jsonl"
    batch_id: str | None = None

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
            provider_compat=str(value.get("provider_compat") or "openai"),
            ledger_path=str(value.get("ledger_path") or "/tmp/stac-provider-ledger.jsonl"),
            batch_id=(str(value.get("batch_id")) if value.get("batch_id") else None),
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


class _PersistentRelayBudget:
    """Durable reservation counter shared by relay restarts."""

    def __init__(self, path: Path, maximum: int, batch_id: str | None = None) -> None:
        self.path = path
        self.reservation_path = Path(str(path) + ".reservations")
        self.batch_id = batch_id or uuid.uuid4().hex
        self.maximum = maximum
        self.lock_path = Path(str(path) + ".lock")
        self._fd: int | None = None
        self._mutex = threading.Lock()
        try:
            path.parent.mkdir(parents=True, exist_ok=True)
            self._fd = os.open(self.lock_path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
        except FileExistsError as exc:
            raise RuntimeError("provider_relay_ledger_single_instance_locked") from exc
        except OSError as exc:
            raise RuntimeError("provider_relay_ledger_unavailable") from exc
        try:
            self.records = self._read()
            reservations = self._read_path(self.reservation_path)
        except Exception:
            self.close()
            raise
        self.reserved = sum(1 for item in reservations if item.get("accepted") == "reserved")
        self.sequence = max(
            [
                int(item["sequence"])
                for item in reservations
                if isinstance(item.get("sequence"), int)
            ]
            or [0]
        )

    def _read(self) -> list[dict[str, Any]]:
        return self._read_path(self.path)

    def _read_path(self, path: Path) -> list[dict[str, Any]]:
        if not path.exists():
            return []
        try:
            result = []
            for line in path.read_text(encoding="utf-8").splitlines():
                if line.strip():
                    item = json.loads(line)
                    if not isinstance(item, dict):
                        raise ValueError("record_not_object")
                    result.append(item)
            return result
        except (OSError, UnicodeError, ValueError, json.JSONDecodeError) as exc:
            raise RuntimeError("provider_relay_ledger_corrupt") from exc

    def _append(self, item: dict[str, Any], path: Path | None = None) -> None:
        try:
            with (path or self.path).open("a", encoding="utf-8") as stream:
                stream.write(json.dumps(item, sort_keys=True) + "\n")
                stream.flush()
                os.fsync(stream.fileno())
        except OSError as exc:
            raise RuntimeError("provider_relay_ledger_write_failed") from exc

    def reserve(self) -> tuple[int, bool]:
        with self._mutex:
            self.sequence += 1
            accepted = self.reserved < self.maximum
            item = {
                "batch_id": self.batch_id,
                "stage": "reservation",
                "sequence": self.sequence,
                "accepted": "reserved" if accepted else False,
                "upstream_attempt_count": 1 if accepted else 0,
                "status": 200 if accepted else 429,
                "timestamp": time.time(),
            }
            self._append(item, self.reservation_path)
            if accepted:
                self.reserved += 1
            return self.sequence, accepted

    def append(self, item: dict[str, Any]) -> None:
        with self._mutex:
            self._append(item)
            self.records.append(item)

    def close(self) -> None:
        if self._fd is not None:
            try:
                os.close(self._fd)
                self.lock_path.unlink(missing_ok=True)
            except OSError:
                pass
            self._fd = None


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

        sequence, accepted = self.server.budget.reserve()
        with self.server.state.lock:
            self.server.state.total_attempts = sequence
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

        # Ark emits usage in a final usage-only SSE chunk only when requested.
        # Keep this provider-specific; Gemini compatibility remains unchanged.
        if config.provider_compat == "ark" and payload.get("stream") is True:
            stream_options = payload.get("stream_options")
            if not isinstance(stream_options, dict):
                stream_options = {}
                payload["stream_options"] = stream_options
            stream_options.setdefault("include_usage", True)
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
        provider_usage, usage_observation, usage_reasons = _extract_provider_usage(
            body, content_type
        )
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
                "provider_usage": provider_usage,
                "provider_usage_observation": usage_observation,
                "provider_usage_missing_fields": usage_reasons,
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
        self.budget = _PersistentRelayBudget(
            Path(config.ledger_path), config.max_requests, config.batch_id
        )
        self.state = ProviderRelayState(
            accepted_requests=self.budget.reserved,
            total_attempts=self.budget.sequence,
        )
        super().__init__(address, _RelayHandler)

    def server_close(self) -> None:
        try:
            super().server_close()
        finally:
            self.budget.close()

    @property
    def url(self) -> str:
        host, port = cast(tuple[str, int], self.server_address)
        return f"http://{host}:{port}"

    def record(self, value: dict[str, Any]) -> None:
        with self.state.lock:
            item = {"batch_id": self.budget.batch_id, **value}
            self.state.records.append(dict(item))
            self.budget.append(item)


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


def _parse_jsonl_records(raw: bytes, *, corruption: str) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    for line in raw.decode(errors="replace").splitlines():
        if not line.strip():
            continue
        try:
            item = json.loads(line)
        except json.JSONDecodeError as exc:
            raise RuntimeError(corruption) from exc
        if not isinstance(item, dict):
            raise RuntimeError(corruption)
        records.append(item)
    return records


def _parse_embedding_probe_output(raw: bytes) -> dict[str, Any]:
    try:
        value = json.loads(raw.decode(errors="replace").strip())
    except json.JSONDecodeError as exc:
        raise RuntimeError("embedding_probe_invalid_response") from exc
    if not isinstance(value, dict):
        raise RuntimeError("embedding_probe_invalid_response")
    return value


class ContainerProviderRelay:
    """A relay isolated from the Victim container and removed by its owning bridge."""

    def __init__(self, *, image: str, victim_container: str, runtime: dict[str, Any]) -> None:
        token = uuid.uuid4().hex
        suffix = uuid.uuid4().hex[:12]
        self.image = image
        self.victim_container = victim_container
        self.network = f"stac-net-{suffix}"
        self.container = f"stac-provider-{suffix}"
        self.volume = f"stac-ledger-{suffix}"
        self.ingress_token = token
        self.embedding_ingress_token = uuid.uuid4().hex
        self.runtime = dict(runtime)
        self.batch_id = str(self.runtime.get("batch_id") or uuid.uuid4().hex)
        self.started = False
        self.embedding_started = False

    @staticmethod
    def _docker(
        *args: str,
        check: bool = True,
        input_data: bytes | None = None,
        timeout: int = 30,
    ) -> subprocess.CompletedProcess[bytes]:
        return subprocess.run(
            ["docker", *args],
            input=input_data,
            capture_output=True,
            check=check,
            timeout=timeout,
        )

    def start(self) -> dict[str, Any]:
        source = str(self.runtime.pop("source"))
        upstream_key = str(self.runtime.pop("upstream_api_key"))
        embedding_source = self.runtime.pop("embedding_source", None)
        embedding_key = self.runtime.pop("embedding_upstream_api_key", None)
        embedding_config = None
        if embedding_source is not None:
            if (
                not embedding_key
                or not self.runtime.get("embedding_model")
                or not self.runtime.get("embedding_upstream_base_url")
            ):
                raise ValueError("provider_relay_incomplete_embedding_config")
            embedding_config = {
                "model": self.runtime.pop("embedding_model"),
                "base_url": self.runtime.pop("embedding_upstream_base_url"),
                # The adapter's api_key is the upstream credential; the
                # separate ingress_token authenticates Victim-to-relay calls.
                "api_key": embedding_key,
                "ingress_token": self.embedding_ingress_token,
                "max_requests": int(self.runtime.pop("embedding_request_budget", 128)),
                "timeout_seconds": int(self.runtime.get("timeout_seconds", 90)),
                "ledger_path": "/var/lib/stac-ledger/embedding.jsonl",
                "batch_id": self.batch_id,
                "port": 18792,
                "host": "0.0.0.0",
            }
        config = {
            **self.runtime,
            "batch_id": self.batch_id,
            "ledger_path": "/var/lib/stac-ledger/provider.jsonl",
            "upstream_api_key": upstream_key,
            "ingress_token": self.ingress_token,
        }
        try:
            self._docker("volume", "create", self.volume)
            self._docker("network", "create", "--internal", self.network)
            self._docker("network", "connect", self.network, self.victim_container)
            self._docker("network", "disconnect", "bridge", self.victim_container)
            self._docker(
                "run",
                "-d",
                "--name",
                self.container,
                "--network",
                self.network,
                "--mount",
                f"type=volume,source={self.volume},destination=/var/lib/stac-ledger",
                self.image,
                "sleep",
                "infinity",
            )
            # Only the relay receives an egress-capable interface. The Victim
            # remains on the internal benchmark network and can reach upstream
            # HTTP only through this authenticated, budgeted process.
            self._docker("network", "connect", "bridge", self.container)
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
            if embedding_config is not None:
                self._docker(
                    "exec",
                    "-i",
                    self.container,
                    "sh",
                    "-c",
                    "umask 077; cat > /tmp/stac_embedding_proxy.py",
                    input_data=str(embedding_source).encode(),
                )
                self._docker(
                    "exec",
                    "-i",
                    self.container,
                    "sh",
                    "-c",
                    "umask 077; cat > /tmp/stac_embedding_proxy.json",
                    input_data=json.dumps(embedding_config).encode(),
                )
                self._docker(
                    "exec",
                    "-d",
                    self.container,
                    "python3",
                    "/tmp/stac_embedding_proxy.py",
                    "/tmp/stac_embedding_proxy.json",
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
                    if embedding_config is not None:
                        embedding_health = self._docker(
                            "exec",
                            self.victim_container,
                            "python3",
                            "-c",
                            "import urllib.request; urllib.request.urlopen('http://"
                            + self.container
                            + ":18792/health',timeout=1).close()",
                            check=False,
                        )
                        if embedding_health.returncode != 0:
                            time.sleep(0.1)
                            continue
                        self.embedding_started = True
                    self.started = True
                    result: dict[str, Any] = {
                        "api_base_url": f"http://{self.container}:18791/v1",
                        "api_key": self.ingress_token,
                    }
                    if embedding_config is not None:
                        result.update(
                            {
                                "embedding_provider": "openai",
                                "embedding_model": embedding_config["model"],
                                "embedding_api_base_url": f"http://{self.container}:18792/v1",
                                "embedding_api_key": self.embedding_ingress_token,
                                "embedding_relay_configured": True,
                            }
                        )
                    return result
                time.sleep(0.1)
            raise RuntimeError("provider_relay_health_timeout")
        except Exception:
            self.stop()
            raise

    def embedding_probe(self, *, from_victim: bool, model: str, text: str) -> dict[str, Any]:
        """Send one bounded embedding request from relay or Victim network namespace."""
        if not self.embedding_started:
            raise RuntimeError("embedding_relay_not_started")
        target = self.victim_container if from_victim else self.container
        host = self.container if from_victim else "127.0.0.1"
        script = "\n".join(
            [
                "import hashlib,json,math,sys,urllib.error,urllib.request",
                "c=json.load(sys.stdin)",
                "body=json.dumps({'model':c['model'],'input':c['text']}).encode()",
                "headers={'Authorization':'Bearer '+c['token'],",
                "         'Content-Type':'application/json'}",
                "r=urllib.request.Request(c['url'],data=body,headers=headers)",
                "try:",
                " with urllib.request.urlopen(r,timeout=c['timeout']) as x:",
                "  raw=x.read(); status=getattr(x,'status',None) or x.getcode()",
                "  data=json.loads(raw)",
                "  rows=data.get('data') if isinstance(data,dict) else None",
                "  e=rows[0].get('embedding') if (isinstance(rows,list) and rows",
                "     and isinstance(rows[0],dict)) else None",
                "  valid=(isinstance(rows,list) and len(rows)==1 and isinstance(e,list)",
                "     and bool(e) and all(",
                "      type(v) in (int,float) and math.isfinite(v) for v in e))",
                "  u=data.get('usage') if isinstance(data,dict) else None",
                "  print(json.dumps({'status':status,'dimension':len(e) if valid else None,",
                "    'finite_nonempty':valid,'usage':u if isinstance(u,dict) else None},",
                "    sort_keys=True))",
                "except urllib.error.HTTPError as x:",
                " raw=x.read(1048576)",
                " print(json.dumps({'status':x.code,'error_category':'upstream_http_error',",
                "   'body_length':len(raw),'body_hash':hashlib.sha256(raw).hexdigest()},",
                "   sort_keys=True))",
                "except TimeoutError:",
                " print(json.dumps({'status':None,'error_category':'read_timeout'},",
                "   sort_keys=True))",
                "except Exception as x:",
                " print(json.dumps({'status':None,'error_category':type(x).__name__},",
                "   sort_keys=True))",
            ]
        )
        payload = json.dumps(
            {
                "url": f"http://{host}:18792/v1/embeddings",
                "token": self.embedding_ingress_token,
                "model": model,
                "text": text,
                "timeout": min(90, int(self.runtime.get("timeout_seconds", 90))),
            }
        ).encode()
        outer_timeout = min(105, max(35, int(self.runtime.get("timeout_seconds", 90)) + 10))
        result = self._docker(
            "exec",
            "-i",
            target,
            "timeout",
            f"{outer_timeout}s",
            "python3",
            "-c",
            script,
            input_data=payload,
            timeout=outer_timeout + 5,
        )
        if result.returncode != 0:
            raise RuntimeError("embedding_probe_process_failed")
        return _parse_embedding_probe_output(result.stdout)

    def embedding_records(self) -> list[dict[str, Any]]:
        if not self.embedding_started:
            return []
        result = self._docker(
            "exec",
            self.container,
            "sh",
            "-c",
            "cat /var/lib/stac-ledger/embedding.jsonl 2>/dev/null || true",
            check=False,
        )
        return _parse_jsonl_records(result.stdout, corruption="embedding_ledger_corrupt")

    def records(self) -> list[dict[str, Any]]:
        if not self.started:
            return []
        result = self._docker(
            "exec",
            self.container,
            "sh",
            "-c",
            "cat /var/lib/stac-ledger/provider.jsonl 2>/dev/null || true",
            check=False,
        )
        return _parse_jsonl_records(result.stdout, corruption="provider_ledger_corrupt")

    def stop(self) -> None:
        # The named ledger volume is intentionally retained across container
        # rebuilds; callers may remove it only after archiving its evidence.
        self._docker("rm", "-f", self.container, check=False)
        self._docker("network", "disconnect", self.network, self.victim_container, check=False)
        self._docker("network", "rm", self.network, check=False)
        self.started = False
        self.embedding_started = False


def relay_runtime_from_model_config(value: dict[str, Any]) -> dict[str, Any] | None:
    source = value.pop("provider_relay_source", None)
    if source is None:
        return None
    allowed_tools = value.pop("provider_allowed_tools", None)
    if allowed_tools is not None:
        value["openclaw_allowed_tools"] = allowed_tools
    runtime = {
        "source": source,
        "upstream_base_url": value.pop("provider_upstream_base_url"),
        "upstream_api_key": value.pop("provider_upstream_api_key"),
        "max_requests": value.pop("provider_request_budget", 8),
        "timeout_seconds": value.pop("provider_timeout_seconds", 90),
        "allowed_tools": allowed_tools,
        "provider_compat": value.pop("provider_compat", "openai"),
        "batch_id": value.pop("batch_id", None),
    }
    embedding_provider = value.get("embedding_provider")
    if embedding_provider is not None and embedding_provider != "ark_multimodal":
        # A raw OpenAI embedding key must never be copied into Victim.  Only
        # the independently hosted Ark adapter has a relay contract today.
        raise ValueError("embedding_provider_requires_independent_relay_adapter")
    if embedding_provider == "ark_multimodal":
        # The adapter and upstream credential stay in this egress relay.
        value["embedding_provider"] = "openai"
        runtime.update(
            {
                "embedding_source": value.pop("embedding_adapter_source"),
                "embedding_model": value.pop("embedding_model"),
                "embedding_upstream_base_url": value.pop("embedding_api_base_url"),
                "embedding_upstream_api_key": value.pop("embedding_api_key"),
                "embedding_request_budget": value.pop("embedding_request_budget", 128),
            }
        )
    return runtime


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
