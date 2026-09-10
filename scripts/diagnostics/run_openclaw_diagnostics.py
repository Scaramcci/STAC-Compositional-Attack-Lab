#!/usr/bin/env python3
"""Run the repeatable, network-isolated OpenClaw transport/tool diagnostic."""
# ruff: noqa: E501

from __future__ import annotations

import argparse
import json
import os
import shlex
import subprocess
import time
import uuid
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[2]
IMAGE = "openclaw-env:2026.3.12"
GATEWAY_PORT = 18789
MOCK_PORT = 19090
RELAY_PORT = 18791

ADD_MANIFEST = {
    "id": "stac-add",
    "name": "STAC deterministic add",
    "description": "A deterministic diagnostic-only addition tool.",
    "configSchema": {"type": "object", "additionalProperties": False, "properties": {}},
}
ADD_PACKAGE = {
    "name": "stac-add",
    "version": "1.0.0",
    "type": "module",
    "openclaw": {"extensions": ["./index.js"]},
}
ADD_PLUGIN = r"""import fs from "node:fs";
const plugin = {
  id: "stac-add",
  name: "STAC deterministic add",
  register(api) {
    api.registerTool({
      name: "add",
      description: "Add two integers locally.",
      parameters: {
        type: "object",
        additionalProperties: false,
        properties: {a: {type: "integer"}, b: {type: "integer"}},
        required: ["a", "b"]
      },
      async execute(callId, params) {
        const result = Number(params.a) + Number(params.b);
        fs.appendFileSync("/tmp/stac-add-executions.jsonl", JSON.stringify({callId, params, result}) + "\n");
        return {content: [{type: "text", text: String(result)}]};
      }
    });
  }
};
export default plugin;
"""

MOCK_SERVER = r"""import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

CALL_ID = "calladd1"

def names(tools):
    return [item.get("function", {}).get("name") for item in tools or []]

def write_capture(item):
    with open("/tmp/mock-captures.jsonl", "a", encoding="utf-8") as stream:
        stream.write(json.dumps(item, sort_keys=True) + "\n")

class Handler(BaseHTTPRequestHandler):
    def log_message(self, *_args):
        return

    def send_body(self, status, body, content_type="application/json"):
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        self.send_body(200, b'{"status":"ok"}')

    def do_POST(self):
        size = int(self.headers.get("Content-Length", "0"))
        payload = json.loads(self.rfile.read(size))
        messages = payload.get("messages") or []
        tools = payload.get("tools") or []
        tool_messages = [item for item in messages if item.get("role") == "tool"]
        capture = {
            "path": self.path,
            "tool_names": names(tools),
            "stream": bool(payload.get("stream")),
            "tool_results": [
                {"tool_call_id": item.get("tool_call_id"), "content": item.get("content")}
                for item in tool_messages
            ],
        }
        write_capture(capture)
        if names(tools) != ["add"]:
            self.send_body(400, b'{"error":{"message":"unexpected_tool_list"}}')
            return
        if tool_messages:
            valid = len(tool_messages) == 1 and tool_messages[0].get("tool_call_id") == CALL_ID and str(tool_messages[0].get("content")) == "5"
            if not valid:
                self.send_body(400, b'{"error":{"message":"invalid_tool_result"}}')
                return
            chunks = [
                {"id":"mock-final","object":"chat.completion.chunk","model":"mock-model","choices":[{"index":0,"delta":{"content":"SUM="},"finish_reason":None}]},
                {"id":"mock-final","object":"chat.completion.chunk","model":"mock-model","choices":[{"index":0,"delta":{"content":"5"},"finish_reason":"stop"}]},
            ]
        else:
            chunks = [
                {"id":"mock-tool","object":"chat.completion.chunk","model":"mock-model","choices":[{"index":0,"delta":{"role":"assistant","tool_calls":[{"index":0,"id":CALL_ID,"type":"function","function":{"name":"add","arguments":"{\"a\":"}}]},"finish_reason":None}]},
                {"id":"mock-tool","object":"chat.completion.chunk","model":"mock-model","choices":[{"index":0,"delta":{"tool_calls":[{"index":0,"function":{"arguments":"2,\"b\":3}"}}]},"finish_reason":"tool_calls"}]},
            ]
        data = "".join("data: " + json.dumps(chunk, separators=(",", ":")) + "\n\n" for chunk in chunks) + "data: [DONE]\n\n"
        self.send_body(200, data.encode(), "text/event-stream")

ThreadingHTTPServer(("127.0.0.1", 19090), Handler).serve_forever()
"""


def docker(
    *args: str,
    input_text: str | None = None,
    timeout: int = 30,
    check: bool = False,
) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["docker", *args],
        input=input_text,
        text=True,
        capture_output=True,
        timeout=timeout,
        check=check,
    )


def put(container: str, path: str, content: str) -> None:
    result = docker(
        "exec",
        "-i",
        container,
        "sh",
        "-c",
        f"umask 077; mkdir -p $(dirname {path}); cat > {path}",
        input_text=content,
    )
    if result.returncode:
        raise RuntimeError(f"container_file_write_failed:{path}:{result.stderr[-300:]}")


def json_lines(raw: str) -> list[dict[str, Any]]:
    values: list[dict[str, Any]] = []
    for line in raw.splitlines():
        try:
            value = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(value, dict):
            values.append(value)
    return values


def openclaw_config(
    relay_host: str,
    provider_token: str,
    gateway_token: str,
    *,
    model: str,
    enable_add: bool,
) -> dict[str, Any]:
    value: dict[str, Any] = {
        "gateway": {
            "mode": "local",
            "bind": "loopback",
            "port": GATEWAY_PORT,
            "auth": {"mode": "token", "token": gateway_token},
            "http": {"endpoints": {"chatCompletions": {"enabled": True}}},
        },
        "browser": {"enabled": False},
        "auth": {"profiles": {"openai:default": {"provider": "openai", "mode": "api_key"}}},
        "agents": {
            "defaults": {
                "model": {"primary": f"openai/{model}"},
                "workspace": "/root/.openclaw/workspace",
            }
        },
        "models": {
            "mode": "merge",
            "providers": {
                "openai": {
                    "baseUrl": f"http://{relay_host}:{RELAY_PORT}/v1",
                    "api": "openai-completions",
                    "apiKey": provider_token,
                    "models": [
                        {
                            "id": model,
                            "name": model,
                            "contextWindow": 200000,
                            "maxTokens": 1024,
                            "input": ["text"],
                            "cost": {"input": 0, "output": 0, "cacheRead": 0, "cacheWrite": 0},
                            "reasoning": False,
                            "compat": {
                                "supportsStore": False,
                                "supportsUsageInStreaming": False,
                                "maxTokensField": "max_tokens",
                                "supportsStrictMode": False,
                            },
                        }
                    ],
                }
            },
        },
        "tools": ({"allow": ["add"]} if enable_add else {"deny": ["*"]}),
    }
    if enable_add:
        value["plugins"] = {
            "allow": ["stac-add"],
            "load": {"paths": ["/tmp/stac-add"]},
            "entries": {"stac-add": {"enabled": True}},
        }
    return value


def put_auth_profile(container: str, provider_token: str) -> None:
    put(
        container,
        "/root/.openclaw/agents/main/agent/auth-profiles.json",
        json.dumps(
            {
                "version": 1,
                "profiles": {
                    "openai:default": {
                        "type": "api_key",
                        "provider": "openai",
                        "key": provider_token,
                    }
                },
            }
        ),
    )


def wait_gateway(container: str, token: str) -> None:
    deadline = time.monotonic() + 45
    while time.monotonic() < deadline:
        result = docker(
            "exec",
            container,
            "openclaw",
            "gateway",
            "call",
            "health",
            "--json",
            "--token",
            token,
            timeout=10,
        )
        if result.returncode == 0:
            return
        time.sleep(0.5)
    raise RuntimeError("openclaw_gateway_health_timeout")


def run_offline(output: Path) -> dict[str, Any]:
    suffix = uuid.uuid4().hex[:12]
    network = f"stac-diag-net-{suffix}"
    victim = f"stac-diag-victim-{suffix}"
    backend = f"stac-diag-provider-{suffix}"
    gateway_token = uuid.uuid4().hex
    provider_token = uuid.uuid4().hex
    upstream_token = uuid.uuid4().hex
    owned = {"network": network, "containers": [victim, backend]}
    result: dict[str, Any] = {"status": "failed", "owned_resources": owned}
    try:
        docker("network", "create", "--internal", network, check=True)
        for name in (backend, victim):
            docker(
                "run",
                "-d",
                "--name",
                name,
                "--network",
                network,
                IMAGE,
                "sleep",
                "infinity",
                check=True,
            )

        put(backend, "/tmp/mock.py", MOCK_SERVER)
        put(
            backend,
            "/tmp/stac_provider_relay.py",
            (ROOT / "src/stac_attack_lab/environments/safeclaw/provider_relay.py").read_text(
                encoding="utf-8"
            ),
        )
        relay_config = {
            "upstream_base_url": f"http://127.0.0.1:{MOCK_PORT}/v1",
            "upstream_api_key": upstream_token,
            "ingress_token": provider_token,
            "max_requests": 3,
            "timeout_seconds": 10,
            "allowed_tools": ["add"],
        }
        put(backend, "/tmp/relay.json", json.dumps(relay_config))
        docker("exec", "-d", backend, "python3", "/tmp/mock.py", check=True)
        docker(
            "exec",
            "-d",
            backend,
            "python3",
            "/tmp/stac_provider_relay.py",
            "--config",
            "/tmp/relay.json",
            "--host",
            "0.0.0.0",
            "--port",
            str(RELAY_PORT),
            check=True,
        )

        put(victim, "/tmp/stac-add/openclaw.plugin.json", json.dumps(ADD_MANIFEST))
        put(victim, "/tmp/stac-add/package.json", json.dumps(ADD_PACKAGE))
        put(victim, "/tmp/stac-add/index.js", ADD_PLUGIN)
        put(
            victim,
            "/root/.openclaw/openclaw.json",
            json.dumps(
                openclaw_config(
                    backend,
                    provider_token,
                    gateway_token,
                    model="mock-model",
                    enable_add=True,
                )
            ),
        )
        put_auth_profile(victim, provider_token)
        validate = docker("exec", victim, "openclaw", "config", "validate", timeout=20)
        plugins = docker("exec", victim, "openclaw", "plugins", "list", timeout=20)
        if validate.returncode or "stac-add" not in plugins.stdout:
            raise RuntimeError(
                f"openclaw_plugin_validation_failed:{validate.stderr[-300:]}:{plugins.stdout[-500:]}:{plugins.stderr[-300:]}"
            )
        docker(
            "exec",
            "-d",
            victim,
            "sh",
            "-c",
            f"openclaw gateway run --port {GATEWAY_PORT} --bind loopback --auth token --token {gateway_token} >/tmp/gateway.log 2>&1",
            check=True,
        )
        wait_gateway(victim, gateway_token)
        gateway_payload = json.dumps(
            {
                "model": "openclaw",
                "messages": [
                    {
                        "role": "user",
                        "content": "Use add exactly once to calculate 2+3, then report the result.",
                    }
                ],
                "stream": False,
            }
        )
        gateway = docker(
            "exec",
            "-i",
            victim,
            "curl",
            "-sS",
            "--max-time",
            "30",
            "-H",
            f"Authorization: Bearer {gateway_token}",
            "-H",
            "Content-Type: application/json",
            "-d",
            gateway_payload,
            f"http://127.0.0.1:{GATEWAY_PORT}/v1/chat/completions",
            timeout=40,
        )
        wrong_payload = json.dumps(
            {
                "model": "mock-model",
                "messages": [{"role": "tool", "tool_call_id": "wrong-call", "content": "ERROR"}],
                "tools": [
                    {
                        "type": "function",
                        "function": {
                            "name": "add",
                            "description": "add",
                            "parameters": {"type": "object"},
                        },
                    }
                ],
                "stream": False,
            }
        )
        wrong = docker(
            "exec",
            "-i",
            victim,
            "curl",
            "-sS",
            "-o",
            "/tmp/wrong.out",
            "-w",
            "%{http_code}",
            "--max-time",
            "10",
            "-H",
            f"Authorization: Bearer {provider_token}",
            "-H",
            "Content-Type: application/json",
            "-d",
            wrong_payload,
            f"http://{backend}:{RELAY_PORT}/v1/chat/completions",
        )
        over = docker(
            "exec",
            "-i",
            victim,
            "curl",
            "-sS",
            "-o",
            "/tmp/over.out",
            "-w",
            "%{http_code}",
            "--max-time",
            "10",
            "-H",
            f"Authorization: Bearer {provider_token}",
            "-H",
            "Content-Type: application/json",
            "-d",
            wrong_payload,
            f"http://{backend}:{RELAY_PORT}/v1/chat/completions",
        )
        captures = json_lines(
            docker(
                "exec", backend, "sh", "-c", "cat /tmp/mock-captures.jsonl 2>/dev/null || true"
            ).stdout
        )
        ledger = json_lines(
            docker(
                "exec",
                backend,
                "sh",
                "-c",
                "cat /tmp/stac-provider-ledger.jsonl 2>/dev/null || true",
            ).stdout
        )
        executions = json_lines(
            docker(
                "exec", victim, "sh", "-c", "cat /tmp/stac-add-executions.jsonl 2>/dev/null || true"
            ).stdout
        )
        gateway_json = json.loads(gateway.stdout) if gateway.stdout.strip() else {}
        response_text = json.dumps(gateway_json, ensure_ascii=False)
        assertions = {
            "gateway_succeeded": gateway.returncode == 0 and "SUM=5" in response_text,
            "only_add_reached_provider": len(captures) >= 2
            and all(item.get("tool_names") == ["add"] for item in captures),
            "fragmented_arguments_merged": len(captures) >= 2
            and captures[1].get("tool_results") == [{"tool_call_id": "calladd1", "content": "5"}],
            "add_executed_once": len(executions) == 1
            and executions[0].get("params") == {"a": 2, "b": 3}
            and executions[0].get("result") == 5,
            "bad_tool_result_rejected": wrong.stdout == "400",
            "request_budget_rejected": over.stdout == "429"
            and len(ledger) == 4
            and ledger[-1].get("accepted") is False,
            "ledger_counts_actual_http": [item.get("accepted") for item in ledger]
            == [True, True, True, False],
            "relay_path_is_not_double_v1": all(
                item.get("upstream_path") == "/v1/chat/completions"
                for item in ledger
                if item.get("accepted")
            ),
        }
        result = {
            "status": "passed" if all(assertions.values()) else "failed",
            "assertions": assertions,
            "provider_request_ledger": ledger,
            "provider_captures": captures,
            "add_executions": executions,
            "gateway_response": gateway_json,
            "config_validation": validate.stdout.strip(),
            "network_isolation": "docker_internal_network",
            "owned_resources": owned,
        }
        if result["status"] != "passed":
            result["gateway_log_tail"] = docker(
                "exec", victim, "sh", "-c", "tail -120 /tmp/gateway.log 2>/dev/null || true"
            ).stdout[-12000:]
    except Exception as exc:
        result["error"] = f"{type(exc).__name__}:{exc}"
        result["gateway_log_tail"] = docker(
            "exec", victim, "sh", "-c", "tail -120 /tmp/gateway.log 2>/dev/null || true"
        ).stdout[-12000:]
    finally:
        for name in (victim, backend):
            docker("rm", "-f", name)
        docker("network", "rm", network)
    output.mkdir(parents=True, exist_ok=False)
    (output / "offline_openclaw_diagnostic.json").write_text(
        json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    return result


def project_env() -> dict[str, str]:
    values = dict(os.environ)
    env_path = ROOT / ".env"
    if not env_path.exists():
        return values
    for raw in env_path.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("export "):
            line = line[7:].lstrip()
        if "=" not in line:
            continue
        key, encoded = line.split("=", 1)
        key = key.strip()
        if key in values:
            continue
        parsed = shlex.split(encoded, comments=True, posix=True)
        if len(parsed) == 1:
            values[key] = parsed[0]
    return values


def run_live_phase(
    *,
    phase: str,
    model: str,
    base_url: str,
    upstream_key: str,
    enable_add: bool,
    max_requests: int,
) -> dict[str, Any]:
    suffix = uuid.uuid4().hex[:12]
    network = f"stac-live-net-{suffix}"
    victim = f"stac-live-victim-{suffix}"
    relay = f"stac-live-provider-{suffix}"
    gateway_token = uuid.uuid4().hex
    provider_token = uuid.uuid4().hex
    result: dict[str, Any] = {"phase": phase, "status": "failed"}
    try:
        docker("network", "create", network, check=True)
        for name in (relay, victim):
            docker(
                "run",
                "-d",
                "--name",
                name,
                "--network",
                network,
                IMAGE,
                "sleep",
                "infinity",
                check=True,
            )
        put(
            relay,
            "/tmp/stac_provider_relay.py",
            (ROOT / "src/stac_attack_lab/environments/safeclaw/provider_relay.py").read_text(
                encoding="utf-8"
            ),
        )
        put(
            relay,
            "/tmp/relay.json",
            json.dumps(
                {
                    "upstream_base_url": base_url,
                    "upstream_api_key": upstream_key,
                    "ingress_token": provider_token,
                    "max_requests": max_requests,
                    "timeout_seconds": 90,
                    "allowed_tools": ["add"] if enable_add else [],
                }
            ),
        )
        docker(
            "exec",
            "-d",
            relay,
            "python3",
            "/tmp/stac_provider_relay.py",
            "--config",
            "/tmp/relay.json",
            "--host",
            "0.0.0.0",
            "--port",
            str(RELAY_PORT),
            check=True,
        )
        if enable_add:
            put(victim, "/tmp/stac-add/openclaw.plugin.json", json.dumps(ADD_MANIFEST))
            put(victim, "/tmp/stac-add/package.json", json.dumps(ADD_PACKAGE))
            put(victim, "/tmp/stac-add/index.js", ADD_PLUGIN)
        put(
            victim,
            "/root/.openclaw/openclaw.json",
            json.dumps(
                openclaw_config(
                    relay,
                    provider_token,
                    gateway_token,
                    model=model,
                    enable_add=enable_add,
                )
            ),
        )
        put_auth_profile(victim, provider_token)
        validate = docker("exec", victim, "openclaw", "config", "validate", timeout=20)
        if validate.returncode:
            raise RuntimeError(f"live_config_invalid:{validate.stderr[-500:]}")
        deadline = time.monotonic() + 10
        while time.monotonic() < deadline:
            health = docker(
                "exec",
                victim,
                "python3",
                "-c",
                f"import urllib.request; urllib.request.urlopen('http://{relay}:{RELAY_PORT}/health',timeout=1).close()",
            )
            if health.returncode == 0:
                break
            time.sleep(0.2)
        else:
            raise RuntimeError("live_relay_health_timeout")
        docker(
            "exec",
            "-d",
            victim,
            "sh",
            "-c",
            f"openclaw gateway run --port {GATEWAY_PORT} --bind loopback --auth token --token {gateway_token} >/tmp/gateway.log 2>&1",
            check=True,
        )
        wait_gateway(victim, gateway_token)
        prompt = (
            "Use the add tool exactly once to calculate 2+3, then answer with the result."
            if enable_add
            else "Reply with exactly ARK_TEXT_OK and do not use any tool."
        )
        payload = json.dumps(
            {
                "model": "openclaw",
                "messages": [{"role": "user", "content": prompt}],
                "stream": False,
            }
        )
        gateway = docker(
            "exec",
            "-i",
            victim,
            "curl",
            "-sS",
            "--max-time",
            "90",
            "-H",
            f"Authorization: Bearer {gateway_token}",
            "-H",
            "Content-Type: application/json",
            "-d",
            payload,
            f"http://127.0.0.1:{GATEWAY_PORT}/v1/chat/completions",
            timeout=100,
        )
        ledger = json_lines(
            docker(
                "exec",
                relay,
                "sh",
                "-c",
                "cat /tmp/stac-provider-ledger.jsonl 2>/dev/null || true",
            ).stdout
        )
        executions = json_lines(
            docker(
                "exec",
                victim,
                "sh",
                "-c",
                "cat /tmp/stac-add-executions.jsonl 2>/dev/null || true",
            ).stdout
        )
        response = json.loads(gateway.stdout) if gateway.stdout.strip() else {}
        response_text = json.dumps(response, ensure_ascii=False)
        checks = {
            "gateway_http_completed": gateway.returncode == 0,
            "all_provider_requests_succeeded": bool(ledger)
            and all(item.get("accepted") and item.get("status") == 200 for item in ledger),
            "request_budget_respected": len([item for item in ledger if item.get("accepted")])
            <= max_requests,
            "ark_path_exact": all(
                item.get("upstream_path") == "/api/v3/chat/completions" for item in ledger
            ),
            "tool_policy": all(
                item.get("final_tools") == (["add"] if enable_add else []) for item in ledger
            ),
            "semantic_result": (
                len(executions) == 1 and executions[0].get("result") == 5 and "5" in response_text
                if enable_add
                else "ARK_TEXT_OK" in response_text
            ),
        }
        raw_usage = response.get("usage")
        reported_usage = (
            raw_usage
            if isinstance(raw_usage, dict)
            and any(isinstance(value, (int, float)) and value > 0 for value in raw_usage.values())
            else "unknown"
        )
        result = {
            "phase": phase,
            "status": "passed" if all(checks.values()) else "failed",
            "checks": checks,
            "provider_request_ledger": ledger,
            "provider_http_request_count": len([item for item in ledger if item.get("accepted")]),
            "response": response,
            "usage": reported_usage,
            "add_executions": executions,
        }
        if result["status"] != "passed":
            result["gateway_log_tail"] = docker(
                "exec",
                victim,
                "sh",
                "-c",
                "tail -100 /tmp/gateway.log 2>/dev/null || true",
            ).stdout[-10000:]
    except Exception as exc:
        result["error"] = f"{type(exc).__name__}:{exc}"
    finally:
        for name in (victim, relay):
            docker("rm", "-f", name)
        docker("network", "rm", network)
    return result


def run_live(output: Path) -> dict[str, Any]:
    env = project_env()
    model = env.get("SAFECLAW_MODEL", "")
    base_url = env.get("SAFECLAW_BASE_URL", "").rstrip("/")
    key = env.get("SAFECLAW_API_KEY", "")
    if model != "ep-20260909180104-hmx9m":
        raise RuntimeError("live_model_mismatch")
    if base_url != "https://ark.cn-beijing.volces.com/api/v3":
        raise RuntimeError("live_base_url_mismatch")
    if not key:
        raise RuntimeError("live_api_key_missing")
    phases = [
        run_live_phase(
            phase="text",
            model=model,
            base_url=base_url,
            upstream_key=key,
            enable_add=False,
            max_requests=1,
        )
    ]
    if phases[0]["status"] == "passed":
        phases.append(
            run_live_phase(
                phase="add",
                model=model,
                base_url=base_url,
                upstream_key=key,
                enable_add=True,
                max_requests=2,
            )
        )
    total = sum(int(item.get("provider_http_request_count", 0)) for item in phases)
    result = {
        "status": "passed"
        if len(phases) == 2 and all(item["status"] == "passed" for item in phases)
        else "failed",
        "provider_http_request_count": total,
        "hard_limit": 8,
        "phases": phases,
    }
    if total > 8:
        raise RuntimeError("live_request_budget_invariant_broken")
    output.mkdir(parents=True, exist_ok=False)
    (output / "live_openclaw_ark_diagnostic.json").write_text(
        json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    return result


def main() -> int:
    global IMAGE
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--mode", choices=("offline", "live"), default="offline")
    parser.add_argument("--run-id", default=f"diagnostic-{uuid.uuid4().hex[:12]}")
    parser.add_argument("--image", default=IMAGE)
    args = parser.parse_args()
    IMAGE = args.image
    if "/" in args.run_id or args.run_id in {".", ".."}:
        raise SystemExit("invalid_run_id")
    output = ROOT / "experiments" / "runs" / args.run_id
    result = run_offline(output) if args.mode == "offline" else run_live(output)
    print(json.dumps({"status": result["status"], "output": str(output)}, sort_keys=True))
    return 0 if result["status"] == "passed" else 1


if __name__ == "__main__":
    raise SystemExit(main())
