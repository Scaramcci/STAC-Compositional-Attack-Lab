#!/usr/bin/env python3
"""Run a disposable, network-isolated OpenClaw -> localhost mock probe."""
# ruff: noqa: E501

from __future__ import annotations

import base64
import json
import subprocess
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
OUT = ROOT / "experiments/stage-b-20260909-openclaw-mock-01"
CONTAINER = "stac-openclaw-mock-01"
IMAGE = "openclaw-env:2026.3.12"


def run(*args: str, check: bool = False, timeout: int = 30) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["docker", *args], text=True, capture_output=True, check=check, timeout=timeout
    )


def main() -> int:
    OUT.mkdir(parents=True, exist_ok=True)
    run("rm", "-f", CONTAINER)
    started = run("run", "-d", "--network", "none", "--name", CONTAINER, IMAGE, "sleep", "infinity")
    if started.returncode != 0:
        (OUT / "tool_integration_result_v3.json").write_text(
            json.dumps(
                {"status": "container_start_failed", "stderr": started.stderr[-500:]}, indent=2
            )
            + "\n"
        )
        return 1
    config = {
        "gateway": {
            "mode": "local",
            "bind": "loopback",
            "port": 18789,
            "auth": {"mode": "token", "token": "fake-gateway-token"},
            "http": {
                "endpoints": {"chatCompletions": {"enabled": True}, "responses": {"enabled": False}}
            },
        },
        "auth": {"profiles": {"openai:default": {"provider": "openai", "mode": "api_key"}}},
        "agents": {
            "defaults": {
                "model": {"primary": "openai/mock-model"},
                "workspace": "/root/.openclaw/workspace",
            }
        },
        "models": {
            "mode": "merge",
            "providers": {
                "openai": {
                    "baseUrl": "http://127.0.0.1:19090/v1",
                    "api": "openai-completions",
                    "apiKey": "fake-provider-key",
                    "models": [
                        {
                            "id": "mock-model",
                            "name": "mock",
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
        "tools": {
            "allow": ["add"],
            "deny": ["exec", "process", "read", "write", "edit", "browser"],
        },
        "plugins": {"load": {"paths": ["/tmp/add-plugin.js"]}},
    }
    config_json = json.dumps(config)
    plugin_code = r"""module.exports = {
  id: "local-add",
  name: "local-add",
  register(api) {
    api.registerTool({
      name: "add",
      description: "Add two numbers locally",
      parameters: {type: "object", properties: {a: {type: "number"}, b: {type: "number"}}, required: ["a", "b"]},
      async execute(_id, params) { return {content: [{type: "text", text: String(Number(params.a) + Number(params.b))}]}; }
    });
  }
};
"""
    mock_code = r"""import json, time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
class H(BaseHTTPRequestHandler):
  def log_message(self,*a): pass
  def do_GET(self):
    self.send_response(200); self.send_header("Content-Length","2"); self.end_headers(); self.wfile.write(b"OK")
  def do_POST(self):
    n=int(self.headers.get("content-length","0")); raw=self.rfile.read(n)
    body=json.loads(raw)
    safe={"path":self.path,"headers":{k.lower():v for k,v in self.headers.items() if k.lower() not in ("authorization","proxy-authorization")},"body":body,"received_at":time.time()}
    try:
      captures=json.load(open("/tmp/mock-captures.json"))
except Exception:
      captures=[]
    captures.append({"path":safe["path"],"headers":safe["headers"],"body":body,"received_at":safe["received_at"]})
    json.dump(captures,open("/tmp/mock-captures.json","w"))
    has_tool_result=any(isinstance(m,dict) and m.get("role")=="tool" for m in body.get("messages",[]))
    if has_tool_result:
      out={"id":"mock-response-final","object":"chat.completion","model":"mock-model","choices":[{"index":0,"message":{"role":"assistant","content":"SUM=5"},"finish_reason":"stop"}],"usage":{"prompt_tokens":1,"completion_tokens":1,"total_tokens":2}}
    else:
      out={"id":"mock-response-tool","object":"chat.completion","model":"mock-model","choices":[{"index":0,"message":{"role":"assistant","content":None,"tool_calls":[{"id":"call-add-1","type":"function","function":{"name":"add","arguments":"{\"a\":2,\"b\":3}"}}]},"finish_reason":"tool_calls"}],"usage":{"prompt_tokens":1,"completion_tokens":1,"total_tokens":2}}
    if body.get("stream"):
      if has_tool_result:
        chunk={"id":"mock-response-final","object":"chat.completion.chunk","model":"mock-model","choices":[{"index":0,"delta":{"role":"assistant","content":"SUM=5"},"finish_reason":"stop"}]}
      else:
        chunk={"id":"mock-response-tool","object":"chat.completion.chunk","model":"mock-model","choices":[{"index":0,"delta":{"role":"assistant","tool_calls":[{"index":0,"id":"call-add-1","type":"function","function":{"name":"add","arguments":"{\"a\":2,\"b\":3}"}}]},"finish_reason":"tool_calls"}]}
      b=("data: "+json.dumps(chunk)+"\n\ndata: [DONE]\n\n").encode(); ctype="text/event-stream"
    else:
      b=json.dumps(out).encode(); ctype="application/json"
    self.send_response(200); self.send_header("Content-Type",ctype); self.send_header("Content-Length",str(len(b))); self.end_headers(); self.wfile.write(b)
ThreadingHTTPServer(("127.0.0.1",19090),H).serve_forever()
"""
    try:
        config_b64 = base64.b64encode(config_json.encode()).decode()
        run(
            "exec",
            CONTAINER,
            "python3",
            "-c",
            "import base64; open('/root/.openclaw/openclaw.json','wb').write(base64.b64decode('"
            + config_b64
            + "'))",
            timeout=10,
        )
        mock_b64 = base64.b64encode(mock_code.encode()).decode()
        run(
            "exec",
            CONTAINER,
            "python3",
            "-c",
            "import base64; open('/tmp/mock.py','wb').write(base64.b64decode('" + mock_b64 + "'))",
            timeout=10,
        )
        plugin_b64 = base64.b64encode(plugin_code.encode()).decode()
        run(
            "exec",
            CONTAINER,
            "python3",
            "-c",
            "import base64; open('/tmp/add-plugin.js','wb').write(base64.b64decode('"
            + plugin_b64
            + "'))",
            timeout=10,
        )
        mock_start = run(
            "exec",
            "-d",
            CONTAINER,
            "sh",
            "-c",
            "python3 /tmp/mock.py > /tmp/mock.log 2>&1",
            timeout=10,
        )
        time.sleep(0.5)
        mock_health = run(
            "exec",
            CONTAINER,
            "sh",
            "-c",
            "curl -sS --max-time 2 http://127.0.0.1:19090/health || true",
            timeout=10,
        )
        validate = run(
            "exec", CONTAINER, "sh", "-c", "HOME=/root openclaw config validate", timeout=10
        )
        gateway = run(
            "exec",
            "-d",
            CONTAINER,
            "sh",
            "-c",
            "HOME=/root openclaw gateway run --port 18789 --bind loopback --auth token --token fake-gateway-token > /tmp/gateway.log 2>&1",
            timeout=10,
        )
        deadline = time.time() + 30
        response = None
        while time.time() < deadline:
            health = run(
                "exec",
                CONTAINER,
                "sh",
                "-c",
                "HOME=/root openclaw gateway call health --json --token fake-gateway-token",
                timeout=10,
            )
            if health.returncode == 0:
                response = run(
                    "exec",
                    "-i",
                    CONTAINER,
                    "curl",
                    "-sS",
                    "--max-time",
                    "20",
                    "-H",
                    "Authorization: Bearer fake-gateway-token",
                    "-H",
                    "Content-Type: application/json",
                    "-d",
                    '{"model":"openclaw","messages":[{"role":"user","content":"Use the add tool to calculate 2+3, then report the result."}],"stream":false}',
                    "http://127.0.0.1:18789/v1/chat/completions",
                    timeout=30,
                )
                break
            time.sleep(1)
        capture = run(
            "exec",
            CONTAINER,
            "sh",
            "-c",
            "cat /tmp/mock-captures.json 2>/dev/null || true",
            timeout=10,
        )
        logs = run(
            "exec",
            CONTAINER,
            "sh",
            "-c",
            "find /tmp /root/.openclaw/logs -maxdepth 2 -type f 2>/dev/null | sort | while read f; do echo FILE:$f; tail -80 $f; done",
            timeout=10,
        )
        captured = json.loads(capture.stdout) if capture.stdout.strip() else []
        if isinstance(captured, dict):
            captured = [captured]
        body = captured[-1].get("body", {}) if captured else {}
        log_text = logs.stdout[-12000:]
        log_lines = [
            line
            for line in log_text.splitlines()
            if any(
                marker in line.lower()
                for marker in (
                    "agent model",
                    "listening on",
                    "chat completion",
                    "internal error",
                    "no reply",
                    "context window",
                    "failover",
                    "provider",
                )
            )
        ]
        result = {
            "status": "completed",
            "startup_commands": {
                "container": [
                    "docker",
                    "run",
                    "-d",
                    "--network",
                    "none",
                    IMAGE,
                    "sleep",
                    "infinity",
                ],
                "mock": ["python3", "/tmp/mock.py"],
                "gateway": [
                    "openclaw",
                    "gateway",
                    "run",
                    "--port",
                    "18789",
                    "--bind",
                    "loopback",
                    "--auth",
                    "token",
                ],
                "client": ["curl", "POST", "/v1/chat/completions"],
            },
            "network_isolation": "docker --network none; provider mock bound to container loopback",
            "container_start_stdout": started.stdout.strip(),
            "mock_start_returncode": mock_start.returncode,
            "mock_health": mock_health.stdout.strip(),
            "config_validate_returncode": validate.returncode,
            "config_validate_stderr": validate.stderr[-200:],
            "gateway_start_returncode": gateway.returncode,
            "gateway_health_checked": response is not None,
            "gateway_response": response.stdout if response else "",
            "gateway_response_returncode": response.returncode if response else None,
            "mock_capture": {
                "request_count": len(captured),
                "path": captured[-1].get("path") if captured else None,
                "headers": {
                    k: (captured[-1].get("headers", {}) if captured else {}).get(k)
                    for k in ("content-type", "user-agent", "x-stainless-retry-count")
                    if captured
                },
                "body_keys": sorted(body) if isinstance(body, dict) else [],
                "model": body.get("model") if isinstance(body, dict) else None,
                "stream": body.get("stream") if isinstance(body, dict) else None,
                "has_store": "store" in body if isinstance(body, dict) else False,
                "has_max_tokens": "max_tokens" in body if isinstance(body, dict) else False,
                "has_max_completion_tokens": "max_completion_tokens" in body
                if isinstance(body, dict)
                else False,
                "tools_count": len(body.get("tools", []))
                if isinstance(body, dict) and isinstance(body.get("tools"), list)
                else None,
                "tool_schemas": [
                    {
                        "type": t.get("type"),
                        "name": (t.get("function") or {}).get("name"),
                        "has_strict": "strict" in (t.get("function") or {}),
                        "parameters_required": (
                            (t.get("function") or {}).get("parameters") or {}
                        ).get("required", []),
                    }
                    for t in body.get("tools", [])
                    if isinstance(t, dict)
                ]
                if isinstance(body, dict) and isinstance(body.get("tools"), list)
                else [],
                "message_roles": [
                    m.get("role") for m in body.get("messages", []) if isinstance(m, dict)
                ]
                if isinstance(body, dict)
                else [],
                "tool_message_projection": [
                    {
                        "role": m.get("role"),
                        "tool_call_id": m.get("tool_call_id"),
                        "name": m.get("name"),
                        "content_length": len(str(m.get("content", ""))),
                    }
                    for m in body.get("messages", [])
                    if isinstance(m, dict) and m.get("role") in {"assistant", "tool"}
                ]
                if isinstance(body, dict)
                else [],
            },
            "mock_capture_returncode": capture.returncode,
            "redacted_log_markers": log_lines[-80:],
        }
        (OUT / "tool_integration_result_v3.json").write_text(
            json.dumps(result, indent=2, sort_keys=True) + "\n"
        )
        return 0
    finally:
        run("rm", "-f", CONTAINER)


if __name__ == "__main__":
    raise SystemExit(main())
