"""Container-local OpenAI embedding adapter for Ark multimodal endpoints.

This module uses only the standard library so the runner can deploy its source
inside the pinned SafeClaw image without installing the lab package there.
"""

from __future__ import annotations

import base64
import hmac
import json
import math
import struct
import sys
import threading
import time
import urllib.error
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any


def convert_embeddings(
    payload: dict[str, Any],
    config: dict[str, Any],
    *,
    begin_request: Any = None,
    record_request: Any = None,
) -> dict[str, Any]:
    """Embed each text independently: Ark's input array describes one fused item."""
    if payload.get("model") != config["model"]:
        raise ValueError("model_mismatch")
    inputs = payload.get("input")
    if isinstance(inputs, str):
        inputs = [inputs]
    if (
        not isinstance(inputs, list)
        or not inputs
        or not all(isinstance(item, str) and item for item in inputs)
    ):
        raise ValueError("input_must_be_nonempty_text_or_text_list")
    encoding = payload.get("encoding_format", "float")
    if encoding not in ("float", "base64"):
        raise ValueError("unsupported_encoding_format")
    # Do not silently truncate vectors: this changes retrieval semantics.
    if "dimensions" in payload:
        raise ValueError("dimensions_override_unsupported")
    data = []
    tokens = 0
    dimension = None
    for index, text in enumerate(inputs):
        sequence = begin_request() if begin_request is not None else index + 1
        started = time.monotonic()
        request = urllib.request.Request(
            config["base_url"].rstrip("/") + "/embeddings/multimodal",
            data=json.dumps(
                {
                    "model": config["model"],
                    "input": [{"type": "text", "text": text}],
                }
            ).encode(),
            headers={
                "Authorization": "Bearer " + config["api_key"],
                "Content-Type": "application/json",
                "User-Agent": "OpenAI/Python 1.0.0",
            },
        )
        try:
            with urllib.request.urlopen(
                request, timeout=int(config.get("timeout_seconds", 60))
            ) as response:
                result = json.load(response)
                status = int(getattr(response, "status", 200))
        except Exception as exc:
            if record_request is not None:
                category = (
                    f"provider_http_{exc.code}"
                    if isinstance(exc, urllib.error.HTTPError)
                    else type(exc).__name__
                )
                record_request(sequence, getattr(exc, "code", None), category, started)
            raise
        if record_request is not None:
            record_request(sequence, status, None, started)
        vector = result["data"]["embedding"]
        if (
            not isinstance(vector, list)
            or not vector
            or not all(type(value) in (int, float) and math.isfinite(value) for value in vector)
        ):
            raise RuntimeError("invalid_upstream_vector")
        if dimension is not None and len(vector) != dimension:
            raise RuntimeError("inconsistent_upstream_dimensions")
        dimension = len(vector)
        embedding = (
            base64.b64encode(struct.pack(f"<{len(vector)}f", *vector)).decode()
            if encoding == "base64"
            else vector
        )
        data.append({"object": "embedding", "index": index, "embedding": embedding})
        tokens += int(result.get("usage", {}).get("prompt_tokens", 0))
    return {
        "object": "list",
        "model": config["model"],
        "data": data,
        "usage": {"prompt_tokens": tokens, "total_tokens": tokens},
    }


def create_server(config: dict[str, Any], port: int = 18790) -> ThreadingHTTPServer:
    max_requests = int(config.get("max_requests", 128))
    if max_requests < 1:
        raise ValueError("embedding_request_budget_must_be_positive")
    ledger_path = Path(str(config.get("ledger_path", "/tmp/stac-embedding-ledger.jsonl")))
    request_lock = threading.Lock()
    request_count = 0
    attempt_count = 0

    def begin_request() -> int:
        nonlocal attempt_count, request_count
        with request_lock:
            attempt_count += 1
            sequence = attempt_count
            if request_count >= max_requests:
                with ledger_path.open("a", encoding="utf-8") as stream:
                    stream.write(
                        json.dumps(
                            {
                                "sequence": sequence,
                                "accepted": False,
                                "status": 429,
                                "error_category": "embedding_request_budget_exhausted",
                                "upstream_path": "/embeddings/multimodal",
                                "duration_ms": 0,
                            },
                            sort_keys=True,
                        )
                        + "\n"
                    )
                raise RuntimeError("embedding_request_budget_exhausted")
            request_count += 1
            return sequence

    def record_request(
        sequence: int, status: int | None, error_category: str | None, started: float
    ) -> None:
        value = {
            "sequence": sequence,
            "accepted": True,
            "status": status,
            "error_category": error_category,
            "upstream_path": "/embeddings/multimodal",
            "duration_ms": round((time.monotonic() - started) * 1000, 3),
        }
        with request_lock, ledger_path.open("a", encoding="utf-8") as stream:
            stream.write(json.dumps(value, sort_keys=True) + "\n")

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, format: str, *args: Any) -> None:
            # Never log request bodies, headers, or upstream exception strings.
            pass

        def reply(self, status: int, data: dict[str, Any]) -> None:
            body = json.dumps(data).encode()
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def do_GET(self) -> None:
            self.reply(200 if self.path == "/health" else 404, {"ready": True})

        def do_POST(self) -> None:
            if self.path != "/v1/embeddings":
                self.reply(404, {"error": {"message": "unknown_endpoint"}})
                return
            if not hmac.compare_digest(
                self.headers.get("Authorization", ""), "Bearer " + config["api_key"]
            ):
                self.reply(401, {"error": {"message": "unauthorized"}})
                return
            try:
                size = int(self.headers.get("Content-Length", "0"))
                if not 0 < size <= 4 * 1024 * 1024:
                    raise ValueError("invalid_body_size")
                payload = json.loads(self.rfile.read(size))
                if not isinstance(payload, dict):
                    raise ValueError("invalid_request")
                result = convert_embeddings(
                    payload,
                    config,
                    begin_request=begin_request,
                    record_request=record_request,
                )
            except urllib.error.HTTPError:
                # OpenClaw 2026.3.12 retries every 429/5xx up to four times.
                # The ledger retains the real upstream status; returning a
                # local 400 keeps this transport attempt non-retryable.
                self.reply(400, {"error": {"message": "ark_upstream_http_error"}})
            except (ValueError, TypeError):
                self.reply(400, {"error": {"message": "invalid_embedding_request"}})
            except RuntimeError as exc:
                message = (
                    "embedding_request_budget_exhausted"
                    if str(exc) == "embedding_request_budget_exhausted"
                    else "ark_embedding_failed"
                )
                self.reply(400, {"error": {"message": message}})
            except Exception:
                self.reply(400, {"error": {"message": "ark_embedding_failed"}})
            else:
                self.reply(200, result)

    return ThreadingHTTPServer(("127.0.0.1", port), Handler)


if __name__ == "__main__":
    runtime = json.loads(Path(sys.argv[1]).read_text())
    create_server(runtime).serve_forever()
