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
import urllib.error
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any


def convert_embeddings(payload: dict[str, Any], config: dict[str, str]) -> dict[str, Any]:
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
            },
        )
        with urllib.request.urlopen(request, timeout=60) as response:
            result = json.load(response)
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


def create_server(config: dict[str, str], port: int = 18792) -> ThreadingHTTPServer:
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
                result = convert_embeddings(payload, config)
            except urllib.error.HTTPError as exc:
                self.reply(exc.code, {"error": {"message": "ark_upstream_http_error"}})
            except (ValueError, TypeError):
                self.reply(400, {"error": {"message": "invalid_embedding_request"}})
            except Exception:
                self.reply(502, {"error": {"message": "ark_embedding_failed"}})
            else:
                self.reply(200, result)

    return ThreadingHTTPServer(("127.0.0.1", port), Handler)


if __name__ == "__main__":
    runtime = json.loads(Path(sys.argv[1]).read_text())
    create_server(runtime).serve_forever()
