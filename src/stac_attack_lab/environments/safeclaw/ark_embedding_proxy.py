"""Container-local OpenAI embedding adapter for Ark multimodal endpoints.

This module uses only the standard library so the runner can deploy its source
inside the pinned SafeClaw image without installing the lab package there.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import math
import re
import struct
import sys
import time
import urllib.error
import urllib.request
from email.message import Message
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any


class UpstreamEmbeddingError(urllib.error.HTTPError):
    """HTTPError-compatible, redacted projection of an Ark failure."""

    def __init__(
        self,
        *,
        category: str,
        status: int | None = None,
        provider_error_code: str | None = None,
        safe_message: str | None = None,
        request_id: str | None = None,
        retry_after: str | None = None,
        body_length: int = 0,
        body_hash: str | None = None,
    ) -> None:
        super().__init__(
            "https://ark.invalid/embeddings/multimodal", status or 502, category, Message(), None
        )
        self.category = category
        self.upstream_http_status = status
        self.provider_error_code = provider_error_code
        self.safe_message = safe_message
        self.request_id = request_id
        self.retry_after = retry_after
        self.error_body_length = body_length
        self.error_body_hash = body_hash
        self.upstream_attempt_count = 1


class InvalidEmbeddingError(RuntimeError):
    def __init__(self, message: str) -> None:
        super().__init__(message)
        self.category = "invalid_vector"
        self.safe_message = message
        self.upstream_http_status = None
        self.provider_error_code = None
        self.request_id = None
        self.retry_after = None
        self.error_body_length = 0
        self.error_body_hash = None
        self.upstream_attempt_count = 1


def _bounded_text(value: Any, limit: int = 240) -> str | None:
    if not isinstance(value, str):
        return None
    text = " ".join(value.split())
    return text[:limit] if text else None


def _safe_error_fields(raw: bytes) -> dict[str, Any]:
    fields: dict[str, Any] = {
        "error_body_length": len(raw),
        "error_body_hash": hashlib.sha256(raw).hexdigest() if raw else None,
        "provider_error_code": None,
        "safe_message": None,
    }
    try:
        parsed = json.loads(raw) if raw else None
    except (TypeError, ValueError, json.JSONDecodeError):
        parsed = None
    error = parsed.get("error") if isinstance(parsed, dict) else None
    if isinstance(error, dict):
        code = str(error.get("code", ""))
        if re.fullmatch(r"[A-Za-z0-9_.:-]{1,120}", code):
            fields["provider_error_code"] = code
    return fields


def _request_id(headers: Any) -> str | None:
    for name in ("x-request-id", "request-id", "x-ark-request-id"):
        raw = headers.get(name) if headers is not None else None
        if raw is None and hasattr(headers, "items"):
            raw = next((value for key, value in headers.items() if str(key).lower() == name), None)
        value = _bounded_text(raw, 160)
        if value:
            return value
    return None


def convert_embeddings(
    payload: dict[str, Any], config: dict[str, str], *, on_attempt: Any = None
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
    tokens_known = True
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
        started = time.monotonic()
        try:
            with urllib.request.urlopen(request, timeout=60) as response:
                result = json.load(response)
                upstream_status = getattr(response, "status", None)
                if upstream_status is None and hasattr(response, "getcode"):
                    upstream_status = response.getcode()
                response_headers = getattr(response, "headers", None)
        except urllib.error.HTTPError as exc:
            raw = exc.read(1024 * 1024)
            details = _safe_error_fields(raw)
            category = (
                "authentication"
                if exc.code in (401, 403)
                else "rate_limited"
                if exc.code == 429
                else "endpoint_not_found"
                if exc.code == 404
                else "upstream_http_error"
            )
            error = UpstreamEmbeddingError(
                category=category,
                status=exc.code,
                provider_error_code=details["provider_error_code"],
                safe_message=category,
                request_id=_request_id(exc.headers),
                retry_after=_bounded_text(
                    next(
                        (
                            value
                            for key, value in exc.headers.items()
                            if str(key).lower() == "retry-after"
                        ),
                        None,
                    ),
                    80,
                ),
                body_length=details["error_body_length"],
                body_hash=details["error_body_hash"],
            )
            if on_attempt:
                on_attempt(error, time.monotonic() - started)
            raise error from exc
        except TimeoutError as exc:
            error = UpstreamEmbeddingError(category="timeout", safe_message="upstream_timeout")
            if on_attempt:
                on_attempt(error, time.monotonic() - started)
            raise error from exc
        except (urllib.error.URLError, OSError) as exc:
            error = UpstreamEmbeddingError(
                category="transport_error", safe_message="upstream_transport_error"
            )
            if on_attempt:
                on_attempt(error, time.monotonic() - started)
            raise error from exc
        except (json.JSONDecodeError, UnicodeDecodeError) as exc:
            error = UpstreamEmbeddingError(
                category="non_json_response", safe_message="upstream_response_not_json"
            )
            if on_attempt:
                on_attempt(error, time.monotonic() - started)
            raise error from exc
        except Exception as exc:
            error = UpstreamEmbeddingError(
                category="upstream_failure", safe_message="upstream_request_failed"
            )
            if on_attempt:
                on_attempt(error, time.monotonic() - started)
            raise error from exc
        if on_attempt:
            on_attempt(
                {
                    "upstream_http_status": upstream_status,
                    "request_id": _request_id(response_headers),
                },
                time.monotonic() - started,
            )
        result_data = result.get("data") if isinstance(result, dict) else None
        vector = result_data.get("embedding") if isinstance(result_data, dict) else None
        if (
            not isinstance(vector, list)
            or not vector
            or not all(type(value) in (int, float) and math.isfinite(value) for value in vector)
        ):
            raise InvalidEmbeddingError("invalid_upstream_vector")
        if dimension is not None and len(vector) != dimension:
            raise InvalidEmbeddingError("inconsistent_upstream_dimensions")
        dimension = len(vector)
        embedding = (
            base64.b64encode(struct.pack(f"<{len(vector)}f", *vector)).decode()
            if encoding == "base64"
            else vector
        )
        data.append({"object": "embedding", "index": index, "embedding": embedding})
        prompt_tokens = result.get("usage", {}).get("prompt_tokens")
        if type(prompt_tokens) is int and prompt_tokens >= 0:
            tokens += prompt_tokens
        else:
            tokens_known = False
    response = {
        "object": "list",
        "model": config["model"],
        "data": data,
    }
    if tokens_known:
        response["usage"] = {"prompt_tokens": tokens, "total_tokens": tokens}
    return response


def create_server(config: dict[str, str], port: int = 18790) -> ThreadingHTTPServer:
    class Handler(BaseHTTPRequestHandler):
        def log_message(self, format: str, *args: Any) -> None:
            # Never log request bodies, headers, or upstream exception strings.
            pass

        def _record(
            self,
            *,
            local_status: int,
            stage: str,
            started: float,
            upstream: Any = None,
            association_id: str | None = None,
        ) -> None:
            path = config.get("ledger_path")
            if not path:
                return
            record: dict[str, Any] = {
                "timestamp": time.time(),
                "association_id": association_id,
                "stage": stage,
                "endpoint_path": "/embeddings/multimodal",
                "local_proxy_status": local_status,
                "duration_ms": round((time.monotonic() - started) * 1000, 3),
            }
            if isinstance(upstream, UpstreamEmbeddingError):
                record.update(
                    {
                        "upstream_http_status": upstream.upstream_http_status,
                        "provider_error_code": upstream.provider_error_code,
                        "safe_message": upstream.safe_message,
                        "request_id": upstream.request_id,
                        "retry_after": upstream.retry_after,
                        "error_category": upstream.category,
                        "error_body_length": upstream.error_body_length,
                        "error_body_hash": upstream.error_body_hash,
                        "upstream_attempt_count": getattr(upstream, "upstream_attempt_count", 1),
                    }
                )
            elif isinstance(upstream, dict):
                record.update(upstream)
            with Path(path).open("a", encoding="utf-8") as stream:
                stream.write(json.dumps(record, sort_keys=True) + "\n")

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
            started = time.monotonic()
            association_id = _bounded_text(self.headers.get("X-Request-ID"), 160)
            attempts: list[Any] = []
            if self.path != "/v1/embeddings":
                self.reply(404, {"error": {"message": "unknown_endpoint"}})
                self._record(
                    local_status=404,
                    stage="request_validation",
                    started=started,
                    association_id=association_id,
                )
                return
            if not hmac.compare_digest(
                self.headers.get("Authorization", ""), "Bearer " + config["api_key"]
            ):
                self.reply(401, {"error": {"message": "unauthorized"}})
                self._record(
                    local_status=401,
                    stage="request_validation",
                    started=started,
                    association_id=association_id,
                )
                return
            try:
                size = int(self.headers.get("Content-Length", "0"))
                if not 0 < size <= 4 * 1024 * 1024:
                    raise ValueError("invalid_body_size")
                payload = json.loads(self.rfile.read(size))
                if not isinstance(payload, dict):
                    raise ValueError("invalid_request")
                result = convert_embeddings(
                    payload, config, on_attempt=lambda event, _elapsed: attempts.append(event)
                )
            except (UpstreamEmbeddingError, InvalidEmbeddingError) as exc:
                local_status = 502 if exc.upstream_http_status is None else exc.upstream_http_status
                exc.upstream_attempt_count = len(attempts) or 1
                self.reply(
                    local_status,
                    {
                        "error": {
                            "message": exc.category,
                            "upstream_http_status": exc.upstream_http_status,
                            "provider_error_code": exc.provider_error_code,
                            "request_id": exc.request_id,
                            "retry_after": exc.retry_after,
                        }
                    },
                )
                self._record(
                    local_status=local_status,
                    stage="upstream",
                    started=started,
                    upstream=exc,
                    association_id=association_id,
                )
                return
            except (ValueError, TypeError):
                self.reply(400, {"error": {"message": "invalid_embedding_request"}})
                self._record(
                    local_status=400,
                    stage="request_validation",
                    started=started,
                    association_id=association_id,
                )
                return
            except Exception:
                self.reply(502, {"error": {"message": "ark_embedding_failed"}})
                self._record(
                    local_status=502,
                    stage="upstream",
                    started=started,
                    association_id=association_id,
                )
                return
            else:
                self.reply(200, result)
                self._record(
                    local_status=200,
                    stage="complete",
                    started=started,
                    upstream={"upstream_http_status": 200, "upstream_attempt_count": len(attempts)},
                    association_id=association_id,
                )

    return ThreadingHTTPServer(("127.0.0.1", port), Handler)


if __name__ == "__main__":
    runtime = json.loads(Path(sys.argv[1]).read_text())
    create_server(runtime).serve_forever()
