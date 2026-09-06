from __future__ import annotations

import base64
import io
import json
import struct
import urllib.error
from typing import Any

import pytest

from stac_attack_lab.environments.safeclaw import ark_embedding_proxy as adapter

CONFIG = {
    "model": "ep-test",
    "base_url": "https://ark.cn-beijing.volces.com/api/v3/",
    "api_key": "synthetic-key",
}


def test_batch_preserves_independent_vectors_and_order(monkeypatch: pytest.MonkeyPatch) -> None:
    calls = []

    def upstream(request: Any, **kwargs: Any) -> io.BytesIO:
        body = json.loads(request.data)
        calls.append(body)
        assert request.full_url.endswith("/api/v3/embeddings/multimodal")
        assert request.get_header("Authorization") == "Bearer synthetic-key"
        vector = [1.0, 0.0] if body["input"][0]["text"] == "first" else [0.0, 1.0]
        return io.BytesIO(
            json.dumps(
                {
                    "data": {"embedding": vector},
                    "usage": {"prompt_tokens": 3},
                }
            ).encode()
        )

    monkeypatch.setattr(adapter.urllib.request, "urlopen", upstream)
    result = adapter.convert_embeddings({"model": "ep-test", "input": ["first", "second"]}, CONFIG)
    assert [c["input"] for c in calls] == [
        [{"type": "text", "text": "first"}],
        [{"type": "text", "text": "second"}],
    ]
    assert result["data"] == [
        {"object": "embedding", "index": 0, "embedding": [1.0, 0.0]},
        {"object": "embedding", "index": 1, "embedding": [0.0, 1.0]},
    ]
    assert result["usage"] == {"prompt_tokens": 6, "total_tokens": 6}


def test_base64_is_little_endian_float32(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        adapter.urllib.request,
        "urlopen",
        lambda *a, **k: io.BytesIO(b'{"data":{"embedding":[0.5,-1.0]}}'),
    )
    result = adapter.convert_embeddings(
        {
            "model": "ep-test",
            "input": "one",
            "encoding_format": "base64",
        },
        CONFIG,
    )
    assert struct.unpack("<2f", base64.b64decode(result["data"][0]["embedding"])) == (0.5, -1.0)


@pytest.mark.parametrize(
    "extra",
    [
        {"model": "wrong"},
        {"input": []},
        {"input": [1, 2]},
        {"input": [{"type": "text", "text": "fusion"}]},
        {"encoding_format": "invalid"},
        {"dimensions": 123},
    ],
)
def test_invalid_request_makes_no_upstream_call(
    extra: dict[str, Any],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def forbidden(*args: Any, **kwargs: Any) -> None:
        pytest.fail("invalid input reached upstream")

    monkeypatch.setattr(adapter.urllib.request, "urlopen", forbidden)
    with pytest.raises(ValueError):
        adapter.convert_embeddings({"model": "ep-test", "input": "one", **extra}, CONFIG)


def test_upstream_error_is_not_returned_as_partial_batch(monkeypatch: pytest.MonkeyPatch) -> None:
    calls = 0

    def upstream(*args: Any, **kwargs: Any) -> io.BytesIO:
        nonlocal calls
        calls += 1
        if calls == 2:
            raise urllib.error.HTTPError("https://example.invalid", 429, "secret", {}, None)
        return io.BytesIO(b'{"data":{"embedding":[1,2]}}')

    monkeypatch.setattr(adapter.urllib.request, "urlopen", upstream)
    with pytest.raises(urllib.error.HTTPError):
        adapter.convert_embeddings({"model": "ep-test", "input": ["one", "two"]}, CONFIG)


@pytest.mark.parametrize("vector", [[], [True], [float("nan")], ["invalid"]])
def test_invalid_upstream_vectors_are_rejected(
    vector: list[Any], monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(
        adapter.urllib.request,
        "urlopen",
        lambda *a, **k: io.BytesIO(json.dumps({"data": {"embedding": vector}}).encode()),
    )
    with pytest.raises(RuntimeError, match="invalid_upstream_vector"):
        adapter.convert_embeddings({"model": "ep-test", "input": "one"}, CONFIG)


def test_http_translation_auth_and_error_redaction(monkeypatch: pytest.MonkeyPatch) -> None:
    # Feed a raw HTTP request through the real handler without opening sockets.
    from http.server import BaseHTTPRequestHandler

    class FakeServer:
        pass

    handlers: list[type[BaseHTTPRequestHandler]] = []

    def capture_server(address: Any, handler: type[BaseHTTPRequestHandler]) -> Any:
        assert address == ("127.0.0.1", 18792)
        handlers.append(handler)
        return FakeServer()

    monkeypatch.setattr(adapter, "ThreadingHTTPServer", capture_server)
    adapter.create_server(CONFIG)

    class Connection:
        def __init__(self, raw: bytes):
            self.rfile = io.BytesIO(raw)
            self.response = bytearray()

        def makefile(self, *args: Any, **kwargs: Any) -> io.BytesIO:
            return self.rfile

        def sendall(self, data: bytes) -> None:
            self.response.extend(data)

    def request(token: str) -> bytes:
        body = json.dumps({"model": "ep-test", "input": ["one", "two"]}).encode()
        conn = Connection(
            f"POST /v1/embeddings HTTP/1.0\r\nAuthorization: Bearer {token}\r\n"
            f"Content-Length: {len(body)}\r\n\r\n".encode()
            + body
        )
        handlers[0](conn, ("127.0.0.1", 1), FakeServer())
        return bytes(conn.response)

    calls = 0

    def upstream(*args: Any, **kwargs: Any) -> io.BytesIO:
        nonlocal calls
        calls += 1
        return io.BytesIO(b'{"data":{"embedding":[1,2]}}')

    monkeypatch.setattr(adapter.urllib.request, "urlopen", upstream)
    assert b"401" in request("wrong").split(b"\r\n")[0]
    assert calls == 0
    response = request("synthetic-key")
    assert b"200" in response.split(b"\r\n")[0]
    result = json.loads(response.split(b"\r\n\r\n", 1)[1])
    assert len(result["data"]) == 2

    def failed(*args: Any, **kwargs: Any) -> None:
        raise urllib.error.HTTPError("https://secret.invalid", 429, "synthetic-key", {}, None)

    monkeypatch.setattr(adapter.urllib.request, "urlopen", failed)
    response = request("synthetic-key")
    assert b"429" in response.split(b"\r\n")[0]
    assert b"synthetic-key" not in response
    assert b"secret.invalid" not in response
