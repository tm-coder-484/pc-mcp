import anyio
import pytest

from pc_mcp.auth import TokenGate

TOKEN = "t0ken-abcdefghijklmnop"


async def _request(path: str, headers: list[tuple[bytes, bytes]] | None = None) -> tuple[int, str | None]:
    seen: dict = {}

    async def app(scope, receive, send):
        seen["path"] = scope["path"]
        await send({"type": "http.response.start", "status": 200, "headers": []})
        await send({"type": "http.response.body", "body": b"ok"})

    sent: list[dict] = []

    async def send(message):
        sent.append(message)

    async def receive():
        return {"type": "http.request", "body": b"", "more_body": False}

    gate = TokenGate(app, TOKEN)
    await gate({"type": "http", "path": path, "headers": headers or []}, receive, send)
    return sent[0]["status"], seen.get("path")


def run(coro):
    return anyio.run(lambda: coro)


def test_token_in_path_is_stripped_and_allowed():
    assert run(_request(f"/{TOKEN}/mcp")) == (200, "/mcp")
    assert run(_request(f"/{TOKEN}")) == (200, "/")


def test_bearer_header_is_allowed():
    assert run(_request("/mcp", [(b"authorization", f"Bearer {TOKEN}".encode())])) == (200, "/mcp")


@pytest.mark.parametrize(
    "path,headers",
    [
        ("/mcp", []),
        ("/wrong-token-xxxxxxxxxx/mcp", []),
        (f"/{TOKEN[:-1]}/mcp", []),
        (f"/x/{TOKEN}/mcp", []),
        ("/mcp", [(b"authorization", b"Bearer nope")]),
    ],
)
def test_everything_else_is_rejected(path, headers):
    status, inner_path = run(_request(path, headers))
    assert status == 401
    assert inner_path is None


def test_short_tokens_are_refused():
    with pytest.raises(ValueError):
        TokenGate(lambda *a: None, "short")
