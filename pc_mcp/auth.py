"""Shared-secret gate in front of the MCP app.

A request is let through only if it carries the access token, either

* as the first path segment:          https://host/<token>/mcp   (works with clients that only take a URL)
* or as a bearer header on any path:  Authorization: Bearer <token>

Everything else gets a 401 before it reaches the MCP layer.
"""

from __future__ import annotations

import hmac
import json
import logging

from starlette.types import ASGIApp, Receive, Scope, Send

log = logging.getLogger("pc_mcp.auth")


class TokenGate:
    def __init__(self, app: ASGIApp, token: str) -> None:
        if len(token) < 16:
            raise ValueError("access token must be at least 16 characters")
        self.app = app
        self._token = token.encode()
        self.rejected = 0

    def _matches(self, candidate: bytes) -> bool:
        return hmac.compare_digest(candidate, self._token)

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] not in ("http", "websocket"):
            await self.app(scope, receive, send)
            return

        path: str = scope.get("path", "")
        first, sep, rest = path.lstrip("/").partition("/")
        if self._matches(first.encode()):
            inner = dict(scope)
            inner["path"] = "/" + rest if sep else "/"
            inner["raw_path"] = inner["path"].encode()
            await self.app(inner, receive, send)
            return

        for name, value in scope.get("headers", []):
            if name == b"authorization" and value[:7].lower() == b"bearer ":
                if self._matches(value[7:].strip()):
                    await self.app(scope, receive, send)
                    return

        self.rejected += 1
        log.warning("rejected unauthenticated request (%d so far)", self.rejected)
        if scope["type"] == "websocket":
            await send({"type": "websocket.close", "code": 1008})
            return
        body = json.dumps({"error": "unauthorized", "hint": "use the full URL printed by pc-mcp"}).encode()
        await send(
            {
                "type": "http.response.start",
                "status": 401,
                "headers": [(b"content-type", b"application/json"), (b"content-length", str(len(body)).encode())],
            }
        )
        await send({"type": "http.response.body", "body": body})
