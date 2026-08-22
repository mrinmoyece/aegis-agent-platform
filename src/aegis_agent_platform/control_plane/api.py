"""Minimal ASGI health surface for the control-plane process."""

from __future__ import annotations

import json
from collections.abc import Awaitable, Callable
from typing import Any

from aegis_agent_platform.config import ConfigurationError, Settings

type AsgiMessage = dict[str, Any]
type Receive = Callable[[], Awaitable[AsgiMessage]]
type Send = Callable[[AsgiMessage], Awaitable[None]]


async def application(scope: AsgiMessage, receive: Receive, send: Send) -> None:
    """Serve only liveness and configuration-readiness endpoints."""
    del receive
    if scope.get("type") != "http":
        return

    path = scope.get("path")
    if path == "/healthz":
        await _respond(send, 200, {"status": "ok", "service": "control-plane"})
        return
    if path == "/readyz":
        try:
            Settings.from_env()
        except ConfigurationError as error:
            await _respond(
                send,
                503,
                {"status": "not-ready", "reason": str(error)},
            )
            return
        await _respond(
            send,
            200,
            {"status": "ready", "checks": ["configuration"]},
        )
        return
    await _respond(send, 404, {"status": "not-found"})


async def _respond(send: Send, status: int, body: dict[str, Any]) -> None:
    encoded = json.dumps(body, separators=(",", ":")).encode()
    await send(
        {
            "type": "http.response.start",
            "status": status,
            "headers": [
                (b"content-type", b"application/json"),
                (b"content-length", str(len(encoded)).encode()),
            ],
        }
    )
    await send({"type": "http.response.body", "body": encoded})
