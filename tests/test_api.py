"""ASGI health-surface tests."""

from __future__ import annotations

import asyncio
import json
from typing import Any

from aegis_agent_platform.control_plane.api import application


def request(
    path: str,
    *,
    environment: dict[str, str] | None = None,
) -> tuple[int, dict[str, Any]]:
    messages: list[dict[str, Any]] = []

    async def receive() -> dict[str, Any]:
        return {"type": "http.request", "body": b"", "more_body": False}

    async def send(message: dict[str, Any]) -> None:
        messages.append(message)

    async def invoke() -> None:
        await application(
            {"type": "http", "path": path},
            receive,
            send,
        )

    with PatchedEnvironment(environment or {}):
        asyncio.run(invoke())

    status = messages[0]["status"]
    body = json.loads(messages[1]["body"])
    return status, body


class PatchedEnvironment:
    """Narrow environment patcher that does not require an HTTP test framework."""

    def __init__(self, values: dict[str, str]) -> None:
        self.values = values
        self.original: dict[str, str | None] = {}

    def __enter__(self) -> None:
        import os

        keys = {
            "AEGIS_ENVIRONMENT",
            "AEGIS_PORT",
            "AEGIS_LOG_LEVEL",
            "AEGIS_SERVICE_NAME",
            "AEGIS_DATABASE_URL",
            "AEGIS_REDIS_URL",
            "AEGIS_OIDC_ISSUER",
            "AEGIS_OIDC_JWKS_URL",
            "AEGIS_OIDC_AUDIENCE",
        }
        self.original = {key: os.environ.get(key) for key in keys}
        for key in keys:
            os.environ.pop(key, None)
        os.environ.update(self.values)

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc_value: BaseException | None,
        traceback: object,
    ) -> None:
        import os

        del exc_type, exc_value, traceback
        for key, value in self.original.items():
            if value is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = value


def test_liveness() -> None:
    status, body = request("/healthz")

    assert status == 200
    assert body == {"status": "ok", "service": "control-plane"}


def test_configuration_readiness() -> None:
    status, body = request("/readyz")

    assert status == 200
    assert body["checks"] == ["configuration"]


def test_invalid_configuration_is_not_ready() -> None:
    status, body = request("/readyz", environment={"AEGIS_PORT": "invalid"})

    assert status == 503
    assert body["status"] == "not-ready"


def test_unknown_route() -> None:
    status, body = request("/runs")

    assert status == 404
    assert body == {"status": "not-found"}
