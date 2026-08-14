"""Control-plane process entry point."""

from __future__ import annotations

import asyncio

import uvicorn

from aegis_agent_platform.config import ProcessRole, Settings
from aegis_agent_platform.observability.logging import configure_json_logging
from aegis_agent_platform.runtime.deployment import run_background_role


def main() -> None:
    """Dispatch exactly one validated process role."""
    settings = Settings.from_env()
    configure_json_logging(level=settings.log_level)
    if settings.process_role is not ProcessRole.API:
        asyncio.run(run_background_role(settings))
        return
    uvicorn.run(
        "aegis_agent_platform.runtime.deployment:create_application",
        factory=True,
        host=settings.host,
        port=settings.port,
        log_level=settings.log_level.lower(),
        access_log=False,
    )


if __name__ == "__main__":
    main()
