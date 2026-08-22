"""Control-plane process entry point."""

from __future__ import annotations

import uvicorn

from aegis_agent_platform.config import Settings


def main() -> None:
    """Run the minimal ASGI control-plane service."""
    settings = Settings.from_env()
    uvicorn.run(
        "aegis_agent_platform.control_plane.api:application",
        host=settings.host,
        port=settings.port,
        log_level=settings.log_level.lower(),
        access_log=True,
    )


if __name__ == "__main__":
    main()
