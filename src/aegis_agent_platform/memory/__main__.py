"""Run the deterministic fake-only Layer 10 memory demonstration."""

from __future__ import annotations

import asyncio
import json

from aegis_agent_platform.memory.demo import run_demo


def main() -> None:
    print(json.dumps(asyncio.run(run_demo()), indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
