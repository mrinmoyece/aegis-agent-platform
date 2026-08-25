"""Run local Layer 16 demo, chaos, and performance qualification evidence."""

from __future__ import annotations

import argparse
import asyncio
import json
from collections.abc import Mapping, Sequence
from pathlib import Path

from aegis_agent_platform.domain import JsonValue
from aegis_agent_platform.qualification.demo import run_qualification_demo
from aegis_agent_platform.qualification.smoke import (
    run_chaos_smoke,
    run_load_smoke,
)


def _arguments(argv: Sequence[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    subcommands = parser.add_subparsers(dest="command", required=True)
    demo = subcommands.add_parser("demo")
    demo.add_argument("--output", type=Path, default=Path(".aegis-qualification/demo"))
    chaos = subcommands.add_parser("chaos-smoke")
    chaos.add_argument(
        "--output",
        type=Path,
        default=Path(".aegis-qualification/chaos.json"),
    )
    load = subcommands.add_parser("load-smoke")
    load.add_argument("--samples", type=int, default=3)
    load.add_argument("--p95-budget-ms", type=float, default=5_000)
    load.add_argument(
        "--output",
        type=Path,
        default=Path(".aegis-qualification/load.json"),
    )
    return parser.parse_args(argv)


async def _run(args: argparse.Namespace) -> Mapping[str, JsonValue]:
    if args.command == "demo":
        result = await run_qualification_demo(args.output)
    elif args.command == "chaos-smoke":
        result = await run_chaos_smoke()
        _write(args.output, result)
    elif args.command == "load-smoke":
        result = await run_load_smoke(
            samples=args.samples,
            p95_budget_ms=args.p95_budget_ms,
        )
        _write(args.output, result)
        raw_blocking = result.get("blocking_profiles", ())
        blocking_profiles = raw_blocking if isinstance(raw_blocking, Sequence) else ()
        if blocking_profiles:
            raise RuntimeError(
                "qualification load budget failed for: "
                + ", ".join(str(p) for p in blocking_profiles)
            )
    else:
        raise ValueError("unknown qualification command")
    return result


def _write(path: Path, value: Mapping[str, JsonValue]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )


def main(argv: Sequence[str] | None = None) -> None:
    args = _arguments(argv)
    print(json.dumps(asyncio.run(_run(args)), indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
