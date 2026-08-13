"""Safe command-line interface for deterministic evaluation workflows."""

from __future__ import annotations

import argparse
import asyncio
import json
from datetime import UTC, datetime
from pathlib import Path

from aegis_agent_platform.evals.baseline import (
    build_baseline,
    compare_baseline,
    load_baseline,
    load_waivers,
    write_baseline,
)
from aegis_agent_platform.evals.catalog import build_suite
from aegis_agent_platform.evals.governance import (
    load_dataset_manifest,
    verify_dataset,
    write_dataset_manifest,
)
from aegis_agent_platform.evals.reporting import (
    read_report_case_ids,
    write_report_bundle,
)
from aegis_agent_platform.evals.runner import (
    EvaluationRunner,
    RunOptions,
    RunSelection,
)

DEFAULT_BASELINE = Path("evals/baselines/canonical-v1.json")
DEFAULT_MANIFEST = Path("evals/datasets/checkout-layer11-v1.json")
DEFAULT_WAIVERS = Path("evals/waivers.json")
DEFAULT_OUTPUT = Path(".aegis-evals")


def main(argv: list[str] | None = None) -> int:
    """Execute one bounded evaluation command."""
    parser = _parser()
    args = parser.parse_args(argv)
    suite = build_suite()
    command = str(args.command)
    if command == "list":
        for case in sorted(suite.cases, key=lambda item: item.case_id):
            print(
                f"{case.case_id}\t{case.layer}\t{case.expected_outcome.value}\t"
                f"{','.join(case.tags)}"
            )
        return 0
    if command == "check-fixtures":
        manifest = load_dataset_manifest(Path(args.manifest))
        if manifest.digest != suite.dataset.digest:
            print("dataset manifest differs from the executable catalog")
            return 1
        report = verify_dataset(Path.cwd(), manifest)
        for finding in report.findings:
            print(f"{finding.fixture_id}: {finding.reason_code}: {finding.detail}")
        print(
            f"fixtures={report.checked_fixtures} "
            f"digest={report.dataset_digest} passed={str(report.passed).lower()}"
        )
        return 0 if report.passed else 1
    if command == "write-manifest":
        if not args.yes:
            parser.error("write-manifest requires --yes")
        write_dataset_manifest(Path(args.manifest), suite.dataset)
        print(f"wrote reviewed dataset manifest: {args.manifest}")
        return 0
    if command == "run":
        return asyncio.run(_run(args, compare=bool(args.compare)))
    if command == "compare":
        return asyncio.run(_run(args, compare=True))
    if command == "replay":
        identifiers = frozenset(read_report_case_ids(Path(args.report)))
        args.case = sorted(identifiers)
        args.tag = []
        args.compare = False
        return asyncio.run(_run(args, compare=False))
    if command == "update-baseline":
        if not args.yes:
            parser.error("update-baseline requires --yes")
        return asyncio.run(_update_baseline(args))
    parser.error(f"unknown command: {command}")


async def _run(args: argparse.Namespace, *, compare: bool) -> int:
    suite = build_suite()
    selection = RunSelection(
        frozenset(args.case or ()),
        frozenset(args.tag or ()),
        int(args.shard_index),
        int(args.shard_count),
    )
    runner = EvaluationRunner(suite)
    report = await runner.run(
        RunOptions(
            _source_revision(),
            selection,
            concurrency=int(args.concurrency) if args.concurrency else None,
            timeout_seconds=int(args.timeout) if args.timeout else None,
        )
    )
    comparison = None
    if compare:
        baseline = load_baseline(Path(args.baseline))
        waivers = (
            load_waivers(Path(args.waivers)) if Path(args.waivers).is_file() else ()
        )
        comparison = compare_baseline(
            suite,
            baseline,
            report,
            at=datetime.now(UTC),
            waivers=waivers,
        )
    paths = write_report_bundle(
        Path(args.output),
        report,
        comparison=comparison,
    )
    passed = report.passed and (comparison is None or comparison.passed)
    print(
        f"cases={len(report.results)} passed={str(passed).lower()} "
        f"report={paths.json} fingerprint={report.metadata.content_digest}"
    )
    return 0 if passed else 1


async def _update_baseline(args: argparse.Namespace) -> int:
    suite = build_suite()
    report = await EvaluationRunner(suite).run(
        RunOptions(_source_revision(), RunSelection())
    )
    baseline = build_baseline(
        suite,
        report,
        baseline_id=str(args.baseline_id),
        review_reference=str(args.review_reference),
    )
    write_baseline(Path(args.baseline), baseline)
    print(f"wrote reviewed baseline: {args.baseline} digest={baseline.digest}")
    return 0


def _source_revision() -> str:
    marker = Path(".git")
    git_directory = marker
    if marker.is_file():
        declaration = marker.read_text(encoding="utf-8").strip()
        prefix = "gitdir: "
        if not declaration.startswith(prefix):
            raise RuntimeError("worktree .git marker is malformed")
        candidate = Path(declaration.removeprefix(prefix))
        git_directory = (
            candidate if candidate.is_absolute() else (marker.parent / candidate)
        ).resolve()
    head = (git_directory / "HEAD").read_text(encoding="utf-8").strip()
    if _is_revision(head):
        return head
    prefix = "ref: "
    if not head.startswith(prefix):
        raise RuntimeError("git HEAD is malformed")
    reference = head.removeprefix(prefix)
    roots = [git_directory]
    common = git_directory / "commondir"
    if common.is_file():
        common_path = Path(common.read_text(encoding="utf-8").strip())
        roots.append(
            common_path
            if common_path.is_absolute()
            else (git_directory / common_path).resolve()
        )
    for root in roots:
        loose = root / reference
        if loose.is_file():
            revision = loose.read_text(encoding="utf-8").strip()
            if _is_revision(revision):
                return revision
        packed = root / "packed-refs"
        if packed.is_file():
            for line in packed.read_text(encoding="utf-8").splitlines():
                if line.endswith(f" {reference}"):
                    revision = line.partition(" ")[0]
                    if _is_revision(revision):
                        return revision
    raise RuntimeError("git source revision could not be resolved")


def _is_revision(value: str) -> bool:
    return len(value) == 40 and all(
        character in "0123456789abcdef" for character in value
    )


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="aegis-evals",
        description="Deterministic release evidence; never runtime truth.",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)
    subparsers.add_parser("list", help="List versioned evaluation cases")

    fixture = subparsers.add_parser(
        "check-fixtures",
        help="Verify dataset provenance, digests, and sensitive-content policy",
    )
    fixture.add_argument("--manifest", default=str(DEFAULT_MANIFEST))

    manifest = subparsers.add_parser(
        "write-manifest",
        help="Explicitly regenerate the reviewed dataset manifest",
    )
    manifest.add_argument("--manifest", default=str(DEFAULT_MANIFEST))
    manifest.add_argument("--yes", action="store_true")

    run = subparsers.add_parser("run", help="Run deterministic fake-only cases")
    _run_arguments(run)
    run.add_argument(
        "--compare",
        action="store_true",
        help="Compare the complete run with the checked-in baseline",
    )

    compare = subparsers.add_parser(
        "compare",
        help="Run all cases and enforce the checked-in baseline",
    )
    _run_arguments(compare)

    replay = subparsers.add_parser(
        "replay",
        help="Replay the exact case set referenced by a prior JSON report",
    )
    replay.add_argument("report")
    _run_arguments(replay, include_filters=False)
    replay.set_defaults(case=[], tag=[], compare=False)

    update = subparsers.add_parser(
        "update-baseline",
        help="Explicitly regenerate a baseline from a complete passing run",
    )
    update.add_argument("--baseline", default=str(DEFAULT_BASELINE))
    update.add_argument("--baseline-id", default="canonical-v1")
    update.add_argument("--review-reference", required=True)
    update.add_argument("--yes", action="store_true")
    return parser


def _run_arguments(
    parser: argparse.ArgumentParser,
    *,
    include_filters: bool = True,
) -> None:
    if include_filters:
        parser.add_argument("--case", action="append", default=[])
        parser.add_argument("--tag", action="append", default=[])
    parser.add_argument("--shard-index", type=int, default=0)
    parser.add_argument("--shard-count", type=int, default=1)
    parser.add_argument("--concurrency", type=int)
    parser.add_argument("--timeout", type=int)
    parser.add_argument("--output", default=str(DEFAULT_OUTPUT))
    parser.add_argument("--baseline", default=str(DEFAULT_BASELINE))
    parser.add_argument("--waivers", default=str(DEFAULT_WAIVERS))


def catalog_json() -> str:
    """Expose a deterministic machine-readable list for developer tooling."""
    suite = build_suite()
    return json.dumps(
        [
            {
                "case_id": case.case_id,
                "layer": case.layer,
                "outcome": case.expected_outcome.value,
                "tags": case.tags,
            }
            for case in sorted(suite.cases, key=lambda item: item.case_id)
        ],
        sort_keys=True,
        separators=(",", ":"),
    )


__all__ = ["catalog_json", "main"]
