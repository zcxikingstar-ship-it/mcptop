from __future__ import annotations

import argparse
import sys
import time
from pathlib import Path

from . import __version__
from .analysis import analyze_processes
from .configs import discover_configured_servers
from .models import ConfigProblem, Observation
from .processes import ProcessSnapshotError, capture_processes
from .render import render_explain, render_json, render_table

SUPPORTED_PLATFORMS = {"darwin", "linux"}


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="mcptop",
        description="htop for local MCP servers — config-aware and read-only",
        epilog=(
            "Non-goals in v1: mcptop never kills processes, edits MCP configuration, "
            "reads session transcripts, or supports unlisted AI clients. Windows, "
            "remote hosts, and containers are not supported."
        ),
    )
    parser.add_argument(
        "--watch", metavar="SECONDS", type=float, help="refresh continuously"
    )
    parser.add_argument(
        "--json", action="store_true", help="emit stable JSON to stdout"
    )
    parser.add_argument(
        "--explain", metavar="PID", type=int, help="explain one matched PID"
    )
    parser.add_argument(
        "--detached-after",
        metavar="SECONDS",
        type=int,
        default=900,
        help="age threshold for suspicious detached processes (default: 900)",
    )
    parser.add_argument(
        "--cwd",
        type=Path,
        default=Path.cwd(),
        help="project directory used to discover project-scoped MCP config",
    )
    parser.add_argument("--version", action="version", version=f"mcptop {__version__}")
    return parser


def _validate_args(parser: argparse.ArgumentParser, args: argparse.Namespace) -> None:
    if args.detached_after < 0:
        parser.error("--detached-after must be zero or greater")
    if args.watch is not None and args.watch < 0.2:
        parser.error("--watch must be at least 0.2 seconds")
    if args.watch is not None and (args.json or args.explain is not None):
        parser.error("--watch cannot be combined with --json or --explain")


def _snapshot(
    cwd: Path, detached_after: int
) -> tuple[list[Observation], int, list[ConfigProblem]]:
    servers, problems = discover_configured_servers(cwd=cwd)
    processes = capture_processes()
    observations = analyze_processes(processes, servers, detached_after=detached_after)
    return observations, len(servers), problems


def _warn_problems(problems: list[ConfigProblem]) -> None:
    for problem in problems:
        print(
            f"mcptop: could not parse {problem.source}: {problem.message}",
            file=sys.stderr,
        )


def _run_once(args: argparse.Namespace) -> int:
    observations, configured_count, problems = _snapshot(args.cwd, args.detached_after)
    if args.json:
        print(
            render_json(
                observations,
                configured_count=configured_count,
                problems=problems,
                platform=sys.platform,
                detached_after=args.detached_after,
            )
        )
        return 0
    _warn_problems(problems)
    if args.explain is not None:
        for item in observations:
            if item.process.pid == args.explain:
                print(render_explain(item))
                return 0
        print(
            f"mcptop: PID {args.explain} is not a running configured MCP process",
            file=sys.stderr,
        )
        return 1
    print(
        render_table(
            observations,
            configured_count=configured_count,
            detached_after=args.detached_after,
        )
    )
    return 0


def _run_watch(args: argparse.Namespace) -> int:
    interval = float(args.watch)
    try:
        while True:
            observations, configured_count, problems = _snapshot(
                args.cwd, args.detached_after
            )
            if sys.stdout.isatty():
                print("\033[2J\033[H", end="")
            print(
                render_table(
                    observations,
                    configured_count=configured_count,
                    detached_after=args.detached_after,
                ),
                flush=True,
            )
            _warn_problems(problems)
            time.sleep(interval)
    except KeyboardInterrupt:
        if sys.stdout.isatty():
            print()
        return 0


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    _validate_args(parser, args)
    if sys.platform not in SUPPORTED_PLATFORMS:
        print(
            "mcptop v1 supports macOS and Linux only; Windows is not supported.",
            file=sys.stderr,
        )
        return 2
    try:
        return _run_watch(args) if args.watch is not None else _run_once(args)
    except ProcessSnapshotError as exc:
        print(f"mcptop: {exc}", file=sys.stderr)
        return 2
    except OSError as exc:
        print(f"mcptop: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
