from __future__ import annotations

import os
import shlex
from collections import defaultdict

from .models import ConfiguredServer, Observation, ProcessInfo

_LAUNCHERS = {
    "bun",
    "bunx",
    "deno",
    "docker",
    "node",
    "npm",
    "npx",
    "podman",
    "python",
    "python3",
    "uv",
    "uvx",
}
_GENERIC_TOKENS = {
    "exec",
    "index.js",
    "main.py",
    "mcp",
    "run",
    "serve",
    "server",
    "start",
    "stdio",
}


def command_tokens(command: str) -> list[str]:
    try:
        return shlex.split(command)
    except ValueError:
        return command.split()


def _basename(value: str) -> str:
    return os.path.basename(value.rstrip("/"))


def _normalized(value: str) -> str:
    return value.strip().strip("'\"").lower()


def _distinctive_tokens(command: tuple[str, ...]) -> list[str]:
    result: list[str] = []
    for index, token in enumerate(command):
        normalized = _normalized(token)
        base = _normalized(_basename(token))
        if not normalized or normalized.startswith("-"):
            continue
        if index == 0 and base in _LAUNCHERS:
            continue
        candidate = (
            normalized if ("/" not in normalized and "\\" not in normalized) else base
        )
        if candidate in _GENERIC_TOKENS or len(candidate) < 4:
            continue
        result.append(candidate)
    return result


def command_match_score(process: ProcessInfo, server: ConfiguredServer) -> int:
    process_tokens = command_tokens(process.command)
    if not process_tokens or not server.command:
        return 0
    process_lower = [_normalized(token) for token in process_tokens]
    process_bases = [_normalized(_basename(token)) for token in process_tokens]
    process_text = " ".join(process_lower)

    configured_executable = _normalized(_basename(server.command[0]))
    executable_matches = configured_executable == process_bases[0]
    distinctive = _distinctive_tokens(server.command)
    token_hits = sum(
        1
        for token in distinctive
        if token in process_lower or token in process_bases or token in process_text
    )

    if executable_matches and configured_executable not in _LAUNCHERS:
        return 100 + token_hits
    if executable_matches and token_hits:
        return 80 + token_hits
    if token_hits >= 2:
        return 60 + token_hits
    if token_hits == 1 and any(
        marker in distinctive[0]
        for marker in ("mcp", "modelcontextprotocol", "server-")
    ):
        return 50
    return 0


def detect_client(process: ProcessInfo) -> str | None:
    tokens = command_tokens(process.command)
    if not tokens:
        return None
    executable = _normalized(_basename(tokens[0]))
    command = process.command.lower()
    if executable in {"codex", "codex-cli"} or "/codex.app/contents/" in command:
        return "codex"
    if executable in {"claude", "claude-code"} or "/claude.app/contents/" in command:
        return "claude"
    if executable in {"cursor", "cursor-agent"} or "/cursor.app/contents/" in command:
        return "cursor"
    if executable == "opencode" or "/opencode.app/contents/" in command:
        return "opencode"
    return None


def _ancestry(pid: int, by_pid: dict[int, ProcessInfo]) -> list[int]:
    result: list[int] = []
    seen = {pid}
    current = by_pid.get(pid)
    while current and current.ppid > 0 and current.ppid not in seen:
        parent = by_pid.get(current.ppid)
        if parent is None:
            break
        result.append(parent.pid)
        seen.add(parent.pid)
        current = parent
    return result


def analyze_processes(
    processes: list[ProcessInfo],
    servers: list[ConfiguredServer],
    *,
    detached_after: int = 900,
) -> list[Observation]:
    by_pid = {process.pid: process for process in processes}
    direct: dict[int, list[ConfiguredServer]] = defaultdict(list)
    for process in processes:
        scored = [(command_match_score(process, server), server) for server in servers]
        matches = [server for score, server in scored if score > 0]
        if matches:
            direct[process.pid].extend(matches)

    observations: list[Observation] = []
    for process in processes:
        matches = list(direct.get(process.pid, []))
        inherited_from: int | None = None
        ancestry = _ancestry(process.pid, by_pid)
        if not matches:
            for ancestor_pid in ancestry:
                if ancestor_pid in direct:
                    matches = list(direct[ancestor_pid])
                    inherited_from = ancestor_pid
                    break
        if not matches:
            continue

        client_ancestor = None
        client_ancestor_pid = None
        for ancestor_pid in ancestry:
            client = detect_client(by_pid[ancestor_pid])
            if client:
                client_ancestor = client
                client_ancestor_pid = ancestor_pid
                break

        reasons: list[str] = []
        status = "identified"
        if inherited_from is not None:
            reasons.append(f"descendant of matched MCP process {inherited_from}")
        else:
            reasons.append("command matches a configured local MCP server")
        if client_ancestor:
            reasons.append(
                f"active {client_ancestor} ancestor at PID {client_ancestor_pid}"
            )
        elif process.state.upper().startswith("Z"):
            status = "suspicious_detached"
            reasons.append(
                "process state is zombie and no AI client ancestor was found"
            )
        elif process.elapsed_seconds >= detached_after:
            status = "suspicious_detached"
            reasons.append(
                f"no AI client ancestor found after {process.elapsed_seconds}s"
            )
        else:
            reasons.append(
                f"no AI client ancestor found, but age is below {detached_after}s threshold"
            )

        unique_matches = list(
            {
                (item.client, item.name, item.command, item.source): item
                for item in matches
            }.values()
        )
        observations.append(
            Observation(
                process=process,
                matches=unique_matches,
                ancestry=ancestry,
                client_ancestor=client_ancestor,
                client_ancestor_pid=client_ancestor_pid,
                inherited_from_pid=inherited_from,
                status=status,
                reasons=reasons,
            )
        )

    return sorted(
        observations,
        key=lambda item: (
            item.status != "suspicious_detached",
            -item.process.rss_kb,
            item.process.pid,
        ),
    )
