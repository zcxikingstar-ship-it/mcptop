from __future__ import annotations

import json
import re
import shlex
from datetime import UTC, datetime
from pathlib import Path
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

from .models import ConfigProblem, ConfiguredServer, Observation

_SENSITIVE_NAME = re.compile(
    r"(?:api[_-]?key|auth|credential|password|secret|token)", re.IGNORECASE
)


def human_bytes(value: int) -> str:
    size = float(value)
    for unit in ("B", "K", "M", "G", "T"):
        if size < 1024 or unit == "T":
            return f"{size:.0f}{unit}" if unit in {"B", "K"} else f"{size:.1f}{unit}"
        size /= 1024
    return f"{size:.1f}T"


def human_duration(seconds: int) -> str:
    if seconds < 60:
        return f"{seconds}s"
    if seconds < 3600:
        return f"{seconds // 60}m"
    if seconds < 86400:
        return f"{seconds // 3600}h{(seconds % 3600) // 60:02d}m"
    return f"{seconds // 86400}d{(seconds % 86400) // 3600:02d}h"


def _redact_url(token: str) -> str:
    try:
        parsed = urlsplit(token)
    except ValueError:
        return token
    if parsed.scheme not in {"http", "https"}:
        return token
    netloc = parsed.netloc
    if "@" in netloc:
        userinfo, host = netloc.rsplit("@", 1)
        username = userinfo.split(":", 1)[0]
        netloc = f"{username}:***@{host}"
    query = []
    for key, value in parse_qsl(parsed.query, keep_blank_values=True):
        query.append((key, "***" if _SENSITIVE_NAME.search(key) else value))
    return urlunsplit(
        (parsed.scheme, netloc, parsed.path, urlencode(query), parsed.fragment)
    )


def redact_command(command: str, *, max_chars: int = 88) -> str:
    try:
        tokens = shlex.split(command)
    except ValueError:
        tokens = command.split()
    redacted: list[str] = []
    hide_next = False
    for token in tokens:
        if hide_next:
            redacted.append("***")
            hide_next = False
            continue
        if token.startswith(("http://", "https://")):
            redacted.append(_redact_url(token))
            continue
        if token.startswith("-") and _SENSITIVE_NAME.search(token):
            if "=" in token:
                key = token.split("=", 1)[0]
                redacted.append(f"{key}=***")
            else:
                redacted.append(token)
                hide_next = True
            continue
        if "=" in token:
            key, _value = token.split("=", 1)
            if _SENSITIVE_NAME.search(key):
                redacted.append(f"{key}=***")
                continue
        redacted.append(token)
    result = " ".join(redacted)
    result = result.replace(str(Path.home()), "~")
    if len(result) > max_chars:
        return result[: max_chars - 1] + "…"
    return result


def _server_labels(matches: list[ConfiguredServer]) -> tuple[str, str]:
    clients = ",".join(sorted({item.client for item in matches})) or "?"
    names = ",".join(sorted({item.name for item in matches})) or "?"
    return clients, names


def render_table(
    observations: list[Observation],
    *,
    configured_count: int,
    detached_after: int,
) -> str:
    suspicious = sum(item.status == "suspicious_detached" for item in observations)
    lines = [
        "mcptop  ·  read-only MCP process view",
        (
            f"{len(observations)} process(es) from {configured_count} local config entry(s); "
            f"{suspicious} suspicious (threshold {human_duration(detached_after)})"
        ),
        "",
    ]
    if not observations:
        lines.append("No running processes matched configured local MCP servers.")
        return "\n".join(lines)

    headers = (
        "STATUS",
        "CLIENT",
        "SERVER",
        "PID",
        "PPID",
        "CPU",
        "RSS",
        "AGE",
        "COMMAND",
    )
    rows: list[tuple[str, ...]] = []
    for item in observations:
        clients, names = _server_labels(item.matches)
        status = "SUSPECT" if item.status == "suspicious_detached" else "ATTACHED"
        rows.append(
            (
                status,
                clients[:12],
                names[:20],
                str(item.process.pid),
                str(item.process.ppid),
                f"{item.process.cpu_percent:.1f}%",
                human_bytes(item.process.rss_kb * 1024),
                human_duration(item.process.elapsed_seconds),
                redact_command(item.process.command, max_chars=64),
            )
        )
    widths = [
        min(max(len(headers[index]), *(len(row[index]) for row in rows)), 24)
        for index in range(len(headers) - 1)
    ]
    lines.append(
        "  ".join(headers[index].ljust(widths[index]) for index in range(len(widths)))
        + "  "
        + headers[-1]
    )
    for row in rows:
        lines.append(
            "  ".join(row[index].ljust(widths[index]) for index in range(len(widths)))
            + "  "
            + row[-1]
        )
    lines.extend(
        [
            "",
            "ATTACHED only means a live AI-client ancestor was found; it is not a health verdict.",
            "SUSPECT means heuristic evidence, not a confirmed orphan. Use --explain PID.",
        ]
    )
    return "\n".join(lines)


def observation_dict(item: Observation) -> dict[str, object]:
    clients, names = _server_labels(item.matches)
    return {
        "pid": item.process.pid,
        "ppid": item.process.ppid,
        "cpu_percent": item.process.cpu_percent,
        "rss_bytes": item.process.rss_kb * 1024,
        "elapsed_seconds": item.process.elapsed_seconds,
        "process_state": item.process.state,
        "status": item.status,
        "clients": clients.split(",") if clients != "?" else [],
        "servers": names.split(",") if names != "?" else [],
        "config_sources": sorted({match.source for match in item.matches}),
        "command_summary": redact_command(item.process.command, max_chars=240),
        "client_ancestor": (
            {"client": item.client_ancestor, "pid": item.client_ancestor_pid}
            if item.client_ancestor
            else None
        ),
        "ancestry": item.ancestry,
        "inherited_from_pid": item.inherited_from_pid,
        "reasons": item.reasons,
    }


def render_json(
    observations: list[Observation],
    *,
    configured_count: int,
    problems: list[ConfigProblem],
    platform: str,
    detached_after: int,
) -> str:
    payload = {
        "schema_version": 1,
        "generated_at": datetime.now(UTC).isoformat(),
        "platform": platform,
        "read_only": True,
        "configured_servers": configured_count,
        "detached_after_seconds": detached_after,
        "processes": [observation_dict(item) for item in observations],
        "config_problems": [
            {"source": problem.source, "message": problem.message}
            for problem in problems
        ],
    }
    return json.dumps(payload, indent=2, sort_keys=True)


def render_explain(item: Observation) -> str:
    clients, names = _server_labels(item.matches)
    source_lines = sorted(
        {
            f"  - {match.client}/{match.name}: {match.source} ({match.scope})"
            for match in item.matches
        }
    )
    ancestor = (
        f"{item.client_ancestor} at PID {item.client_ancestor_pid}"
        if item.client_ancestor
        else "none found"
    )
    lines = [
        f"mcptop explain PID {item.process.pid}",
        "",
        f"Status: {item.status}",
        f"Matched client(s): {clients}",
        f"Matched server(s): {names}",
        f"Command: {redact_command(item.process.command, max_chars=240)}",
        f"Parent: {item.process.ppid}",
        f"AI client ancestor: {ancestor}",
        "Ancestry: " + (" -> ".join(map(str, item.ancestry)) or "none in snapshot"),
        "Config evidence:",
        *source_lines,
        "Reasons:",
        *(f"  - {reason}" for reason in item.reasons),
        "",
        "This is heuristic evidence. mcptop never sends signals or changes configuration.",
    ]
    return "\n".join(lines)
