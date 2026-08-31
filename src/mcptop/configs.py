from __future__ import annotations

import json
import shlex
import tomllib
from collections.abc import Iterable
from pathlib import Path
from typing import Any

from .models import ConfigProblem, ConfiguredServer


def _display_path(path: Path, home: Path) -> str:
    try:
        return "~/" + str(path.resolve().relative_to(home.resolve()))
    except (OSError, ValueError):
        return str(path)


def _project_root(cwd: Path) -> Path:
    current = cwd.resolve()
    for candidate in (current, *current.parents):
        if (candidate / ".git").exists():
            return candidate
    return current


def _strip_json_comments(text: str) -> str:
    output: list[str] = []
    index = 0
    in_string = False
    escaped = False
    while index < len(text):
        char = text[index]
        next_char = text[index + 1] if index + 1 < len(text) else ""
        if in_string:
            output.append(char)
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == '"':
                in_string = False
            index += 1
            continue
        if char == '"':
            in_string = True
            output.append(char)
            index += 1
            continue
        if char == "/" and next_char == "/":
            index += 2
            while index < len(text) and text[index] not in "\r\n":
                index += 1
            continue
        if char == "/" and next_char == "*":
            index += 2
            while index + 1 < len(text) and text[index : index + 2] != "*/":
                index += 1
            index += 2
            continue
        output.append(char)
        index += 1
    return "".join(output)


def _strip_trailing_commas(text: str) -> str:
    output: list[str] = []
    index = 0
    in_string = False
    escaped = False
    while index < len(text):
        char = text[index]
        if in_string:
            output.append(char)
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == '"':
                in_string = False
            index += 1
            continue
        if char == '"':
            in_string = True
            output.append(char)
            index += 1
            continue
        if char == ",":
            lookahead = index + 1
            while lookahead < len(text) and text[lookahead].isspace():
                lookahead += 1
            if lookahead < len(text) and text[lookahead] in "}]":
                index += 1
                continue
        output.append(char)
        index += 1
    return "".join(output)


def _load_json(path: Path) -> Any:
    raw = path.read_text(encoding="utf-8")
    return json.loads(_strip_trailing_commas(_strip_json_comments(raw)))


def _command_tuple(value: Any, args: Any = None) -> tuple[str, ...] | None:
    if isinstance(value, list) and all(isinstance(item, str) for item in value):
        return tuple(value) if value else None
    if not isinstance(value, str) or not value.strip():
        return None
    try:
        base = tuple(shlex.split(value))
    except ValueError:
        base = (value,)
    if isinstance(args, list):
        base += tuple(str(item) for item in args)
    return base or None


def _server_from_mapping(
    *, client: str, name: str, value: Any, source: str, scope: str
) -> ConfiguredServer | None:
    if not isinstance(value, dict):
        return None
    if value.get("disabled") is True or value.get("enabled") is False:
        return None
    server_type = str(value.get("type", "stdio")).lower()
    if server_type in {"http", "sse", "streamable-http", "remote"} or "url" in value:
        return None
    command = _command_tuple(value.get("command"), value.get("args"))
    if command is None:
        return None
    return ConfiguredServer(client, str(name), command, source, scope)


def _parse_mcp_servers(
    mapping: Any, *, client: str, source: str, scope: str
) -> list[ConfiguredServer]:
    if not isinstance(mapping, dict):
        return []
    servers: list[ConfiguredServer] = []
    for name, value in mapping.items():
        server = _server_from_mapping(
            client=client, name=str(name), value=value, source=source, scope=scope
        )
        if server:
            servers.append(server)
    return servers


def _parse_codex(path: Path, source: str) -> list[ConfiguredServer]:
    data = tomllib.loads(path.read_text(encoding="utf-8"))
    return _parse_mcp_servers(
        data.get("mcp_servers"), client="codex", source=source, scope="user"
    )


def _parse_claude(path: Path, source: str, scope: str) -> list[ConfiguredServer]:
    data = _load_json(path)
    if not isinstance(data, dict):
        return []
    servers = _parse_mcp_servers(
        data.get("mcpServers"), client="claude", source=source, scope=scope
    )
    projects = data.get("projects")
    if isinstance(projects, dict):
        for project_path, project in projects.items():
            if isinstance(project, dict):
                project_scope = f"project:{project_path}"
                servers.extend(
                    _parse_mcp_servers(
                        project.get("mcpServers"),
                        client="claude",
                        source=source,
                        scope=project_scope,
                    )
                )
    return servers


def _parse_cursor(path: Path, source: str, scope: str) -> list[ConfiguredServer]:
    data = _load_json(path)
    mapping = data.get("mcpServers") if isinstance(data, dict) else None
    return _parse_mcp_servers(mapping, client="cursor", source=source, scope=scope)


def _parse_opencode(path: Path, source: str, scope: str) -> list[ConfiguredServer]:
    data = _load_json(path)
    if not isinstance(data, dict) or not isinstance(data.get("mcp"), dict):
        return []
    mcp = data["mcp"]
    mapping = mcp.get("servers") if isinstance(mcp.get("servers"), dict) else mcp
    return _parse_mcp_servers(mapping, client="opencode", source=source, scope=scope)


def _unique_paths(
    items: Iterable[tuple[str, Path, str, str]],
) -> list[tuple[str, Path, str, str]]:
    seen: set[tuple[str, str]] = set()
    result: list[tuple[str, Path, str, str]] = []
    for parser, path, client, scope in items:
        key = (parser, str(path.resolve()))
        if key not in seen:
            seen.add(key)
            result.append((parser, path, client, scope))
    return result


def discover_configured_servers(
    *, home: Path | None = None, cwd: Path | None = None
) -> tuple[list[ConfiguredServer], list[ConfigProblem]]:
    home = (home or Path.home()).expanduser()
    cwd = (cwd or Path.cwd()).expanduser()
    root = _project_root(cwd)

    candidates = _unique_paths(
        [
            ("codex", home / ".codex/config.toml", "codex", "user"),
            ("codex", root / ".codex/config.toml", "codex", "project"),
            ("claude", home / ".claude.json", "claude", "user"),
            ("claude", root / ".mcp.json", "claude", "project"),
            ("cursor", home / ".cursor/mcp.json", "cursor", "user"),
            ("cursor", root / ".cursor/mcp.json", "cursor", "project"),
            (
                "opencode",
                home / ".config/opencode/opencode.json",
                "opencode",
                "user",
            ),
            (
                "opencode",
                home / ".config/opencode/opencode.jsonc",
                "opencode",
                "user",
            ),
            ("opencode", root / "opencode.json", "opencode", "project"),
            ("opencode", root / "opencode.jsonc", "opencode", "project"),
        ]
    )

    servers: list[ConfiguredServer] = []
    problems: list[ConfigProblem] = []
    for parser, path, _client, scope in candidates:
        if not path.is_file():
            continue
        source = _display_path(path, home)
        try:
            if parser == "codex":
                parsed = _parse_codex(path, source)
                if scope == "project":
                    parsed = [
                        ConfiguredServer(
                            item.client, item.name, item.command, item.source, scope
                        )
                        for item in parsed
                    ]
                servers.extend(parsed)
            elif parser == "claude":
                servers.extend(_parse_claude(path, source, scope))
            elif parser == "cursor":
                servers.extend(_parse_cursor(path, source, scope))
            elif parser == "opencode":
                servers.extend(_parse_opencode(path, source, scope))
        except (
            OSError,
            UnicodeError,
            json.JSONDecodeError,
            tomllib.TOMLDecodeError,
        ) as exc:
            message = f"{type(exc).__name__}: {str(exc).splitlines()[0]}"
            problems.append(ConfigProblem(source, message))

    deduped: dict[tuple[str, str, tuple[str, ...], str], ConfiguredServer] = {}
    for server in servers:
        key = (server.client, server.name, server.command, server.source)
        deduped[key] = server
    return list(deduped.values()), problems
