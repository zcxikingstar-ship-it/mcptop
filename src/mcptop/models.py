from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(frozen=True)
class ConfiguredServer:
    client: str
    name: str
    command: tuple[str, ...]
    source: str
    scope: str


@dataclass(frozen=True)
class ConfigProblem:
    source: str
    message: str


@dataclass(frozen=True)
class ProcessInfo:
    pid: int
    ppid: int
    cpu_percent: float
    rss_kb: int
    elapsed_seconds: int
    state: str
    command: str


@dataclass
class Observation:
    process: ProcessInfo
    matches: list[ConfiguredServer] = field(default_factory=list)
    ancestry: list[int] = field(default_factory=list)
    client_ancestor: str | None = None
    client_ancestor_pid: int | None = None
    inherited_from_pid: int | None = None
    status: str = "identified"
    reasons: list[str] = field(default_factory=list)
