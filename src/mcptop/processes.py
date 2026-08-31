from __future__ import annotations

import subprocess

from .models import ProcessInfo


class ProcessSnapshotError(RuntimeError):
    pass


def parse_elapsed(value: str) -> int:
    value = value.strip()
    if not value:
        return 0
    days = 0
    if "-" in value:
        day_part, value = value.split("-", 1)
        days = int(day_part)
    parts = [int(part) for part in value.split(":")]
    if len(parts) == 3:
        hours, minutes, seconds = parts
    elif len(parts) == 2:
        hours = 0
        minutes, seconds = parts
    elif len(parts) == 1:
        hours = minutes = 0
        seconds = parts[0]
    else:
        raise ValueError(f"unsupported elapsed time: {value}")
    return days * 86400 + hours * 3600 + minutes * 60 + seconds


def parse_ps_output(output: str) -> list[ProcessInfo]:
    processes: list[ProcessInfo] = []
    for raw_line in output.splitlines():
        line = raw_line.strip()
        if not line:
            continue
        parts = line.split(None, 6)
        if len(parts) < 7:
            continue
        pid, ppid, cpu, rss, elapsed, state, command = parts
        try:
            processes.append(
                ProcessInfo(
                    pid=int(pid),
                    ppid=int(ppid),
                    cpu_percent=float(cpu.replace(",", ".")),
                    rss_kb=int(rss),
                    elapsed_seconds=parse_elapsed(elapsed),
                    state=state,
                    command=command,
                )
            )
        except ValueError:
            continue
    return processes


def capture_processes() -> list[ProcessInfo]:
    command = ["ps", "-axo", "pid=,ppid=,%cpu=,rss=,etime=,stat=,args="]
    try:
        result = subprocess.run(
            command,
            check=False,
            capture_output=True,
            text=True,
            timeout=5,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise ProcessSnapshotError(f"could not run ps: {exc}") from exc
    if result.returncode != 0:
        detail = result.stderr.strip() or f"exit code {result.returncode}"
        raise ProcessSnapshotError(f"ps failed: {detail}")
    return parse_ps_output(result.stdout)
