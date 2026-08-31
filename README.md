<div align="center">

# mcptop

### `htop` for local MCP servers.

**Config-aware · read-only · zero runtime dependencies · no network calls**

[![CI](https://github.com/zcxikingstar-ship-it/mcptop/actions/workflows/ci.yml/badge.svg)](https://github.com/zcxikingstar-ship-it/mcptop/actions/workflows/ci.yml)
[![Python 3.11+](https://img.shields.io/badge/python-3.11%2B-3776ab)](https://www.python.org/)
[![license](https://img.shields.io/badge/license-MIT-5ee6a8)](LICENSE)

</div>

MCP servers are ordinary local processes, but ordinary process monitors do not know which AI client launched them, which configuration declared them, or why an old process may be suspicious.

`mcptop` adds that missing semantic layer:

```bash
mcptop
```

```text
mcptop  ·  read-only MCP process view
3 process(es) from 2 local config entry(s); 1 suspicious (threshold 15m)

STATUS    CLIENT  SERVER      PID    PPID  CPU   RSS     AGE   COMMAND
SUSPECT   claude  filesystem  48120  1     0.0%  186.2M  4h12m node …/server-filesystem/dist/index.js
ATTACHED  codex   browser     92811  92740 0.2%  72.4M   8m    npx -y browser-mcp
ATTACHED  codex   browser     92819  92811 0.0%  41.8M   8m    node …/browser-mcp/index.js

ATTACHED only means a live AI-client ancestor was found; it is not a health verdict.
SUSPECT means heuristic evidence, not a confirmed orphan. Use --explain PID.
```

## Why this exists

The failure mode is real. Codex users have reported [1,300+ unreaped MCP child processes and 37 GB of memory use](https://github.com/openai/codex/issues/12491), as well as [accumulated MCP helpers causing input and WindowServer stalls](https://github.com/openai/codex/issues/25744).

`ps`, `top`, and `htop` show resource use. They do not map a generic `node`, `python`, `npx`, or `uvx` process back to an MCP server entry in your coding-agent configuration. `mcptop` does, and every suspicion comes with inspectable evidence.

## Install

Python 3.11 or newer is required. Install directly from the public repository:

```bash
uv tool install git+https://github.com/zcxikingstar-ship-it/mcptop.git
```

or:

```bash
pipx install git+https://github.com/zcxikingstar-ship-it/mcptop.git
```

Then run `mcptop` from any project directory.

## What it understands

| Client | User configuration | Project configuration |
| --- | --- | --- |
| Codex | `~/.codex/config.toml` | `.codex/config.toml` |
| Claude Code | `~/.claude.json` | `.mcp.json` |
| Cursor | `~/.cursor/mcp.json` | `.cursor/mcp.json` |
| OpenCode v2 | `~/.config/opencode/opencode.json[c]` | `opencode.json[c]` |

The formats and locations follow the current [Claude Code](https://code.claude.com/docs/en/mcp), [Cursor](https://prod.cursor.com/help/customization/mcp), and [OpenCode](https://v2.opencode.ai/docs/mcp-servers/) MCP documentation. Remote HTTP/SSE servers are intentionally skipped because they do not create a local server process.

## Explain a finding

```bash
mcptop --explain 48120
```

```text
Status: suspicious_detached
Matched client(s): claude
Matched server(s): filesystem
AI client ancestor: none found
Config evidence:
  - claude/filesystem: ~/.claude.json (user)
Reasons:
  - command matches a configured local MCP server
  - no AI client ancestor found after 15120s
```

The explanation includes the configuration source, command-match evidence, ancestry, and threshold reason. It does not claim that a process is safe to kill.

## Watch mode

```bash
mcptop --watch 2
```

`Ctrl-C` exits cleanly. Watch mode only refreshes process snapshots; it never sends a signal to a target process.

## Machine-readable output

```bash
mcptop --json | jq '.processes[] | select(.status == "suspicious_detached")'
```

JSON uses a versioned schema and keeps stdout clean. Parse warnings go to `config_problems` rather than corrupting the JSON stream. See [the detection contract](docs/detection.md) for fields and limitations.

## Safety boundary

`mcptop` is deliberately diagnostic:

- never kills, pauses, or signals a process;
- never edits MCP or agent configuration;
- never reads agent transcripts or prompt history;
- never installs, starts, or executes an MCP server;
- never performs a network request;
- redacts common token, key, password, credential, and URL-secret shapes from command summaries.

Process arguments may still contain unusual secrets that cannot be recognized reliably. Review output before sharing it publicly. See [SECURITY.md](SECURITY.md).

## What `SUSPECT` means

A process is marked `suspicious_detached` only when it matches a configured local MCP command and either:

1. no supported AI-client ancestor is present and its age exceeds `--detached-after`; or
2. the operating system reports a zombie process state.

This is evidence for investigation, not proof of an orphan. A manually launched MCP server can be legitimate. Conversely, a leaked server may remain attached to a still-running desktop client and therefore appear as `ATTACHED`. Counts, age, and memory remain visible so that pattern is still inspectable.

## Support matrix

| Environment | v1 status |
| --- | --- |
| macOS | Supported and tested in CI |
| Linux | Supported and tested in CI |
| Windows | Not supported; exits clearly with code 2 |
| WSL, containers, remote hosts | Not claimed |

## Development

```bash
python3.12 -m venv .venv
. .venv/bin/activate
python -m pip install -e .
python -m unittest discover -s tests -v
mcptop --json | python -m json.tool
```

The test suite includes a synthetic corpus of 50 attached process trees and 10 detached processes, command redaction cases, all supported configuration formats, JSON-contract checks, and clean watch-mode shutdown.

## License

[MIT](LICENSE)
