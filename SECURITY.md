# Security policy

## Safety boundary

`mcptop` is a read-only diagnostic tool. Version 1 reads supported MCP configuration files and the local process table. It does not:

- send signals to processes;
- edit or delete files;
- execute configured MCP commands;
- read coding-agent transcripts;
- access process memory;
- make network requests.

Common secret shapes in process arguments are redacted before terminal or JSON output. Redaction is best effort: a secret passed as an unusual positional argument may not be recognizable. Treat reports as local diagnostic data and review them before sharing.

Configuration parse errors report the source and parser message, never the configuration contents.

## Reporting a vulnerability

Please use GitHub's private security advisory flow for this repository. Include a minimal reproduction, affected platform and Python version, and the output shape after removing personal paths and credentials.

Do not open a public issue containing live tokens, full process arguments, private configuration, or home-directory contents.

## Supported versions

Security fixes are applied to the latest released version.
