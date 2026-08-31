# Contributing

Contributions should preserve the project's narrow safety boundary: config-aware, explainable, local, and read-only.

## Development

```bash
python3.12 -m venv .venv
. .venv/bin/activate
python -m pip install -e .
python -m unittest discover -s tests -v
```

## Detection changes

Every new matcher needs:

1. a true-positive process/config fixture;
2. a nearby non-match fixture;
3. an explanation string that identifies the evidence;
4. documentation of any new false-positive boundary.

Do not add automatic process termination, configuration mutation, transcript parsing, telemetry, or network access to a detection pull request.
