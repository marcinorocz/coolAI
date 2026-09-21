# Contributing

Use Python 3.11+ and install `pip install -e '.[test,dev,mcp]'`.
Run `ruff check .`, `ruff format --check .` and `pytest` before a pull request.

For security fixes, add a regression test demonstrating that denied actions
never reach the dispatch callback. For approval changes, cover altered arguments,
expiry, replay, concurrent consumers and policy changes. Keep examples fictional.

Prefer explicit, deterministic rules. Avoid new permissions hidden behind defaults.
Never log raw tool arguments, responses, prompts, targets, tokens or keys.

For feature requests, describe the workflow, the trusted and untrusted actors,
the required decision and a reproducible example. Report security issues as
described in SECURITY.md.
