# Contributing to coolAI Gate

Thanks for helping make agentic systems safer and easier to trust.

## Before you start

- Search existing issues before opening a new one.
- For a bug, use the bug-report template and include a minimal reproduction.
- For an idea, use the feature-request template and describe the user problem first.
- Do not include credentials, personal data, production logs, or customer documents in issues or pull requests.

## Development workflow

1. Fork the repository and create a focused branch.
2. Make one coherent change per pull request.
3. Add or update tests for behaviour changes.
4. Run `python -m pytest -q` locally.
5. Explain the motivation, policy impact, and test evidence in the pull request.

## Design principles

- **Safe by default:** consequential actions should require explicit approval.
- **Explainable:** every decision should provide reasons a human can understand.
- **Small and composable:** avoid unnecessary framework dependencies.
- **Privacy-aware:** never use real personal or confidential data in examples or tests.

## Pull request checklist

- [ ] The change is focused and documented.
- [ ] Tests pass locally.
- [ ] New behaviour has test coverage.
- [ ] No secrets or real personal data were committed.
- [ ] The change respects the [Code of Conduct](CODE_OF_CONDUCT.md).

By contributing, you agree that your contributions are licensed under the repository's [MIT License](LICENSE).

## Development checks for 0.2

Use Python 3.11+ and install `pip install -e '.[test,dev,mcp]'`.
Run `ruff check .`, `ruff format --check .` and `pytest` before a pull request.

For enforcement changes, add regression tests proving denied calls never reach
the dispatch callback. For approval changes, cover modified arguments, expiry,
replay, concurrent consumption and policy changes. Keep examples fictional.
Never log raw arguments, responses, prompts, targets, tokens or signing keys.
