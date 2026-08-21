# Contributing

Thanks for helping improve AgentCapDiff.

## High-value contributions

- Minimal examples that produce a false positive or false negative
- Adapters for real agent/tool schemas
- Capability taxonomy proposals backed by concrete examples
- CI and SARIF interoperability fixes
- Documentation that improves safe deployment

## Development

```bash
python -m venv .venv
source .venv/bin/activate
python -m pip install -e ".[dev]"
ruff check .
pytest
```

## Pull requests

Keep PRs focused. Explain any new capability or risk rule, include tests, and document expected false-positive tradeoffs. Security-sensitive changes should reference the threat model.

## Conduct

Participation is governed by [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md).
