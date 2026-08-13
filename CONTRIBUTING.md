# Contributing

Thank you for helping make production agent systems easier to understand.

## Development setup

Use Python 3.12 or newer:

```bash
python3.12 -m venv .venv
. .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -e '.[dev]'
make check
```

Copy `.env.example` to `.env` only when using the local Compose stack. Never
commit `.env` or real credentials.

## Change workflow

1. Read `AGENTS.md` and relevant ADRs.
2. Keep a pull request within one roadmap layer or one clearly bounded fix.
3. Add tests for behavior and architecture constraints.
4. Run `make check`, `make compose-config`, and `make container-check` when
   configuration or the image changes.
5. Update the enterprise checklist when capability status changes.

Commits should explain the reason for the change. Pull requests must distinguish
implemented behavior from future design.

## Architecture decisions

Create an ADR when changing a binding invariant, trust boundary, persistence
model, public contract, or major dependency. Use the existing ADR format and
record superseded decisions rather than rewriting history.

## Security

Do not open a public issue for a suspected vulnerability. Follow
`SECURITY.md`.
