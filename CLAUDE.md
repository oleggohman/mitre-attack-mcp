# Project rules for agents

Details live in [TESTING.md](TESTING.md); this file is the checklist.

## Definition of done

A change is done only when all of these hold:

1. `.venv/bin/python -m pytest -q --cov --cov-report=term-missing` passes with 100 % line and
   branch coverage (use this form in sandboxes; never `uv run` / `uv sync` there, they fail).
2. `.venv/bin/ruff check src tests` is clean (no `noqa`, no baseline).
3. The smoke suite passes. A new or changed tool has an `ARGS` entry in `tests/tool_args.py`
   (see "Adding or changing a tool" in TESTING.md).
4. Never claim a tool "works" without calling it on real data (smoke suite or a direct call).
5. Check the response size of changed tools against the budget in `tests/tool_args.py`.
6. User-visible changes are reflected in `README.md` and `CHANGELOG.md` (`[Unreleased]`).
7. After committing to `main`, run Trivy and fix findings:
   `trivy fs --skip-db-update --scanners vuln,secret,misconfig --skip-dirs .venv --skip-dirs .ruff_cache .`

## Rules

- Code comments in English. No secrets or identifiable information in commits.
- Do not weaken a test or add an expected-empty cell without a raw-data check to make it pass;
  fix the bug or mark it `known_bug` / strict xfail with a follow-up entry.
- `# pragma: no cover` is allowed only on the `if __name__ == "__main__":` line of `server.py`.
