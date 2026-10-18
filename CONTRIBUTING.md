# Contributing to Sentinel-Linux 2.0

Sentinel-Linux 2.0 is a security-critical portfolio project. The bar for
contributions is high — not because the project is precious, but because the
code is read by people who will judge its quality forensically.

## Ground rules

1. **Security first.** When a change trades a little convenience for a
   meaningful security gain, the secure path wins. When two requirements
   conflict, security and correctness beat speed and cleverness.
2. **Tests required.** New code ships with tests. Bug fixes ship with a
   regression test that fails before the fix and passes after.
3. **No fabrication.** Coverage numbers, scan results, and benchmark figures
   come from real commands. If a number cannot be reproduced, it does not
   appear in a PR.
4. **One concern per commit.** Atomic, conventional commits. No drive-by
   refactors in feature commits.

## Development setup

```bash
# Prereqs: uv (https://docs.astral.sh/uv/), git
git clone https://github.com/RichSsa24/Sentinel_Linux2.0.git
cd Sentinel_Linux2.0

# Pin Python and install everything (creates .venv, writes uv.lock if needed).
uv python install 3.12
uv sync --frozen

# Install pre-commit hooks once.
uv run pre-commit install

# Copy the environment template, readable only by you (it will hold secrets).
install -m 600 .env.example .env
```

## Quality gates (must pass before every commit)

The same gates run in CI. Run them locally first.

```bash
uv run ruff check .            # lint + import order + common bug patterns
uv run ruff format --check .   # formatting
uv run mypy                    # strict typing (src + tests, pydantic plugin)
uv run bandit -r src/ -c pyproject.toml
uv export --quiet --format requirements-txt --no-emit-project \
  -o requirements-audit.txt && uv run pip-audit -r requirements-audit.txt --strict --disable-pip
uv run pytest --cov=src/sentinel --cov-report=term-missing   # fails below 95%
uv run pre-commit run --all-files
```

The PostgreSQL integration tests run when `SENTINEL_TEST_POSTGRES_URL` points
at a disposable database. CI provides one and connects as Sentinel's own
non-superuser role, created by `deploy/postgres/initdb/10-sentinel-role.sh` as
in Compose, so nothing passes there that needs more privilege. Changes to
`deploy/prometheus/alerts.yml` must keep `promtool test rules alerts.test.yml`
passing (see the `alerting` job in `ci.yml` for the command).

Performance changes ship with numbers: run `uv run python scripts/benchmark.py`
before and after, and quote both in the commit message. Changes to the
container or Compose stack should pass `scripts/smoke_test_image.sh` locally.

`mypy --strict` is non-negotiable on first-party code. `# type: ignore` is
allowed only with a comment explaining the specific upstream stub gap.

## Commit conventions

Follow [Conventional Commits](https://www.conventionalcommits.org/). Examples:

```
feat(pipeline): bound async queue at 1024 events
fix(collectors/auth): tolerate truncated journald entries
test(detection): cover sudoers modification rule positive + negative
docs(adr): record dedup-window sizing decision
chore(deps): bump pydantic to 2.9.x
ci: pin GitHub Actions runners by SHA
```

- Subject line: imperative, lowercase, no trailing period, ≤ 72 chars.
- Body: explain **why**, not what. The diff already shows what.
- Reference the phase in the body when relevant: `Phase 1 — race condition`.

## Pull-request checklist

Before requesting review:

- [ ] All gates above pass locally.
- [ ] New code is typed; no new `Any`, no new `# type: ignore` without a
      comment explaining the specific upstream stub gap.
- [ ] Tests cover the change, including a negative case for security
      controls.
- [ ] No secrets, no real credentials, no production hostnames in the diff.
- [ ] If a security trade-off was made, it is recorded as an ADR under
      `docs/adr/`.
- [ ] The PR description maps the change to the relevant frameworks
      (OWASP / NIST CSF 2.0 / MITRE ATT&CK / CIS) where applicable.

## Reporting security issues

Do not file vulnerabilities in public issues. See `SECURITY.md`.
