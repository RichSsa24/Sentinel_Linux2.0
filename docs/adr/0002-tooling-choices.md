# ADR 0002 — Tooling Choices

- **Status:** accepted
- **Date:** 2026-06-16
- **Deciders:** José Ricardo Solís Arias
- **Phase:** 0

## Context

Sentinel-Linux 2.0 is a portfolio-grade security project. Tool choices are
both engineering decisions and signaling decisions: they tell a recruiter
whether the author tracks the current Python ecosystem and the current
security-tooling baseline. This ADR records the choices made at Phase 0
and why.

## Decisions

### Language: Python 3.12 (CI matrix on 3.12 + 3.13)

- **Why 3.12.** Strong, settled type-checker support (mypy 1.13 is current);
  PEP 695 generics; the structured-pattern-matching surface is mature.
- **Why not 3.14.** Python 3.14 was already installed on the dev host, but
  several first-class security tools (bandit, mypy plugins, some pydantic
  plugins) lag at the time of writing. A portfolio that requires the
  bleeding edge to build is a portfolio that does not build.
- **CI matrix:** `["3.12", "3.13"]` proves forward compatibility without
  paying the 3.14 ecosystem-lag tax.

### Package manager: `uv`

- **Why `uv`.** Fast, reproducible, hash-locked `uv.lock`, manages its own
  Python interpreter (so the project is decoupled from whatever sits on
  the system `PATH`), supports PEP 735 dependency groups, and integrates
  cleanly with both pre-commit and GitHub Actions.
- **Alternatives considered:** `pip-tools` + `requirements.txt` (works but
  slower, more ceremony, no interpreter management); `poetry` (slower CI,
  larger metadata churn, dependency-resolver quirks).
- **Reproducibility:** `uv.lock` carries cryptographic hashes for every
  pinned dependency. `uv sync --frozen` is the only install path used in
  CI; drift is caught immediately.

### Build backend: `hatchling`

- Minimal, PEP 621-native, well documented, plays well with `uv`. The
  `src/`-layout makes the package boundary unambiguous.

### License: MIT

- **Why MIT.** Maximum reach for a portfolio piece; no copyleft friction
  for any potential employer's evaluation; clear and short.
- **Alternative considered:** Apache-2.0 — explicit patent grant is
  attractive, but the project does not introduce novel algorithms that
  would benefit from one, and the longer text adds friction for a piece
  meant to be read end-to-end.

### Quality gates

| Tool             | Role                                          |
|------------------|-----------------------------------------------|
| `ruff` (lint)    | Lint, import order, pyupgrade, datetimez, security subset (`S`), simplify, async, comprehensions, return-value patterns. Strict ruleset; per-test ignores documented in `pyproject.toml`. |
| `ruff format`    | Formatter; replaces Black for speed and single-tool consistency. |
| `mypy --strict`  | Strict typing across `src/` and `tests/`. `# type: ignore` allowed only with a comment naming the specific upstream stub gap. |
| `bandit`         | Python-specific security lint over `src/`. |
| `pip-audit`      | Known-vulnerable dependency scan; `--strict` (warnings = errors). |
| `pytest`         | Test runner; `pytest-asyncio` for async tests; `pytest-cov` for branch coverage. |
| `hypothesis`     | Property-based testing (Phase 1+ — idempotency, dedup, rule evaluator). |
| `pre-commit`     | Runs ruff, mypy, bandit, detect-secrets, and hygiene hooks on every commit. |
| `detect-secrets` | Baseline-driven secret-scanning pre-commit hook. |
| GitHub Actions   | CI runs every gate on Ubuntu 24.04 across the Python matrix. |

### Logging: `structlog`

- **Why.** Structured JSON output by default; processor pipeline makes
  cross-cutting controls (redaction, control-char stripping, UTC
  timestamps) trivial to enforce; mature stdlib bridge.
- **Alternative considered:** `loguru` (less explicit pipeline, harder to
  inject security-relevant processors), stdlib `logging` only (verbose,
  no native structured output, redaction must be bolted on).

### Configuration: `pydantic-settings`

- **Why.** Strict, typed, env-driven, refuses unknown prefixed variables
  (`extra="forbid"`), refuses to start without required values. This is
  the same library used to validate API request bodies in Phase 6,
  reducing the surface area we have to maintain.

### Detection-rule format: declarative YAML (Sigma-inspired)

- Decided in principle here; implemented in Phase 4. Rule files are
  parsed with `yaml.safe_load`, validated against a strict Pydantic
  schema, and evaluated by an allowlisted operator grammar — never by
  executing rule strings. **Rules are data, never code.**

## Trade-offs accepted

- **`uv` as a contributor prerequisite.** Contributors must install `uv`.
  This is documented in `CONTRIBUTING.md`; it is one command on every
  platform. The reproducibility win is worth the small onboarding cost.
- **GitHub Actions versioned by tag, not SHA, in the CI workflow.** SHA
  pinning is the CIS-aligned posture for org-wide policy, but in a public
  portfolio repo the major-version tag is the readable choice. The
  workflow file carries a comment noting that SHA pinning is recommended
  for production. Container base images (Phase 7) **are** pinned by
  digest.
- **Filter warnings = error in pytest.** Surfaces upstream deprecations
  early. If a noisy upstream needs to be tolerated, it is allowlisted
  narrowly in `pyproject.toml` rather than globally silenced.

## Consequences

- A new contributor runs three commands and has the full gated toolchain
  working: `uv python install 3.12`, `uv sync --frozen`,
  `uv run pre-commit install`.
- Adding a new gate is a one-line addition to `pyproject.toml` plus a
  one-line addition to `.pre-commit-config.yaml` and `ci.yml`.
- The same gates run locally, in pre-commit, and in CI — there is one
  source of truth for "does this code pass."
