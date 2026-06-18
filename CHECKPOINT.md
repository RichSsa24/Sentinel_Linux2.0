# Sentinel-Linux 2.0 — Work Checkpoint

> **Purpose:** hand-off note so the next session can continue without re-deriving
> context. Snapshot date: **2026-06-17**. This file is working state, not shipped
> docs — delete or ignore once the work is committed.

---

## TL;DR for tomorrow

- **Phase 1 (pipeline spine) is complete and green.**
- **Phase 2 (collectors) is COMPLETE: all 4 collectors done** — auth-log, FIM,
  `/proc` process, and the **network/socket collector** (added this session,
  split into `network.py` + a pure `netparse.py` parser).
- **Phase 2 is at its gate, awaiting the `APPROVE PHASE 2` token** before Phase 3.
- **Nothing is committed yet.** The entire working tree (Phases 0→2) is
  uncommitted on `main` by the user's explicit choice. Do **not** commit without
  asking — see [Open decisions](#open-decisions).
- Full gate is green: **203 tests pass, 98.3% coverage, ruff (check + format) +
  mypy + bandit + pip-audit all clean.**

---

## How to run the gate

The project uses `uv`, but a `.venv` already exists. Either works:

```bash
# Tests + coverage (branch coverage on)
.venv/Scripts/python.exe -m pytest -q --cov=sentinel --cov-branch --cov-report=term-missing

# Lint / format / types / security / deps
.venv/Scripts/python.exe -m ruff check src tests
.venv/Scripts/python.exe -m ruff format --check src tests   # added this session
.venv/Scripts/python.exe -m mypy src tests
.venv/Scripts/python.exe -m bandit -c pyproject.toml -r src
.venv/Scripts/python.exe -m pip_audit
```

CI (`.github/workflows/ci.yml`) runs the same on a py3.12+3.13 matrix. There is
**no `fail_under` coverage gate** in CI, but the user's standard is **80% line /
70% branch minimum** — keep new modules well above that.

> **Note (this session):** the prior gate runs only ran `ruff check`, never
> `ruff format --check` (which the directive §3.5 requires). Running it revealed
> the three earlier collectors were hand-wrapped at ~88 cols against the
> configured `line-length = 100`. The whole tree was normalized with
> `ruff format` (whitespace only, `# fmt: skip` blocks preserved). The tree is
> now format-clean; keep it that way.

---

## Project context

Host-based Linux security monitor. The headline engineering story is **killing the
v1 double-collection race condition structurally** (one producer per source +
bounded queue + idempotent dedup), proved by a keystone test.

- Architecture: `docs/adr/0001-architecture-overview.md` (7 layers, mermaid diagram).
- Tooling rationale: `docs/adr/0002-tooling-choices.md`.
- Phase roadmap: `README.md` (Phases 0–8).
- The ADR references an **external "build directive"** (its §3.1/§3.2/§3.3) that is
  NOT in the repo — those section numbers appear in code comments. The key
  invariants are captured in code, so you don't strictly need the directive.

Phase roadmap: 0 scaffold ✅ · 1 spine ✅ · 2 collectors ✅ · **3 normalizer (next)** ·
4 detection engine + YAML rules · 5 alerting · 6 persistence + API ·
7 dashboard + containerization · 8 validation + release.

---

## What exists now (`src/sentinel/`)

| Module | Status | Purpose |
|--------|--------|---------|
| `settings.py` | done | Typed env-driven config (`SENTINEL_*`), fail-closed. Has `BackpressurePolicy` + queue/dedup fields. |
| `logging.py` | done | structlog pipeline: control-char strip (CWE-117) + sensitive-key redaction. |
| `events.py` | done (extended this session) | Frozen, `extra="forbid"` ECS event schema. `event.id` = SHA-256 idempotency key. |
| `pipeline/queue.py` | done | Bounded `asyncio.Queue[Event]` with `BLOCK` / `DROP_NEWEST` backpressure. |
| `pipeline/dedup.py` | done | TTL + size-bounded dedup window (the race-condition kill). |
| `pipeline/runner.py` | done | `Pipeline`: one-producer-per-source registry, single consumer, consumer-error firewall. |
| `collectors/base.py` | done | `AbstractCollector` contract (`run`/`stop`/`stopping`/`wait_stop`). |
| `collectors/authlog.py` | **done this session** | `AuthLogCollector` + `parse_auth_line` — tails sshd auth log. |
| `collectors/integrity.py` | **done this session** | `FileIntegrityCollector` — FIM (AIDE/Tripwire-style). |
| `collectors/process.py` | done | `ProcessCollector` + `parse_stat` — `/proc` lifecycle monitor. |
| `collectors/netparse.py` | **done this session** | Pure `/proc/net/tcp` parser: IPv4/IPv6 hex decode, state table, `Socket`. No I/O, only stdlib `ipaddress`. |
| `collectors/network.py` | **done this session** | `NetworkCollector` — diffs LISTEN/ESTABLISHED sockets from `/proc/net/tcp[6]`. |

### Schema extensions (`events.py`)
- (earlier) `File` + `FileHash` models and optional `Event.file` (for FIM);
  `Process.ppid` and `Process.command_line`.
- **This session:** added the `Destination` model (ECS `destination.*`, mirrors
  `Source`) and optional `Event.destination`, populated by the network collector
  for established connections.
- All additions are **additive/optional** — existing events and tests untouched.

---

## What was built this session (Phase 2, three collectors)

All three share a deliberate, repeated pattern — **keep it for the socket collector too:**

1. **A pure, unit-testable parser** separated from I/O (`parse_auth_line`,
   `parse_stat`). Locale-independent, length-capped, **rejects rather than coerces**
   malformed input (per §3.3).
2. **A collector** subclassing `AbstractCollector` with the same shape:
   - poll loop: `while not self.stopping: await self._drain_once(queue); if await self.wait_stop(timeout): break` then a **final catch-up `_drain_once`**.
   - blocking I/O wrapped in `asyncio.to_thread` (never block the event loop).
   - **degrade safely**: missing/unreadable sources are logged and skipped, never fatal.
   - a `stats` property exposing counters for tests/observability.
3. **Deterministic `event.id`** over identity fields so a re-read/re-baseline race
   dedups to exactly-once.
4. **A keystone-style exactly-once test** driving the collector through the real
   `Pipeline` and asserting `processed=N, deduped=M`.

### Collector specifics
- **auth-log** (`authlog.py`): parses sshd `Failed/Accepted password|publickey` and
  `Invalid user`. Portable file-tailer: rotation/truncation detection (shrinking size),
  partial-line buffering, syslog timestamp parsed with an explicit month table (no
  locale-dependent `%b`), configurable `year`/`tz`. Headline demo: log rotation
  re-read → dedup → exactly-once.
- **FIM** (`integrity.py`): snapshots watched paths (size/mtime/mode/streamed SHA-256),
  diffs → `file_created` / `file_modified` / `file_attributes_modified` / `file_deleted`.
  Baseline-silent first scan. Only regular files via `lstat` (never follows symlinks).
  Caps: `max_hash_bytes`, `max_files`.
- **process** (`process.py`): enumerates numeric `/proc` dirs → `process_started` /
  `process_stopped`. **Identity = `(pid, starttime)`** to survive pid recycling.
  `proc_root` is injectable (testable on Windows / no-`/proc` hosts). Cap: `max_procs`.
  Known limit (documented): polling misses processes that start+exit within one interval.

### Tests added this session
- `tests/test_collectors_base.py` (closed a pre-existing 60% coverage gap → 100%)
- `tests/test_collectors_authlog.py`
- `tests/test_collectors_integrity.py`
- `tests/test_collectors_process.py`

---

## Conventions to follow (from the user's global rules)

- Python 3.10+ modern typing (`X | None`, `list[str]`), type hints on every function.
- No bare `except` — catch specific exceptions. No `shell=True`.
- Files ≤ 300 lines, functions ≤ 50 lines, ≤ 3 nesting levels (early returns).
- Comments explain **why**, not what. No magic numbers (use named `Final` constants).
- Commits: Conventional Commits, imperative, lowercase, ≤ 72 chars (e.g.
  `feat(collectors): add /proc process lifecycle collector`).
- Tests: AAA, `should ... when ...` intent, one behavior per test, deterministic
  (no real time/network/random — inject clocks, use `tmp_path`).
- **Cross-platform caveat:** dev host is **Windows**. `zoneinfo` IANA names fail
  (no `tzdata`) — use fixed-offset `timezone(timedelta(...))` in tests. Symlink
  creation is privileged — avoid in tests; use `lstat`/monkeypatch instead.
- There's a `code-review-graph` MCP — prefer it over Grep/Glob for exploration
  (see project `CLAUDE.md`). It auto-updates on file changes.

---

## Next steps (in order)

1. **Phase 3 (normalizer)** — settle a boundary question with the user FIRST: the
   current collectors already emit fully-formed `Event`s (the queue is
   `Queue[Event]`), so the ADR's "normalizer converts raw → Event" no longer maps
   1:1. Likely resolution: the normalizer owns the per-collector field-mapping
   (the `parse_*`/`netparse` layer + each collector's `_build` become the
   normalizer's mappers) or becomes a post-queue enrichment/severity step.
   **Clarify scope with the user before building.**
   - The network collector left a clean seam to reuse: `netparse.Socket` (raw) →
     `NetworkCollector._build` (→ `Event`). That raw→Event step is exactly what a
     normalizer would own across all four collectors.
2. **Deferred for the network collector:** pid→socket attribution (a
   `/proc/<pid>/fd` inode scan, costly). Add it only if connection→process mapping
   is wanted. UDP (`/proc/net/udp`) was also left out deliberately — TCP LISTEN/
   ESTABLISHED carries the clean security signal; UDP state semantics are murkier.

---

## Open decisions

- **Commit strategy (BLOCKER for landing the work).** The user was asked
  (branch + PR vs commit on `main` vs not yet) and chose **"don't commit yet."**
  The user's git rules say `main` is protected / no direct pushes, but the existing
  history commits directly to `main`. **Ask again before committing.**
- **Normalizer boundary** (see Next steps #2) — confirm with the user.

---

## Working-tree state (uncommitted)

```
 M pyproject.toml                  # this session: S104 test ignore (fake bind addrs)
 M src/sentinel/__init__.py        # exports for all collectors + Destination
 M src/sentinel/settings.py        # (Phase 1) BackpressurePolicy + queue/dedup fields
 M tests/test_settings.py
?? CHECKPOINT.md                   # this file
?? src/sentinel/collectors/        # base, authlog, integrity, process, netparse, network
?? src/sentinel/events.py          # ECS schema (+ File/FileHash, Process fields, Destination)
?? src/sentinel/pipeline/          # queue, dedup, runner
?? tests/test_collectors_authlog.py
?? tests/test_collectors_base.py
?? tests/test_collectors_integrity.py
?? tests/test_collectors_network.py   # this session
?? tests/test_collectors_process.py
?? tests/test_events.py
?? tests/test_pipeline_dedup.py
?? tests/test_pipeline_keystone.py
?? tests/test_pipeline_queue.py
```

> The 3 earlier collectors + their tests show as `??` (untracked) but were
> reformatted in place by `ruff format` this session — whitespace only.

Last gate result: **203 passed, 98.3% total coverage; ruff (check + format),
mypy, bandit, pip-audit all clean.** (collectors: netparse 100%, network 100%,
authlog/process 99.4%, integrity 96.4%.)
