# ADR 0003 — Runtime Composition and Performance

- **Status:** accepted
- **Date:** 2026-10-17
- **Deciders:** José Ricardo Solís Arias
- **Phase:** 9 (hardening and optimization pass)

## Context

By the end of Phase 8 every layer of ADR 0001 existed and was unit-tested, but
the layers were wired together inside the web lifespan, and that wiring had no
tests. An audit of the running system found:

- **Configuration that did nothing.** `configure_logging()` was never called in
  production, so the control-character stripping and secret redaction never ran.
  Webhook/email sinks, alert gates and per-rule throttles were ignored. Collector
  sources were hard-coded, so the container's `/host/proc` mount was never read.
- **Silent failure modes.** A crashed pipeline left `/readyz` green; a typo'd
  rules path loaded zero rules; `sh -c` as PID 1 meant `docker stop` SIGKILLed
  the service before it could drain.
- **Throughput bounded by the wrong thing.** One SQLite commit per event capped
  the whole system at roughly 500 events/s, while the pipeline itself sustained
  ~350,000.

## Decisions

### 1. A single composition root

`sentinel/runtime.py` turns validated `Settings` into collectors, sinks and an
alert manager, and `Runtime` owns start, health, graceful drain and resource
release. The web layer only starts and stops it. Half-configured channels raise
`ConfigurationError` at startup (fail closed), and `/readyz` reports the
pipeline's liveness, not just the database's.

*Trade-off:* one more module; in exchange the production wiring is testable
without HTTP and is exercised end to end in `tests/test_runtime.py`.

### 2. Write-behind persistence

Detection and alert delivery stay synchronous with consumption; the database
write never runs on that path. Events and their alerts are buffered, and a
dedicated flusher task writes them in one transaction when
`SENTINEL_PERSIST_BATCH_SIZE` events are buffered (the consumer only signals
it) or every `SENTINEL_PERSIST_FLUSH_INTERVAL_SECONDS`, and on shutdown. Batches
use a bulk `executemany` INSERT (audit rows never need their generated keys
back). SQLite runs in WAL mode with `synchronous=NORMAL`.

A failed write is put back at the front of the buffer and retried with
exponential backoff (capped at 30 s), so a database restart loses nothing.
During a longer outage the buffer is capped at `SENTINEL_PERSIST_MAX_BUFFERED`
records: the oldest are dropped, and they — like anything still unwritten at
shutdown — are counted in `sentinel_events_dropped_total{reason="persist_error"}`
and `sentinel_alerts_unpersisted_total`. Alerts are delivered to their sinks
regardless.

A batch the database refuses for its *content* (SQLSTATE class 22 or 23, e.g.
a value too long) is not an outage: retrying it would block every later write.
It is retried row by row; rows still refused are dropped and counted the same
way. The SQLSTATE, not the exception type, decides, because SQLAlchemy's
asyncpg adapter reports most data errors as a bare `DBAPIError`.

*Trade-offs:* the read API may lag by about one flush interval (0.5 s default);
a hard kill loses what was buffered — events that were only in memory anyway;
SQLite may roll back the last transactions on power loss (no corruption).
PostgreSQL is recommended where durability matters. *Result:* ~500 → ~20,000
events/s end to end (code review then moved the size-triggered write off the
consumer path, which roughly doubled the first version's ~10,000).

### 3. Index rules by the actions they can match

`required_actions()` statically derives, from each rule's condition tree, the
set of `event.action` values the rule could ever match; the engine evaluates
only those rules (and skips building the event view when none apply). The
derivation is conservative — anything it cannot prove (negations, negative
operators, other fields) means "any action".

*Validation:* a Hypothesis property test over random condition trees, plus a
differential test against an unindexed engine over the rule library's cases.
*Result:* ~1.7× rule-engine throughput.

### 4. Stat cache for file integrity, keyed on ctime

A file whose `(size, mtime, ctime, inode, device)` is unchanged keeps its
digest. `mtime` alone is unsafe (`touch -d` restores it); `ctime` is maintained
by the kernel and cannot be set from userspace. Because timestamps come from a
coarse clock, entries changed within 2 s of a scan are re-hashed next poll —
the same "racy clean" rule Git applies to its index. For files that cannot be
hashed at all, `ctime` also joins the size/mtime fallback.

*Result:* ~4× cheaper steady-state polls. *Residual risk:* an attacker able to
set the system clock (`CAP_SYS_TIME`) could forge `ctime` — at that privilege
level they can also stop the collector.

### 5. Read the host through a mount, report it natively

Collectors take a `host_root` (Falco/osquery convention) and report host-native
paths and the host's own name. The network collector reads `/proc/1/net`
behind a host mount, because `/proc/net` is a symlink to the *reader's*
namespace.

## Consequences

- Every optimization shipped as its own commit with a before/after measurement
  from `scripts/benchmark.py`, and each has a test that would fail if it hid an
  event. Correctness constraints were never relaxed for speed.
- The bottleneck is now the rule engine and Python object construction rather
  than I/O. The next step change is a kernel event source (eBPF) rather than
  further micro-optimization of polling collectors.
- Operators gained explicit knobs (`SENTINEL_COLLECTORS`, `SENTINEL_HOST_ROOT`,
  `SENTINEL_PERSIST_*`, ...), all validated at startup and documented in
  `.env.example`, which a test keeps in sync with `Settings`.
