# ADR 0004 — Operating Safely: Fail Safe, Stay Visible, Least Privilege

- **Status:** accepted
- **Date:** 2026-10-18
- **Deciders:** José Ricardo Solís Arias
- **Phase:** 10 (security review and operations readiness)

## Context

A line-by-line review of the running system — API, collectors, detection,
alerting, storage, deployment and operations — found that the dangerous
failures of a detector are quiet ones. Representative findings, each
reproduced before it was fixed:

- Padding a command line until a rule's regex timed out made the rule read
  "no match": an attacker could buy a miss.
- Decoy events could exhaust a rule's throttle, and the throttled alert — the
  real attack — was neither notified nor stored.
- One hung webhook held the single delivery path; a crashed collector stayed
  dead behind a green `/readyz`; a full disk left `/readyz` green while every
  write failed.
- In Docker the auth-log collector could not open `/var/log/auth.log` at all,
  and nothing said so.
- On bare metal Sentinel alerted on its own API listener at start-up, two
  times in three.

## Decisions

### 1. Fail safe, never open

When the system cannot decide, it reports. A regex that runs out of time fires
its rule (`EvaluationIncomplete`); a value too long to scan whole is scanned at
both ends. The throttle withholds *notifications* only: throttled alerts are
stored with `notified: false` and announced in the next notification. A file
whose content cannot be hashed is compared by `ctime`, and any metadata change
is reported as a possible modification.

*Alternative rejected:* treating a timeout as "no match" with a metric — it
keeps the false-positive rate down and hands the attacker the evasion.

### 2. Isolate every failure domain

Each alert sink has its own bounded queue, worker and per-delivery deadline
(bulkhead pattern); a full queue drops and counts. Collectors run under a
supervisor that restarts a crashed one with exponential backoff. If the
pipeline itself dies, the process exits so that Docker or systemd starts a
fresh one — neither restarts a process for failing a health check. Database
writes have a deadline, so a hung database cannot hang shutdown.

### 3. Make blindness visible

Readiness covers what the service needs to do its job: the pipeline running,
the database answering (within 2 s), the schema present and writes succeeding.
Each collector reports whether it can read its source
(`sentinel_collector_source_up`), logging only changes. Prometheus rules alert
on scrape loss, a dead pipeline, an unreadable source, a crash loop, an hour
without events, dropped events, a saturated queue, failing writes and failing
or dropped notifications; each links to a runbook section, and tests keep the
rules, the metrics and the runbook in step.

The probes are exempt from the rate limit (a throttled probe would let any
client mark the service down), so the database half of `/readyz` runs at most
once a second whoever asks.

### 4. Restarts must not page

The auth log is opened at its current end at start-up, and the other
collectors take a fresh baseline; Sentinel ignores its own sockets (by inode,
through `/proc/self/fd`). A restart therefore produces no alerts of its own.

*Trade-off accepted:* activity while the service is stopped is not analyzed.
`SENTINEL_AUTH_LOG_BACKFILL=true` re-reads the whole log instead. A persisted
read offset (a "registry", as log shippers keep) would close the gap and is
the next step if that window matters.

### 5. Keep evidence honest, and no longer than needed

Retention is opt-in (`SENTINEL_RETENTION_DAYS`) and measured from insertion
time, which Sentinel sets — never from the event's own timestamp, which comes
from the host and could be forged to expire evidence early. Deletion runs in
bounded batches so the writer is never locked out for long. Reading the API
never writes (an autoflushed `UPDATE` had held SQLite's write lock).

### 6. Least privilege, with the trade-off stated

- The container runs as uid 10001, chosen so that no host account shares it
  (999 often belongs to one, and the host's `/proc` is mounted), with no
  capabilities and a read-only root filesystem; it joins group `adm` only,
  to read the auth log.
- PostgreSQL gives Sentinel a role that owns its database and nothing else; the
  superuser's password never reaches the service.
- The systemd unit runs an unprivileged user in a sandbox
  (`systemd-analyze security`: 1.8).
- `CAP_DAC_READ_SEARCH` would let Sentinel hash root-only files and read user
  crontabs and RHEL's `/var/log/secure`. It is documented as an opt-in, not
  the default: it would also let a compromised service read every file on the
  host.

## Consequences

- Each decision has a test that fails without it, and the security-relevant
  tests were checked by mutation (the guarded code was broken on purpose).
- Operators get one runbook (`docs/OPERATIONS.md`) that the alert rules link
  into, and a changelog listing every setting that is now validated strictly.
- The rule engine is slower than before the review (more conditions per event,
  see ADR 0003's re-measurement); detection coverage was preferred over speed.
