# Changelog

All notable changes to this project. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/); the project is
pre-1.0, so a minor version may change behaviour.

## [Unreleased] — hardening and operations

A line-by-line security and quality review of the whole system, with every
finding fixed behind a test that failed before the fix, followed by the work
needed to run Sentinel in production. Read the [upgrade notes](#upgrade-notes)
before deploying over an earlier version.

### Security

- **Credentials.** The API key is never logged on a failed login; secrets stay
  out of start-up validation errors; weak API keys (under 32 characters, or the
  template's placeholder) and wildcard CORS origins are refused; SMTP verifies
  the server's certificate and host name (credentials were readable by a
  machine in the middle) and refuses credentials without TLS.
- **API.** `X-Forwarded-For` is not trusted (it let any local process pick its
  rate-limit bucket and forge its address in the logs); key holders have a
  rate-limit budget separate from anonymous traffic; every response carries
  the security headers (429, 500 and CORS preflights included); unhandled
  errors return a generic 500 with a request id; cursors are bounded.
- **Logging.** Library logs (uvicorn, httpx) pass through the redacting,
  control-character-stripping pipeline; console alerts escape control
  characters, so a host name taken from a syslog line cannot drive the
  operator's terminal.
- **Detection cannot be blinded by input.** Oversized command lines, paths,
  ports or non-UTF-8 names no longer stop a collector; a file-integrity scan
  never follows, blocks on, or over-reads a swapped entry; regex rules fail
  safe (a timeout fires the rule instead of reading as "no match", and padding
  cannot push a payload out of the scanned window); rule evasions found in
  review are closed and every pattern is bounded; IPv6 address rotation within
  a /64 cannot dodge a threshold; a connection flood cannot hide a listener;
  a forged event timestamp cannot expire evidence under retention.
- **Alerting.** The throttle withholds notifications, never evidence (throttled
  alerts are stored with `notified: false` and announced); the webhook's SSRF
  guard covers CGNAT and IPv4-mapped addresses and pins the connection to the
  address it checked (DNS rebinding); redirects count as failures.
- **Deployment.** The container runs as uid/gid 10001 (999 belonged to host
  accounts); PostgreSQL gives Sentinel its own non-superuser role; SQLite
  databases are created owner-only; `scripts/demo.sh` cannot import planted
  modules when run with sudo; env files are created 0600.
- **Supply chain.** Every image is pinned by tag and digest, the build backend
  by version, uv in CI by version; pip-audit runs on the hashed lockfile export
  without installing pip; checkouts do not persist the job token; a weekly
  workflow scans every deployed image.

### Added

- Collector supervision: a crashed collector restarts with exponential backoff;
  if the pipeline dies, the process exits so its supervisor restarts it.
- `SENTINEL_RETENTION_DAYS`: hourly, batched deletion by insertion time.
- Per-collector source availability (`sentinel_collector_source_up`), logged
  when a source goes missing or comes back, with a hint for the auth log.
- Persistence health: `/readyz` reports failing writes; write deadline
  (`SENTINEL_PERSIST_WRITE_TIMEOUT_SECONDS`); metrics for buffered records and
  failed writes.
- Prometheus alert rules for a blind, data-losing or silent detector, unit-
  tested with promtool, and an operations runbook (`docs/OPERATIONS.md`).
- A hardened systemd unit for bare-metal installs.
- `SENTINEL_AUTH_LOG_BACKFILL`, and support for OpenSSH 9.8+'s
  `sshd-session`, RFC 3339 timestamps, rsyslog's repeat summaries and more
  authentication methods; log rotation is followed like `tail -F`.
- CI: PostgreSQL integration tests, promtool, weekly image scan.

### Changed

- The auth log is read from its current end at start-up, so a restart does
  not re-alert its history (`SENTINEL_AUTH_LOG_BACKFILL=true` restores the old
  behaviour).
- Alert sinks deliver through per-sink queues with deadlines: a slow or hung
  channel delays neither detection nor the other channels.
- `/healthz` and `/readyz` are exempt from the rate limit; the database half
  of `/readyz` runs at most once a second, with a 2 s deadline.
- List endpoints report `total` on the first page only (counting is a table
  scan; per page it made a full walk quadratic).
- With `SENTINEL_LOG_FORMAT=json`, console alerts are JSON lines.
- The network collector ignores Sentinel's own sockets (its API listener
  raised `new-listening-service` on two starts in three).
- Compose: Prometheus 3.15, Grafana 13.2 (data now on a volume), PostgreSQL
  16.15; resource limits and log rotation for every service.

### Fixed

- Reading the API no longer issues an `UPDATE` (a write lock against the
  event writer); rows the database rejects are isolated instead of blocking
  every write; a database outage never drops rows, and a hung one cannot hang
  shutdown. A write that committed but whose acknowledgement was lost (a
  deadline, a dropped connection) was retried and stored twice; records now
  carry a write id and the retry skips what is already stored.
- File integrity: a return to an earlier state is a new event, not a duplicate;
  permission and content changes are reported independently; `chmod`/`chown`
  cannot mask an edit.
- The Compose stack's container could not read `/var/log/auth.log` (root:adm),
  and watched an unmounted path.
- When the auth log's rotated-in file could not be opened yet (created
  root-only, say), the old file's last lines, read in the same poll, were
  discarded; they are now analyzed, and the new file is retried and reported
  unavailable until it can be read.
- `sentinel demo` no longer warns about a rule it then fires.

### Upgrade notes

Settings are validated strictly; each of these was accepted before:

- `SENTINEL_API_KEY` must be at least 32 characters and not the template's
  placeholder; `SENTINEL_WEBHOOK_HMAC_SECRET` at least 32 characters.
- `SENTINEL_DATABASE_URL` must name `sqlite+aiosqlite` or `postgresql+asyncpg`.
- `SENTINEL_API_CORS_ORIGINS` may not contain `*`.
- The rule loader refuses rules that could never fire: unknown field paths,
  values of the wrong type for their operator, and thresholds nested below the
  root condition. Check custom rules with `sentinel rules`.

Data and deployment:

- Migrations 0002 (`alerts.notified`), 0003 (`created_at` indexes) and 0004
  (`write_id`, unique) run automatically in Docker and under the systemd unit;
  on other bare-metal setups run `alembic upgrade head`. Rows stored before
  0004 keep a NULL write id.
- Compose needs a fourth secret, `POSTGRES_APP_PASSWORD`. An existing database
  volume keeps Sentinel's old superuser role; move it to the least-privilege
  role with the dump-and-restore steps in
  [docs/OPERATIONS.md](docs/OPERATIONS.md#upgrading-a-compose-deployment-from-an-earlier-release).
- File integrity watches `/etc` and `/var/spool/cron` by default (bare metal)
  and `/etc` in Compose; set `SENTINEL_FIM_PATHS` to keep a different list.
- Auth-log event ids changed (repeated identical failures are now distinct
  events), so an event re-read across the upgrade is not deduplicated against
  the old one.
- The image runs as uid 10001 and starts through `sentinel serve`.
