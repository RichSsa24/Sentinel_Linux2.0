# Operating Sentinel-Linux

How to deploy, watch, back up, upgrade and troubleshoot Sentinel-Linux. Every
command here was run against the stack it describes; the alert sections are the
runbook the shipped Prometheus rules link to.

- [Deploy](#deploy)
- [Configuration](#configuration)
- [Health and readiness](#health-and-readiness)
- [Metrics](#metrics)
- [Alerts](#alerts)
- [Logs](#logs)
- [Data: retention, backup, restore](#data-retention-backup-restore)
- [Upgrade and rollback](#upgrade-and-rollback)
- [Troubleshooting](#troubleshooting)

## Deploy

### Docker Compose

The stack runs Sentinel, PostgreSQL, Prometheus (with the alert rules) and
Grafana. Sentinel sees the host read-only under `/host` (`/etc`, `/var/log`,
`/proc`) and reports host-native paths and the host's name.

```bash
install -m 600 deploy/.env.example deploy/.env   # owner-only: it holds the secrets
$EDITOR deploy/.env                              # set the four secrets
docker compose -f deploy/docker-compose.yml up -d --build
curl -s http://127.0.0.1:8000/readyz             # {"success":true,"data":{"status":"ready"}}
```

`deploy/.env` holds `SENTINEL_API_KEY` (32+ characters; Prometheus scrapes with
it too), `POSTGRES_PASSWORD` (the `postgres` superuser, for administration
only), `POSTGRES_APP_PASSWORD` (the `sentinel` role the service connects as)
and `GRAFANA_ADMIN_PASSWORD`. Compose refuses to start while any is missing.
Generate each with `python3 -c "import secrets; print(secrets.token_urlsafe(32))"`.

What the stack does for you:

- **Least privilege.** Sentinel runs as uid 10001 with no capabilities, a
  read-only root filesystem and `no-new-privileges`; it joins group `adm`
  (gid 4) to read `/var/log/auth.log` on Debian and Ubuntu. In PostgreSQL it
  connects as `sentinel`, which owns its database and nothing else (not a
  superuser).
- **Loopback only.** The API (8000) and Grafana (3000) bind to 127.0.0.1;
  put a TLS-terminating reverse proxy in front to expose them. Prometheus and
  PostgreSQL are reachable on the internal network only.
- **Bounded.** Memory and PID limits per service; container logs rotate
  (10 MB × 5).
- **Watched paths match mounts.** File integrity watches `/etc` by default
  (`SENTINEL_FIM_PATHS` in `deploy/.env`). A path you add must also be
  mounted under `/host` in `docker-compose.yml`.

Other settings (alert sinks, gates, retention…) go in `deploy/sentinel.env`,
which Compose reads if present; see [Configuration](#configuration).

### Bare metal (systemd)

`deploy/systemd/sentinel.service` runs `sentinel serve` as an unprivileged,
sandboxed user (`systemd-analyze security` exposure 1.8, "OK"), migrates the
schema before each start, and restarts the service if it exits.

```bash
sudo useradd --system --home-dir /var/lib/sentinel --no-create-home \
     --shell /usr/sbin/nologin sentinel
sudo git clone https://github.com/RichSsa24/Sentinel_Linux2.0.git /opt/sentinel
cd /opt/sentinel && sudo uv sync --frozen --no-dev --no-editable
sudo install -d -m 0700 /etc/sentinel
sudo install -m 0600 deploy/systemd/sentinel.env.example /etc/sentinel/sentinel.env
sudoedit /etc/sentinel/sentinel.env     # set SENTINEL_API_KEY
sudo install -m 0644 deploy/systemd/sentinel.service /etc/systemd/system/
sudo systemctl daemon-reload && sudo systemctl enable --now sentinel
curl -s http://127.0.0.1:8000/readyz
```

The unit stores SQLite at `/var/lib/sentinel/sentinel.db` (created 0600; the
directory is 0700). Values in `/etc/sentinel/sentinel.env` override the unit's,
so the template leaves `SENTINEL_DATABASE_URL` unset; set it only to use
PostgreSQL. (The repository's `.env.example` is for running from a checkout:
its relative SQLite path would point into the read-only `/opt/sentinel`.)

**Visibility versus privilege.** As shipped, the service reads what group `adm`
may read and tracks root-only files (e.g. `/etc/shadow`) by metadata, not by
content. RHEL and Fedora keep `/var/log/secure` root-only, and user crontabs
(`/var/spool/cron`) are root-only everywhere. To read them, grant
`CAP_DAC_READ_SEARCH` — which lets the service read every file on the host if
it is ever compromised:

```ini
# /etc/systemd/system/sentinel.service.d/visibility.conf
[Service]
CapabilityBoundingSet=CAP_DAC_READ_SEARCH
AmbientCapabilities=CAP_DAC_READ_SEARCH
Environment=SENTINEL_AUTH_LOG_PATH=/var/log/secure
```

## Configuration

Every variable is documented in [`.env.example`](../.env.example), which a test
keeps in sync with the code. Unknown `SENTINEL_*` variables are a startup error,
so a typo cannot silently disable a control. The ones operators change most:

| Variable | Default | Notes |
| --- | --- | --- |
| `SENTINEL_API_KEY` | — | 32+ characters; without it the API refuses every data request |
| `SENTINEL_DATABASE_URL` | `sqlite+aiosqlite:///./sentinel.db` | `sqlite+aiosqlite://` or `postgresql+asyncpg://` only |
| `SENTINEL_COLLECTORS` | all four | `auth-log,file-integrity,process,network` |
| `SENTINEL_AUTH_LOG_PATH` | `/var/log/auth.log` | `/var/log/secure` on RHEL and Fedora |
| `SENTINEL_AUTH_LOG_BACKFILL` | `false` | `true` reads the whole log at start-up (see below) |
| `SENTINEL_FIM_PATHS` | `/etc,/var/spool/cron` | Compose: `/etc`; add `/var/log` for log-tampering |
| `SENTINEL_RETENTION_DAYS` | unset (keep all) | delete events and alerts this many days after storing them |
| `SENTINEL_WEBHOOK_URL`, `SENTINEL_WEBHOOK_HMAC_SECRET` | — | HTTPS only; the secret signs each payload (32+ characters) |
| `SENTINEL_SMTP_HOST`, `SENTINEL_EMAIL_FROM`, `SENTINEL_EMAIL_RECIPIENTS` | — | STARTTLS (587) or implicit TLS (465), certificate verified |
| `SENTINEL_ALERT_MIN_SEVERITY`, `SENTINEL_ALERT_THROTTLE_MAX` | 0, 10 | notification gates; throttled alerts are still stored |
| `SENTINEL_PERSIST_WRITE_TIMEOUT_SECONDS` | 10 | a database write that takes longer fails and is retried |
| `SENTINEL_LOG_FORMAT` | `console` (image: `json`) | with `json`, console alerts are JSON lines too |

**The auth log is read from its end at start-up.** A restart therefore does
not re-analyze (and re-alert) the history already in the file; lines written
while the service was stopped are not analyzed either. `SENTINEL_AUTH_LOG_BACKFILL=true`
reads the whole file instead. Rotation is followed like `tail -F`, and a file
that appears after start-up is read from its beginning.

**Baselines.** File integrity, process and network collectors treat what they
see at start-up as the baseline (logged as `*.baseline_seeded`): a change made
while the service was stopped is not reported.

## Health and readiness

| Endpoint | Meaning | Use for |
| --- | --- | --- |
| `GET /healthz` | the process answers | liveness |
| `GET /readyz` | the service can do its job (below) | readiness, the image's `HEALTHCHECK` |

`/readyz` answers 503 with the first reason that applies:

| Reason | Meaning | First step |
| --- | --- | --- |
| `detection pipeline is not running` | nothing is being analyzed | the process exits for a restart on its own; see [SentinelPipelineDown](#sentinelpipelinedown) |
| `database not responding` | no answer within 2 s | database load, network partition |
| `database not reachable` | connection refused or failed | URL, credentials, database up |
| `database schema missing; run alembic upgrade head` | migrations not applied | `alembic upgrade head` (automatic in Docker and systemd) |
| `database writes failing` | reads work, the latest write failed | disk full, read-only volume; see [SentinelPersistenceFailing](#sentinelpersistencefailing) |

Both probes are exempt from the API rate limit (a throttled probe would mark a
healthy service down), and the database half of `/readyz` runs at most once a
second however often it is asked.

If the detection pipeline itself dies, the service shuts down gracefully so
that its supervisor (Docker's restart policy, systemd's `Restart=always`)
starts a fresh one; neither restarts a process merely for failing a health
check. A crashed collector is restarted in-process with exponential backoff.

## Metrics

`GET /metrics` (bearer key) in Prometheus format. Sentinel's own health:

| Metric | Type | Meaning |
| --- | --- | --- |
| `sentinel_pipeline_up` | gauge | 1 while events are being analyzed |
| `sentinel_collector_source_up{collector}` | gauge | 1 while the collector can read its source |
| `sentinel_collector_restarts_total{collector}` | counter | collector crashes (each restarted with backoff) |
| `sentinel_events_ingested_total` | counter | events analyzed |
| `sentinel_events_dropped_total{reason}` | counter | `duplicate` (normal), `queue_full`, `consumer_error`, `dead_letter`, `persist_error` |
| `sentinel_queue_depth`, `sentinel_queue_capacity` | gauge | pipeline queue load |
| `sentinel_detections_fired_total{rule_id,severity}` | counter | rule matches |
| `sentinel_alerts_emitted_total{sink}` | counter | notifications delivered |
| `sentinel_alerts_suppressed_total{reason}` | counter | `severity`, `duplicate`, `throttled` (stored, not notified) |
| `sentinel_alert_sink_errors_total` | counter | deliveries that raised |
| `sentinel_alert_deliveries_dropped_total{sink}` | counter | notifications dropped (sink queue full, or at shutdown) |
| `sentinel_alert_latency_seconds` | histogram | detection to delivery |
| `sentinel_alerts_unpersisted_total` | counter | alerts that could not be stored |
| `sentinel_persist_buffered{kind}` | gauge | events/alerts waiting to be written |
| `sentinel_persist_failures_total` | counter | failed (retried) database writes |
| `sentinel_retention_deleted_total{kind}` | counter | rows deleted by retention |

## Alerts

[`deploy/prometheus/alerts.yml`](../deploy/prometheus/alerts.yml) holds the
rules (the Compose stack's Prometheus loads them; route them with an
Alertmanager). A detector that has stopped detecting looks exactly like a quiet
host, so each way Sentinel can go blind or lose data has a rule.

### SentinelDown

Prometheus cannot scrape Sentinel for 2 minutes. Check the container or unit
(`docker compose ps`, `systemctl status sentinel`) and its logs; a crash loop
shows as repeated `runtime.started` entries. A 401 in Prometheus' target page
means its key differs from `SENTINEL_API_KEY`.

### SentinelPipelineDown

`sentinel_pipeline_up == 0` for a minute: nothing is analyzed. The service
exits for a restart when this happens, so a lasting alert means the restart is
failing — look for `runtime.pipeline_crashed` (with its traceback) and the
supervisor's restart count.

### SentinelCollectorSourceDown

A collector cannot read its source for 10 minutes. The log line
`collector.source_unavailable` names the path and, for the auth log, a hint.
Usual causes: the auth log lives elsewhere (`/var/log/secure`) or is
unreadable (the Compose service needs group `adm`; RHEL needs
`CAP_DAC_READ_SEARCH`); the host logs only to journald (install rsyslog); a
watched path is not mounted under `/host`.

### SentinelCollectorRestarting

A collector crashed more than 3 times in 15 minutes and is blind during each
backoff. `pipeline.collector_crashed` carries the traceback — please report it.

### SentinelNoEvents

No event for an hour while the pipeline runs. A live host starts processes and
opens sockets constantly, so the collectors most likely see nothing: check
`sentinel_collector_source_up` and `SENTINEL_COLLECTORS`, and in a container
the `/host` mounts.

### SentinelEventsDropped

Events were lost in the last 10 minutes. `queue_full`: detection cannot keep
up (see the next alert). `consumer_error`: an event made detection raise
(`pipeline.consumer.error`; please report it). `persist_error`: analyzed but
not stored (see [SentinelPersistenceFailing](#sentinelpersistencefailing)).

### SentinelQueueSaturated

The pipeline queue is over 80% full for 5 minutes. With the default
`SENTINEL_QUEUE_BACKPRESSURE`, collectors block when it fills; with
`drop_newest` events are dropped. Look for an event flood (a scan, a fork
bomb), raise `SENTINEL_QUEUE_MAXSIZE`, or give the service more CPU.

### SentinelPersistenceFailing

Database writes keep failing. Events and alerts are held in memory and retried
with backoff, up to `SENTINEL_PERSIST_MAX_BUFFERED` (then the oldest are
dropped and counted); `/readyz` says `database writes failing`.
`runtime.persist_failed` gives the error type: `OperationalError` (database
down, disk full — check `df`), `TimeoutError` (a write took longer than
`SENTINEL_PERSIST_WRITE_TIMEOUT_SECONDS`). Rows the database rejects
(`runtime.persist_rejected`) are isolated and dropped one by one; they do not
block the rest.

### SentinelAlertDeliveryFailing

A sink raised while delivering. `alert.sink.error` gives the sink and error
type: a webhook's TLS error or non-2xx status, an SMTP authentication or TLS
failure. A webhook resolving to a private address is refused by the SSRF guard
(`SENTINEL_WEBHOOK_ALLOW_PRIVATE` permits it on purpose).

### SentinelAlertDeliveriesDropped

Notifications were dropped: a sink's queue was full (the channel is too slow
for the alert rate) or the service stopped before delivering. The alerts
themselves are stored — read them from `GET /alerts`.

## Logs

Logs are structured (JSON with `SENTINEL_LOG_FORMAT=json`, the image's
default) on stdout, where the console sink writes alerts too (as JSON lines in
JSON mode, `"event": "alert"`). Credentials are redacted and
control characters neutralised before rendering; every request is logged once
as `api.request` with its `request_id` (also returned as `X-Request-ID`).

| Event | Meaning |
| --- | --- |
| `runtime.started` | collectors, rule count, sinks and retention in effect |
| `runtime.rule_paths_not_watched` | rules that cannot fire with the current `SENTINEL_FIM_PATHS` |
| `collector.source_unavailable` / `collector.source_available` | a source went missing / came back |
| `authlog.started_at_end` | bytes of history skipped at start-up |
| `integrity.baseline_seeded` (and process, network) | start-up baseline size |
| `runtime.persist_failed` / `runtime.persist_rejected` | write failures / rows the database refused |
| `runtime.pruned` / `runtime.prune_failed` | retention runs |
| `alert.throttled` | the first notification withheld by a throttle in its window |
| `api.auth_failed` | a refused API call (reason and client, never the key) |
| `storage.database_readable_by_others` | an existing SQLite file other users can read |

## Data: retention, backup, restore

**Retention.** With `SENTINEL_RETENTION_DAYS`, events and alerts are deleted
that many days after Sentinel stored them — at start-up and hourly, in
batches of 5,000 rows. Insertion time decides, not the event's own timestamp:
that comes from the host and could be forged to expire evidence early.

**SQLite.** Back up online with SQLite's backup API (a consistent snapshot
while the service writes):

```bash
sudo -u sentinel sh -c 'umask 077; python3 -I -c "
import sqlite3
src = sqlite3.connect(\"/var/lib/sentinel/sentinel.db\")
dst = sqlite3.connect(\"/var/lib/sentinel/backup.db\")
src.backup(dst); dst.close(); src.close()"'
```

Restore: stop the service, replace `sentinel.db` with the backup (owner
`sentinel`, mode 0600), remove any `sentinel.db-wal` and `sentinel.db-shm`,
start the service.

**PostgreSQL (Compose).**

```bash
C="docker compose -f deploy/docker-compose.yml"
(umask 077; $C exec -T postgres pg_dump -U postgres -d sentinel --format=custom > sentinel.dump)

# restore
$C stop sentinel
$C exec -T postgres pg_restore -U postgres -d sentinel --clean --if-exists \
    --no-owner --role=sentinel < sentinel.dump
$C start sentinel
```

## Upgrade and rollback

**Compose.** `git pull`, then `docker compose -f deploy/docker-compose.yml up -d --build`.
The service applies pending migrations before it starts serving. **Bare
metal:** `git pull && uv sync --frozen --no-dev --no-editable`, then
`systemctl restart sentinel` (the unit migrates before starting).

**Rollback.** Take a backup first. Then return to the previous version (image
or checkout); if the release you leave added migrations, downgrade the schema
to the revision the older version expects before starting it — e.g.
`uv run alembic downgrade 0002` (bare metal) or
`docker compose run --rm sentinel python -m alembic downgrade 0002`. The
migrations so far (0002: `alerts.notified`; 0003: `created_at` indexes) are
reversible without data loss.

### Upgrading a Compose deployment from an earlier release

Read [CHANGELOG.md](../CHANGELOG.md) first: several settings are now validated
strictly. For the database, earlier stacks made Sentinel's role the PostgreSQL
superuser; a bootstrap superuser cannot be demoted, so move the data to a
freshly initialised volume:

```bash
C="docker compose -f deploy/docker-compose.yml"
(umask 077; $C exec -T postgres pg_dump -U sentinel -d sentinel --format=custom > pre-upgrade.dump)
$C down
docker volume rm sentinel_sentinel-db-data
git pull                                  # this release
$EDITOR deploy/.env                       # add POSTGRES_APP_PASSWORD
$C up -d postgres                         # initialises the volume, creates the sentinel role
$C exec -T postgres pg_restore -U postgres -d sentinel --no-owner --role=sentinel < pre-upgrade.dump
$C up -d --build
```

Rehearsed on a database from the previous release: the events survived and
the service migrated the schema to the current revision as the new,
non-superuser role. Prometheus 3 reads the 2.x data volume; going back to
Prometheus 2 needs 2.55 or later. Grafana's data was not persisted before
this release, so there is nothing to migrate.

## Troubleshooting

| Symptom | Cause and fix |
| --- | --- |
| `api_key`: `should have at least 32 items`, or `still the .env.example placeholder` | generate a key: `python3 -c "import secrets; print(secrets.token_urlsafe(32))"` |
| `database_url must use an async driver` | use `postgresql+asyncpg://` or `sqlite+aiosqlite://` |
| `Unknown SENTINEL_* environment variables: [...]` | a typo in a variable name; the message lists it |
| `SENTINEL_WEBHOOK_URL is set but SENTINEL_WEBHOOK_HMAC_SECRET is not` | half-configured sinks fail at start-up rather than silently not alerting |
| `/readyz`: `database schema missing` | run `alembic upgrade head` |
| API returns 401 | the header must be `Authorization: Bearer <key>` with the exact key |
| API returns 429 | per-client rate limit (`SENTINEL_API_RATE_LIMIT` per `SENTINEL_API_RATE_WINDOW_SECONDS`); key holders have their own budget |
| `rules ... cannot fire` warning | add the listed paths to `SENTINEL_FIM_PATHS` (and, in Compose, mount them) |
| An alert you expected did not notify | it may be throttled: `GET /alerts` shows it with `notified: false` |
