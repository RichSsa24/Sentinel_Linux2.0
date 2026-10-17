# Sentinel-Linux 2.0

[![CI](https://github.com/RichSsa24/Sentinel_Linux2.0/actions/workflows/ci.yml/badge.svg)](https://github.com/RichSsa24/Sentinel_Linux2.0/actions/workflows/ci.yml)
![Python](https://img.shields.io/badge/python-3.12%20%7C%203.13-blue)
![Typing](https://img.shields.io/badge/mypy-strict-informational)
![License](https://img.shields.io/badge/license-MIT-green)

**A host-based intrusion detection system for Linux, written in async Python.**
Four collectors watch SSH logins, processes, files and sockets; a bounded,
deduplicating pipeline feeds 17 declarative, MITRE ATT&CK-mapped rules; alerts
go out through hardened sinks; everything is queryable through an authenticated
API and Prometheus.

It is built to be *read*: every security claim below points at the code or the
test that backs it, and every number comes from a script you can re-run.

Built and maintained by **José Ricardo Solís Arias** ([@RichSsa24](https://github.com/RichSsa24)).

---

## Try it in 30 seconds

No root, no Docker — just [uv](https://docs.astral.sh/uv/):

```bash
git clone https://github.com/RichSsa24/Sentinel_Linux2.0.git && cd Sentinel_Linux2.0
uv sync
uv run sentinel demo
```

`sentinel demo` replays a scripted intrusion through the **real** pipeline —
normalizer, bounded queue, dedup window, rule engine, alert manager and a
throwaway SQLite database — mixed with benign activity and a duplicate record
(output abridged):

```text
[HIGH]     ssh-brute-force (T1110)            :: SSH brute-force login attempts
[MEDIUM]   ssh-root-login (T1078.003)         :: Successful SSH login as root
[MEDIUM]   interactive-shell-spawn (T1059.004)
[CRITICAL] reverse-shell-process (T1059.004)  :: Reverse-shell-style process invocation
[HIGH]     c2-beacon-port (T1571)             :: Outbound connection to a known C2 port
[MEDIUM]   base64-execution (T1027)
[HIGH]     suspicious-tmp-exec (T1059)
[MEDIUM]   account-creation (T1136.001)
[MEDIUM]   cron-persistence (T1053.003)
[HIGH]     new-suid-binary (T1548.001)
[HIGH]     log-tampering (T1070.002)

Replayed 19 records -> 18 events stored (1 duplicate dropped by the dedup window).
11 alerts from 11 rules; 0 alerts on the 3 benign events.
```

The demo is a test, too: [`tests/test_cli.py`](tests/test_cli.py) fails CI if
any attack step stops being detected or a benign event starts alerting.

`uv run sentinel rules` validates and lists the rule library;
`uv run sentinel serve` runs the full service.

## Architecture

```mermaid
flowchart LR
    subgraph Host["Host (read-only, optionally under /host)"]
        AUTH["/var/log/auth.log"]
        PROC["/proc/&lt;pid&gt;"]
        FS["/etc and other watched paths"]
        NET["/proc/1/net/tcp, tcp6"]
    end

    subgraph Collectors["Collectors — one producer per source"]
        C1[auth-log]
        C2[process]
        C3[file-integrity]
        C4[network]
    end

    NORM[Normalizer<br/>raw → ECS Event<br/>dead-letters bad input]
    Q[[Bounded queue<br/>backpressure]]
    D{Dedup window<br/>SHA-256 event.id}
    ENG[Detection engine<br/>17 YAML rules<br/>action index]
    AM[Alert manager<br/>severity · dedup · throttle]
    SINKS[Console · Webhook HMAC · Email TLS]
    WB[(Write-behind<br/>batched SQLite / PostgreSQL)]
    API[FastAPI<br/>bearer auth · rate limit]
    PROM[Prometheus /metrics]

    AUTH --> C1
    PROC --> C2
    FS --> C3
    NET --> C4
    C1 & C2 & C3 & C4 --> NORM --> Q --> D --> ENG --> AM --> SINKS
    ENG --> WB
    AM --> WB
    WB --> API
    Q & AM -.-> PROM
```

Everything is assembled in one place, [`sentinel/runtime.py`](src/sentinel/runtime.py),
from validated `SENTINEL_*` settings. The design rationale is in
[ADR 0001](docs/adr/0001-architecture-overview.md); the runtime and performance
decisions in [ADR 0003](docs/adr/0003-runtime-and-performance.md).

## Engineering highlights

**Exactly-once delivery under concurrent producers.** Every event carries a
deterministic SHA-256 `event.id` derived from its content, and a single consumer
owns a TTL- and size-bounded dedup window — so a log re-read after rotation or a
double poll cannot produce a duplicate alert. A keystone test races eight
producers through shared duplicates and asserts each id reaches the consumer once
([`test_pipeline_keystone.py`](tests/test_pipeline_keystone.py)).

**Rules are data, never code.** Rules are strict YAML parsed with `safe_load`
into a closed grammar of comparison operators; the evaluator is an allow-listed
interpreter with no `eval`. Rule regexes run on the `regex` engine with a hard
timeout and bounded input (ReDoS). A bad rule fails the whole library at load.
Every rule has a positive and a negative test, plus structural tests — e.g. no
process rule may fire twice for one process ([`test_detection_rules.py`](tests/test_detection_rules.py)).

**A rule index proven sound with property-based testing.** The engine derives,
by static analysis of each rule's condition tree, which `event.action` values it
could ever match, and evaluates only those rules. A Hypothesis property test over
random `all`/`any`/`not` trees checks the derivation never excludes a matching
rule — a deliberately unsound version is caught with a minimal counter-example
([`test_detection_index.py`](tests/test_detection_index.py)).

**File integrity monitoring that does not re-hash the world — and cannot be
fooled by `touch`.** Unchanged files reuse their digest when `(size, mtime,
ctime, inode, device)` is identical. `mtime` alone would be an evasion hole, but
`ctime` cannot be set from userspace; entries changed within the kernel clock's
granularity are re-hashed, as in Git's "racy clean" handling. Tests cover the
same-length-edit-then-restore-mtime attack ([`integrity.py`](src/sentinel/collectors/integrity.py)).

**Containers that see the host, not themselves.** Following the Falco/osquery
`HOST_ROOT` convention, collectors read the host under `/host` but report
host-native paths and the host's name; the network collector reads
`/proc/1/net` because `/proc/net` resolves to the *reader's* network namespace.
Verified end to end: a cron drop, a `useradd` command line and a listener on
`:4444` on the host are detected from inside the read-only container.

**Security of the detector itself.**
- Default-deny bearer auth on every data endpoint, constant-time comparison, and
  a regression test that a failed login never logs the presented or configured
  key ([`security.py`](src/sentinel/api/security.py)).
- Log-injection defence (control characters stripped) and secret redaction in
  the logging pipeline, configured before anything else can log.
- Webhook sink: HTTPS only, HMAC-SHA256 signed, SSRF guard re-checked on every
  send (blocks loopback, private, link-local and metadata addresses).
- Half-configured alert channels fail closed at startup rather than silently
  not alerting; unknown `SENTINEL_*` variables are a startup error.
- Container: non-root, read-only root filesystem, no capabilities,
  `no-new-privileges`, code and rules root-owned, secrets mandatory, ports bound
  to loopback. Threat model: [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md).

## Performance

Measured with [`scripts/benchmark.py`](scripts/benchmark.py) (median of repeated
runs) on a 4-vCPU Xeon @ 2.8 GHz VM, Python 3.13 — re-run it on your hardware.
"Before" is commit `24bb9e7`, where the benchmark was introduced.

| Hot path | Before | After | Change |
| --- | --- | --- | --- |
| End to end: collector → dedup → 17 rules → alerts → SQLite | ~500 events/s | ~10,000 events/s | **~20×** — write-behind batching, bulk insert, SQLite WAL |
| Rule engine | ~18,000 events/s | ~30,000 events/s | ~1.7× — action index, cached field paths |
| FIM poll, 2,000 unchanged files (31 MiB) | ~210 ms | ~50 ms | ~4× — stat cache |
| Process poll, per process | ~125 µs | ~60 µs | ~2× — read only `stat` for known processes |
| Dedup pipeline alone (80% duplicates) | ~350,000 events/s | unchanged | already not the bottleneck |

Each optimization landed as its own commit with its measurement, and none
trades away a detection: the stat cache and rule index each have tests that fail
if they hide an event.

## Detection coverage

17 rules covering 15 ATT&CK techniques across credential access, execution,
persistence, privilege escalation, defense evasion and command-and-control —
each also mapped to NIST CSF 2.0 and D3FEND. Full matrix (generated from the
rules, checked in CI): **[docs/COVERAGE.md](docs/COVERAGE.md)**.

A rule is a short YAML file — this is `rules/ssh-brute-force.yml`, verbatim:

```yaml
id: ssh-brute-force
title: SSH brute-force login attempts
description: >-
  Five or more failed SSH authentications from a single source IP within one
  minute — the classic password-guessing signature.
severity: 6
attack: [T1110]
nist_csf: [DE.CM, DE.AE]
d3fend: [D3-UBA]
references:
  - https://attack.mitre.org/techniques/T1110/
throttle: {window_seconds: 300, max_alerts: 1}
condition:
  threshold:
    match: {field: event.action, op: equals, value: ssh_login_failed}
    window_seconds: 60
    count: 5
    group_by: source.ip
```

## Running it for real

### Docker Compose: Sentinel + PostgreSQL + Prometheus + Grafana

```bash
cp deploy/.env.example deploy/.env      # set the three secrets (Compose refuses to start without them)
docker compose -f deploy/docker-compose.yml up -d --build
sudo scripts/demo.sh                    # harmless host activity -> alerts (cleans up after itself)
```

- API on `127.0.0.1:8000`, Grafana on `127.0.0.1:3000` (dashboard provisioned).
- Prometheus scrapes `/metrics` with the same API key — no token file to sync.
- Optional tuning (webhook/email sinks, alert gates, FIM paths): `deploy/sentinel.env`.

### Bare metal

```bash
export SENTINEL_ENV=production SENTINEL_API_KEY="$(openssl rand -base64 32)"
uv run sentinel serve --host 127.0.0.1 --port 8000
```

Every setting is documented in [`.env.example`](.env.example) (kept in sync with
the code by a test).

### API

| Endpoint | Auth | Purpose |
| --- | --- | --- |
| `GET /healthz` | — | liveness |
| `GET /readyz` | — | readiness: database reachable **and** pipeline running |
| `GET /events?limit=&cursor=` | bearer | normalized events, keyset-paginated |
| `GET /alerts?limit=&cursor=` | bearer | persisted alerts with ATT&CK / NIST mappings |
| `GET /rules` | bearer | the loaded rule library |
| `GET /metrics` | bearer | Prometheus exposition |

Metrics include `sentinel_events_ingested_total`, `sentinel_detections_fired_total{rule_id,severity}`,
`sentinel_alerts_emitted_total{sink}`, `sentinel_alerts_suppressed_total{reason}`,
`sentinel_events_dropped_total{reason}`, `sentinel_queue_depth` and
`sentinel_alert_latency_seconds`.

## Quality gates

Every push runs ([`ci.yml`](.github/workflows/ci.yml)), on Python 3.12 and 3.13:

| Gate | Tool |
| --- | --- |
| 580+ tests, branch coverage ≥ 95% enforced (98.8% at time of writing) | pytest, Hypothesis |
| Strict typing | mypy `--strict` + pydantic plugin |
| Lint and format | ruff |
| Security lint, secret scanning | bandit, detect-secrets |
| Known-vulnerable dependencies | pip-audit |
| Image builds, runs hardened, drains on SIGTERM | `scripts/smoke_test_image.sh` |
| Fixable HIGH/CRITICAL image vulnerabilities | Trivy |
| Runtime SBOM | CycloneDX artifact |

Actions are pinned by commit SHA and Dependabot keeps them, the lockfile and the
base image current.

```bash
uv sync
uv run pytest --cov=src/sentinel
uv run mypy && uv run ruff check . && uv run pre-commit run --all-files
```

## Known limitations

Stated plainly, because a detector's blind spots matter as much as its rules:

- **Polling, not kernel events.** Processes and connections that start and end
  within one poll interval (1–2 s) are missed, as is an `exec` that replaces a
  process image in place. An eBPF or netlink proc-connector collector is the fix.
- **Privilege vs. visibility.** Resolving `/proc/<pid>/exe` requires ptrace-read
  access to the target (`proc(5)`), so the non-root container records the
  executable path only for processes it may inspect; command-line rules are
  unaffected. Unreadable files (e.g. `/etc/shadow`) are tracked by metadata,
  including `ctime`, instead of by hash.
- **SQLite trades durability for speed** (`synchronous=NORMAL` in WAL mode): the
  last transactions can roll back on power loss. Use PostgreSQL in production.
- **No retention policy yet** — the events table grows until pruned externally.
- **Auth-log parsing targets OpenSSH syslog lines** (`/var/log/auth.log`,
  `/var/log/secure` via `SENTINEL_AUTH_LOG_PATH`); journald-only hosts are not
  covered.

## Roadmap

eBPF process/network collector · journald source · event retention · Sigma rule
import · per-rule false-positive allow-lists · multi-host aggregation.

## Documentation

- [ADR 0001 — Architecture](docs/adr/0001-architecture-overview.md) ·
  [ADR 0002 — Tooling](docs/adr/0002-tooling-choices.md) ·
  [ADR 0003 — Runtime & performance](docs/adr/0003-runtime-and-performance.md)
- [Threat model (STRIDE)](docs/THREAT_MODEL.md) · [Detection coverage](docs/COVERAGE.md)
- [Contributing](CONTRIBUTING.md) · [Security policy](SECURITY.md)

## License

MIT — see [LICENSE](LICENSE). Copyright © 2026 José Ricardo Solís Arias.
