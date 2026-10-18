# Sentinel-Linux Threat Model

This document analyzes Sentinel-Linux 2.0 with STRIDE: what an attacker could do
to the detector itself, and which control (with a pointer to the code) stands in
the way. Residual risks are listed explicitly at the end.

## Data flow

1. **Collectors** read host sources: `/var/log/auth.log` (sshd), `/proc/<pid>`
   (processes), watched paths such as `/etc` (file integrity) and
   `/proc/1/net/tcp[6]` (sockets). In a container they read the host read-only
   under `/host`.
2. **Normalizer** maps each raw record onto a strict, frozen ECS `Event`;
   anything unmappable is dead-lettered and counted.
3. **Bounded queue** buffers events between producers and the single consumer.
4. **Dedup window** drops events whose content-derived `event.id` was already
   seen inside the TTL.
5. **Detection engine** evaluates declarative YAML rules (allow-listed
   operators, no code execution).
6. **Alert manager** applies severity floor, dedup and per-rule throttling, then
   fans out to console, webhook and email sinks.
7. **Persistence** writes events and alerts in batched, parameterized
   transactions (SQLite or PostgreSQL).
8. **API** serves events, alerts, rules and metrics behind bearer
   authentication.

## Trust boundaries

| Boundary | Treated as | Control |
| --- | --- | --- |
| Host → collectors | hostile bytes | length caps, strict parsers that reject rather than coerce, file and executable names that are not valid UTF-8 escaped as `\xNN` (not a crash), dead-lettering (`collectors/`, `normalizer/`) |
| Rule files → engine | untrusted configuration | `yaml.safe_load`, strict schema, closed operator set, regex timeout, fail-closed loader (`detection/`) |
| Network → API | untrusted clients | default-deny bearer auth, rate limit, generic errors, no OpenAPI/docs surface (`api/`) |
| Sentinel → webhook/SMTP | hostile network | verified TLS only (webhook and SMTP), HMAC signing, SSRF guard with the connection pinned to the checked address, per-sink queues and deadlines (`alerting/`) |
| Environment → settings | untrusted configuration | strict validation, unknown `SENTINEL_*` keys rejected, secrets as `SecretStr` (`settings.py`) |

## STRIDE analysis

| Threat | Element | Scenario | Mitigation |
| --- | --- | --- | --- |
| **Spoofing** | API clients | An attacker queries the API to learn what is detected or to read events. | Every data endpoint depends on `require_api_key`: default-deny (no key configured → 503), constant-time comparison on bytes, generic 401. Failed attempts are logged with reason and client address only — never the presented or configured key (regression-tested). |
| **Spoofing** | Event sources | A local attacker writes forged lines into `auth.log`. | Auth events are only one signal; process, file and socket collectors read kernel-maintained state. Log deletion fires `log-tampering`; watching `/var/log` with FIM is supported. Root-level forgery is a residual risk (below). |
| **Tampering** | Rule library | An attacker edits YAML rules to blind detection. | Rules load once at startup through a fail-closed loader. In the container the rules and code are root-owned on a read-only root filesystem, and the service runs as an unprivileged user. |
| **Tampering** | Watched files | An attacker edits `/etc/sudoers` with the same length and restores `mtime` (`touch -d`). | FIM compares SHA-256 digests; its stat cache and its fallback for unreadable files both key on `ctime`, which userspace cannot set, and a metadata change made alongside an edit cannot mask it. Content and permission/ownership changes are reported independently (a rewrite plus `chmod u+s` yields both). Tested explicitly. |
| **Tampering** | Log output | Attacker-controlled bytes (usernames, command lines) inject fake log lines or terminal escapes. | The logging pipeline replaces control characters before rendering (CWE-117) and emits structured JSON in production. |
| **Repudiation** | Persistence | An attacker erases evidence through the application. | The API and repository expose no update or delete operations; rows carry insertion timestamps. Direct database access is out of scope for the application (see residual risks). |
| **Information disclosure** | Logs | Secrets end up in logs or alerts. | Sensitive keys (`password`, `token`, `secret`, `authorization`, …) are redacted recursively by the logging pipeline, which is configured before any other component logs. Sink failures log the exception type only. |
| **Information disclosure** | Database | SQL injection dumps stored telemetry. | All queries are SQLAlchemy expressions with bound parameters; bandit runs in CI. |
| **Information disclosure** | Outbound alerts | A crafted or mistyped webhook URL pivots to cloud metadata or internal services (SSRF). | HTTPS only, no redirects followed, proxy variables ignored. Before every send the host is resolved and every address must be globally routable unicast (loopback, private, link-local, CGNAT, reserved, documentation, multicast and IPv4-mapped forms refused); the request then connects to the address that was checked, with TLS verifying the configured name, so a DNS answer that changes after the check (rebinding) cannot redirect it. |
| **Denial of service** | Rule evaluator | A hostile string triggers catastrophic regex backtracking (ReDoS). | Rule regexes run on the `regex` engine with a 100 ms timeout and an 8 KiB input cap; a timeout degrades to "no match" and is logged. |
| **Denial of service** | Pipeline | An event flood exhausts memory. | Bounded queue with explicit backpressure; dedup window, threshold groups and rate-limit client tables are all size-capped with oldest-first eviction. |
| **Denial of service** | Alert channels | A detection storm floods email/webhook receivers — or decoys exhaust a rule's throttle to hide the real attack. | Alert dedup per rule+event, per-rule throttles (from the rule YAML) and a global throttle. The throttle only withholds *notifications*: throttled alerts are stored (`notified: false`), the first one per window is logged, and the rule's next notification states how many were withheld. |
| **Denial of service** | API | Credential stuffing or scraping. | Per-client sliding-window rate limit (in-process middleware) with a bounded client table. |
| **Elevation of privilege** | Container | A bug in Sentinel or a dependency is exploited for host access. | Non-root user, read-only root filesystem, `cap_drop: ALL`, `no-new-privileges`, host mounted read-only, ports bound to loopback. Dependencies are lock-pinned and audited (pip-audit), the image is scanned (Trivy), and GitHub Actions are pinned by SHA. |
| **Elevation of privilege** | Configuration | A deployment runs with a well-known default credential. | Compose refuses to start without the API key and passwords; there are no default secrets in code. Half-configured alert sinks fail at startup. |

## Residual risks

- **Root on the monitored host.** An attacker with root can stop the collector,
  forge `auth.log`, or (with `CAP_SYS_TIME`) manipulate timestamps. Sentinel
  raises the cost and leaves traces (FIM, log-tampering, process and socket
  events), but a host-based detector cannot defend against its own host's kernel.
- **Polling blind spots.** Processes and connections that live for less than one
  poll interval are not observed, nor is an `exec` by a process that was already
  confirmed (the `fork`→`exec` window right after creation is covered). Kernel
  event sources (eBPF) would close this gap.
- **Reduced visibility when unprivileged.** Without ptrace-read access to a
  process, its executable path cannot be resolved; unreadable files are tracked
  by metadata rather than content. For those files any change that moves
  `ctime` (`chmod`, `chown`, a hard link, ACL, xattr, SELinux label) is also
  reported as a possible modification, so it cannot mask a forged edit:
  fail-safe, at the cost of false positives.
- **Database custody.** Whoever holds the database credentials can delete rows.
  Ship events to an external SIEM (via the webhook sink or log forwarding) when
  tamper-evidence matters.
- **SQLite durability.** WAL with `synchronous=NORMAL` may roll back the last
  transactions on power loss. Use PostgreSQL in production.
