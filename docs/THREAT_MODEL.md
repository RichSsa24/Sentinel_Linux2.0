# Sentinel-Linux Threat Model

This document outlines the threat model for Sentinel-Linux 2.0, analyzing the data flows using the STRIDE framework and mapping defensive mitigations to the architecture.

## Architecture Data Flow

1. **Collectors** read from host sources (`/var/log/auth.log`, FIM watches, `/proc`, PCAP).
2. **Normalizer** parses the raw logs into strongly typed `Event` objects.
3. **Queue** buffers the normalized events.
4. **Dedup** layer checks for duplicate `event_id` within the sliding time window.
5. **Evaluator** safely assesses rules (from YAML) against events.
6. **Persistence** asynchronously writes events and alerts via parameterized SQL.
7. **API** serves the stored data to clients, protected by Bearer Token Zero Trust.

---

## STRIDE Analysis

| Threat Type | Element | Description | Mitigation |
|---|---|---|---|
| **Spoofing** | Event Sources | An attacker manipulates local logs (e.g., editing `auth.log`) to inject false events or erase tracks. | **Defense in Depth**: We correlate across multiple sources. Our FIM alerts on tampering with `auth.log` itself. Kernel-level sources (e.g., Auditd, PCAP) cannot be trivially spoofed by userland processes. |
| **Spoofing** | API Clients | An attacker attempts to query the API to discover detections or read sensitive events. | **Zero Trust**: The FastAPI enforces strict Bearer token authentication via `Depends(verify_api_key)`. Unauthenticated requests receive generic 401s. |
| **Tampering** | Rules Engine | An attacker alters the YAML rules to remove detection coverage for their payload. | **Immutability**: Rules are loaded at startup. The container runs with a read-only root filesystem (`read_only: true`), making tampering with rules structurally impossible at runtime. |
| **Repudiation** | Persistence | An attacker deletes their history from the database. | **Append-Only Abstraction**: The Sentinel API and Repository do not implement `DELETE` or `UPDATE` endpoints. SQLite/PostgreSQL are isolated in a separate container/volume. |
| **Information Disclosure** | API / DB | SQL injection allows an attacker to dump the entire database or execute arbitrary commands. | **Strict ORM**: We use SQLAlchemy with 100% parameterized queries. Validated by Bandit (`B608`). The database user has restricted grants. |
| **Denial of Service** | Rule Evaluator | An attacker triggers a rule with a complex payload designed to cause Catastrophic Backtracking (ReDoS) in the regex engine, halting the pipeline. | **Engine Hardening**: We replaced the `re` module with `regex` using a hard `timeout` of 0.1s and bounding the input length to 8192 bytes. Evaluator guarantees completion. |
| **Denial of Service** | Pipeline Queue | An attacker generates a massive flood of logs (e.g., brute force) to exhaust memory (OOM). | **Bounded Backpressure**: The queue is strictly bounded (`maxsize`). When full, it blocks or drops (depending on policy), but memory consumption remains capped. |
| **Elevation of Privilege** | Container | An attacker exploits a vulnerability in the Python runtime or Sentinel code to gain root on the host. | **CIS Hardening**: The container runs as the non-root `sentinel` user. Capabilities are dropped (`cap_drop: ALL`), and `no-new-privileges` is set. |

---

## Trust Boundaries

1. **Host to Collector (Untrusted Input)**: Files and OS calls are treated as hostile. Normalizer drops malformed data safely.
2. **Config to Engine (Untrusted Configuration)**: The rule YAMLs are evaluated safely without `eval()` or `exec()`.
3. **Network to API (Untrusted Clients)**: CORS is restricted. Rate limiting is enforced via `slowapi` to prevent brute force on the authentication layer.

## Residual Risks

- **Host Compromise**: If the underlying host kernel is compromised (e.g., malicious LKM intercepting syscalls), Sentinel's collectors may be fed false telemetry before it even reaches the file system. Detection must rely on secondary signals (e.g., network anomalies).
- **Docker Mount Permissions**: If Sentinel runs in a container, it relies on the Docker daemon securely mapping `/var/log` and `/proc` read-only. Misconfiguration of the runtime could limit visibility.
