# Security Policy

## Supported Versions

Sentinel-Linux 2.0 is currently in pre-release development. Security fixes are
applied only to the latest tag on the `main` branch. Once `v1.0.0` ships, this
table will be updated with a supported-versions window.

| Version  | Supported          |
|----------|--------------------|
| `main`   | :white_check_mark: |
| < 1.0    | preview only       |

## Reporting a Vulnerability

**Do not open a public GitHub issue for security reports.**

Send the report by email to **ricardo02solis@gmail.com** with the subject line
`[SECURITY] Sentinel-Linux 2.0`. Encrypt with the maintainer's PGP key if one
is published in the repository root.

Please include:

1. Affected version / commit SHA.
2. A minimal reproduction (proof-of-concept code, fixture log, or rule file).
3. The observed impact (e.g., privilege escalation, log injection, RCE via
   rule file, SSRF via webhook sink, denial of service).
4. Any suggested remediation.

### What to expect

- **Acknowledgement:** within 72 hours.
- **Initial assessment + severity:** within 7 days (using CVSS v3.1).
- **Fix or mitigation plan:** communicated within 30 days for High/Critical.
- **Public disclosure:** coordinated. We will not publish details until a
  patched release is available, and we will credit reporters who wish to be
  credited.

## Scope

In scope:

- Code in `src/sentinel/` and `rules/`.
- Container images and Compose stack in `deploy/`.
- The detection-rule grammar and the rule loader.
- The collector parsers (treated as adversarial-input surfaces).
- The webhook, email, and console sinks.
- The FastAPI read surface and its authentication/authorization.

Out of scope:

- Vulnerabilities in upstream dependencies — please report those upstream and
  CC us so we can pin/patch.
- Findings that require root on the host running Sentinel; Sentinel runs on a
  host that is, by definition, the trust boundary it monitors.
- Theoretical issues without a working reproduction.

## Hardening Baseline

Sentinel-Linux 2.0 targets the following controls. A finding that bypasses one
of these is in-scope at High severity by default:

- **OWASP ASVS / API Security Top 10** for the FastAPI surface.
- **NIST SP 800-207 (Zero Trust)** for inter-component trust: every API call
  is authenticated; no implicit network trust; fail-closed on policy errors.
- **CIS Docker Benchmark** for container hardening (non-root, read-only root
  filesystem, dropped capabilities, `no-new-privileges`, pinned digests).
- **No code execution from rule files** — rule YAML is parsed with
  `yaml.safe_load` and evaluated against an allowlisted operator grammar.
- **No string-interpolated SQL** — parameterized queries only.
- **Defang and bound everything that gets logged** — log lines are
  control-character-stripped and known-sensitive keys are redacted by the
  logging pipeline before they reach any sink.
