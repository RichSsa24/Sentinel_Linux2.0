# Sentinel-Linux 2.0

> **Status: pre-release (Phase 0).** This README is a stub. The
> recruiter-grade README ships at Phase 8 with architecture diagrams, the
> "killing the race condition" engineering story, MITRE ATT&CK and NIST
> CSF 2.0 coverage matrices, and a one-command demo.

Sentinel-Linux 2.0 is a host-based security monitoring framework for Linux
that collects telemetry from independent sources, normalizes it into a
common ECS-aligned schema, detects adversary behavior with declarative YAML
rules mapped to **MITRE ATT&CK** and **NIST CSF 2.0**, and alerts through
multiple hardened channels — all behind `docker compose up`.

The rebuild ("2.0") exists to demonstrate engineering judgment: a clean
separation of concerns and a concurrency model that makes the v1
double-collection race condition **structurally impossible**, with a test
that proves it.

## Build status

| Phase | Status                                  |
|------:|-----------------------------------------|
| 0     | foundation & security scaffold — in progress |
| 1     | event schema + pipeline spine — pending |
| 2     | collectors — pending                    |
| 3     | normalizer — pending                    |
| 4     | detection engine + rules — pending      |
| 5     | alerting — pending                      |
| 6     | persistence + hardened API — pending    |
| 7     | dashboard + containerization — pending  |
| 8     | validation campaign + release — pending |

## Quick start (placeholder)

`docker compose up` will be the one-command start once Phase 7 is reached.
For now, the development gates are:

```bash
uv python install 3.12
uv sync --frozen
uv run pytest --cov=src/sentinel
uv run pre-commit run --all-files
```

See `CONTRIBUTING.md` for the full gate list and `SECURITY.md` for the
disclosure policy.

## License

MIT — see [`LICENSE`](./LICENSE).
