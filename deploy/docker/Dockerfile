# syntax=docker/dockerfile:1.7
# Sentinel-Linux 2.0 — production image (CIS Docker Benchmark aligned).
#
# - Multi-stage: the toolchain (uv) never reaches the runtime image.
# - Base and tool images pinned by version tag (Dependabot keeps them current).
# - The project is installed into the venv as a regular, non-editable package,
#   so the runtime image needs no source tree and no PYTHONPATH.
# - Non-root user, no shell login, read-only-root-filesystem friendly.
# - The server is PID 1 (`exec`), so `docker stop`'s SIGTERM reaches uvicorn and
#   the pipeline drains its queue and flushes buffered events before exit.

ARG PYTHON_IMAGE=python:3.12-slim-bookworm
ARG UV_IMAGE=ghcr.io/astral-sh/uv:0.11.32

FROM ${UV_IMAGE} AS uv

FROM ${PYTHON_IMAGE} AS builder

COPY --from=uv /uv /bin/uv

ENV UV_COMPILE_BYTECODE=1 \
    UV_LINK_MODE=copy \
    UV_PYTHON_DOWNLOADS=never

WORKDIR /build

# Dependencies first, so source edits do not invalidate this layer.
COPY pyproject.toml uv.lock ./
RUN uv sync --frozen --no-dev --no-install-project --no-editable

COPY README.md LICENSE ./
COPY src/ src/
RUN uv sync --frozen --no-dev --no-editable

# ---------------------------------------------------------------------------

FROM ${PYTHON_IMAGE}

LABEL org.opencontainers.image.title="Sentinel-Linux" \
      org.opencontainers.image.description="Host-based intrusion detection for Linux: collectors, ATT&CK-mapped YAML rules, hardened alerting and API." \
      org.opencontainers.image.source="https://github.com/RichSsa24/Sentinel_Linux2.0" \
      org.opencontainers.image.licenses="MIT"

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PATH="/app/.venv/bin:$PATH" \
    SENTINEL_ENV=production \
    SENTINEL_LOG_FORMAT=json

RUN groupadd --system sentinel \
 && useradd --system --gid sentinel --no-create-home --shell /usr/sbin/nologin sentinel

WORKDIR /app

COPY --from=builder --chown=root:root /build/.venv /app/.venv
COPY --chown=root:root alembic.ini ./
COPY --chown=root:root migrations/ migrations/
COPY --chown=root:root rules/ rules/

# Code and rules are root-owned and read-only to the service account: a
# compromised process cannot rewrite its own detections.
USER sentinel:sentinel

EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
    CMD ["python", "-c", "import sys, urllib.request; sys.exit(urllib.request.urlopen('http://127.0.0.1:8000/readyz', timeout=4).status != 200)"]

# Apply migrations, then *replace* the shell with the server (PID 1).
CMD ["sh", "-c", "python -m alembic upgrade head && exec python -m sentinel serve --host 0.0.0.0 --port 8000"]
