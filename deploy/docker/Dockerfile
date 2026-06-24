# syntax=docker/dockerfile:1.4
# CIS Docker Benchmark Aligned
# - Pinned base image by digest
# - Non-root user
# - Healthcheck implemented
# - Designed for read-only root filesystem (no writes to /)

# Builder stage
FROM python:3.12-slim-bookworm@sha256:0d5886ac89de57f35496a8ebba075dcb0e7646cd68407cf1c3ab3ebc0a66d1f0 AS builder

# Install uv for deterministic dependency resolution
COPY --from=ghcr.io/astral-sh/uv:0.2.14@sha256:1a129035bfd908ec2d82de292daab56b7cbfce165561a03f3fb6222bde958bf6 /uv /bin/uv

ENV UV_COMPILE_BYTECODE=1
ENV UV_LINK_MODE=copy

WORKDIR /build

# Install dependencies first (for caching)
COPY pyproject.toml uv.lock ./
RUN uv sync --frozen --no-install-project --no-dev

# Copy source and build
COPY src/ src/
COPY alembic.ini alembic.ini
COPY migrations/ migrations/
COPY README.md README.md
RUN uv sync --frozen --no-dev

# Final execution stage
FROM python:3.12-slim-bookworm@sha256:0d5886ac89de57f35496a8ebba075dcb0e7646cd68407cf1c3ab3ebc0a66d1f0

ENV PYTHONUNBUFFERED=1
ENV PATH="/app/.venv/bin:$PATH"
ENV SENTINEL_ENV="production"

# Create a non-root user and group
RUN groupadd -r sentinel && useradd -r -g sentinel -s /sbin/nologin sentinel

WORKDIR /app

# Copy the built virtual environment and application code from the builder
COPY --from=builder --chown=sentinel:sentinel /build/.venv /app/.venv
COPY --from=builder --chown=sentinel:sentinel /build/src /app/src
COPY --from=builder --chown=sentinel:sentinel /build/alembic.ini /app/alembic.ini
COPY --from=builder --chown=sentinel:sentinel /build/migrations /app/migrations
COPY --chown=sentinel:sentinel rules/ /app/rules/

# Drop privileges
USER sentinel:sentinel

EXPOSE 8000

# Healthcheck invoking the API's readyz endpoint
HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
    CMD python -c "import urllib.request, sys; sys.exit(0 if urllib.request.urlopen('http://localhost:8000/readyz').getcode() == 200 else 1)"

# Use uvicorn as the main entrypoint
CMD ["python", "-m", "uvicorn", "sentinel.api.app:app", "--host", "0.0.0.0", "--port", "8000", "--log-level", "info"]
