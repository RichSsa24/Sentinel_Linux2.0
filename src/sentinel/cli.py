"""Command-line entry point: ``sentinel serve | rules | demo``.

- ``serve`` runs the API and the detection pipeline, configured entirely from
  ``SENTINEL_*`` environment variables (the container runs the same factory).
- ``rules`` validates the rule library (fail-closed loader) and prints its
  ATT&CK / NIST CSF mapping.
- ``demo`` replays a scripted intrusion through the real pipeline in a couple
  of seconds — no root, no Docker (see :mod:`sentinel.demo`).
"""

from __future__ import annotations

import argparse
import asyncio
import logging
import sys
from collections.abc import Sequence
from pathlib import Path
from typing import TextIO

import structlog
import uvicorn

from sentinel.alerting import severity_label
from sentinel.demo import run_demo, summarize
from sentinel.detection import RuleLoadError, load_rules
from sentinel.logging import build_processors
from sentinel.settings import LogFormat

_DEFAULT_RULES = Path("rules")


def _quiet_logs() -> None:
    """Keep interactive commands readable: only warnings and errors, on stderr.

    Uses the service's processor chain, so control characters are stripped and
    secrets redacted here too.
    """
    structlog.configure(
        processors=build_processors(LogFormat.CONSOLE),
        wrapper_class=structlog.make_filtering_bound_logger(logging.WARNING),
        logger_factory=structlog.PrintLoggerFactory(sys.stderr),
    )


def _cmd_rules(rules_dir: Path, out: TextIO) -> int:
    try:
        rules = sorted(load_rules(rules_dir), key=lambda rule: rule.id)
    except RuleLoadError as exc:
        out.write(f"rule library is invalid: {exc}\n")
        return 1
    width = max(len(rule.id) for rule in rules) if rules else 0
    for rule in rules:
        label = severity_label(rule.severity)
        out.write(f"{rule.id:<{width}}  {label:<8}  {', '.join(rule.attack):<20}  {rule.title}\n")
    out.write(f"\n{len(rules)} rules loaded from {rules_dir} — all valid.\n")
    return 0


def _cmd_demo(rules_dir: Path, out: TextIO) -> int:
    try:
        rules = load_rules(rules_dir)
    except RuleLoadError as exc:
        out.write(f"rule library is invalid: {exc}\n")
        return 1
    out.write(
        "Sentinel-Linux demo: replaying a scripted intrusion through the real pipeline\n"
        "(normalizer -> bounded queue -> dedup -> rules -> alert manager -> SQLite)\n\n"
    )
    result = asyncio.run(run_demo(rules, stream=out))
    out.write(summarize(result) + "\n")
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="sentinel", description="Sentinel-Linux host intrusion detection."
    )
    commands = parser.add_subparsers(dest="command", required=True)

    serve = commands.add_parser("serve", help="run the API and detection pipeline")
    serve.add_argument("--host", default="127.0.0.1", help="bind address (default: 127.0.0.1)")
    serve.add_argument("--port", type=int, default=8000, help="bind port (default: 8000)")

    for name, help_text in (
        ("rules", "validate the rule library and list its ATT&CK mappings"),
        ("demo", "replay a scripted intrusion through the real pipeline"),
    ):
        command = commands.add_parser(name, help=help_text)
        command.add_argument(
            "--rules-dir", type=Path, default=_DEFAULT_RULES, help="default: ./rules"
        )
    return parser


def main(argv: Sequence[str] | None = None, *, out: TextIO | None = None) -> int:
    """Parse `argv` and run the chosen command; returns the process exit code."""
    args = build_parser().parse_args(argv)
    stream = out if out is not None else sys.stdout
    if args.command == "serve":
        uvicorn.run(
            "sentinel.api.app:get_app",
            factory=True,
            host=args.host,
            port=args.port,
            server_header=False,
            # The peer address is the client. Trusting X-Forwarded-For (uvicorn's
            # default for connections from 127.0.0.1) would let any local process
            # choose its rate-limit bucket and forge the address in the logs.
            proxy_headers=False,
            # Leave logging to the app factory: uvicorn's own config would send
            # its access and error logs around the redacting JSON pipeline.
            log_config=None,
            # The app logs every request itself (api.request, with its request
            # id); uvicorn's access log would record each one a second time.
            access_log=False,
        )
        return 0
    _quiet_logs()
    if args.command == "rules":
        return _cmd_rules(args.rules_dir, stream)
    return _cmd_demo(args.rules_dir, stream)


if __name__ == "__main__":  # pragma: no cover - exercised via the console script
    raise SystemExit(main())
