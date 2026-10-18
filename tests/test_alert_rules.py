"""The shipped Prometheus alert rules match what Sentinel exports and are wired in.

`promtool` validates and unit-tests the rules themselves (CI); this checks the
contract between the rules and the code: a metric that is renamed or removed
must fail here, not leave an alert that silently never fires.
"""

from __future__ import annotations

import re
from pathlib import Path

import yaml
from prometheus_client.parser import text_string_to_metric_families

from sentinel.detection.schema import Rule
from sentinel.metrics import Metrics
from sentinel.runtime import Runtime
from sentinel.storage import Database
from tests.conftest import make_api_settings

_DEPLOY = Path(__file__).resolve().parent.parent / "deploy"
_RULES_FILE = _DEPLOY / "prometheus" / "alerts.yml"
_METRIC = re.compile(r"\b(sentinel_[a-z_]+)")


def _rule_expressions() -> dict[str, str]:
    groups = yaml.safe_load(_RULES_FILE.read_text(encoding="utf-8"))["groups"]
    return {rule["alert"]: rule["expr"] for group in groups for rule in group["rules"]}


async def test_every_metric_an_alert_uses_is_exported(
    database: Database, rules: tuple[Rule, ...]
) -> None:
    metrics = Metrics()
    Runtime(make_api_settings(), database=database, metrics=metrics, rules=rules, sinks=[])
    exported = {family.name for family in text_string_to_metric_families(metrics.render().decode())}
    used = {
        alert: {name.removesuffix("_total") for name in _METRIC.findall(expr)}
        for alert, expr in _rule_expressions().items()
    }
    missing = {alert: names - exported for alert, names in used.items() if names - exported}
    assert missing == {}


def test_prometheus_loads_the_rules() -> None:
    config = yaml.safe_load((_DEPLOY / "prometheus" / "prometheus.yml").read_text("utf-8"))
    assert config["rule_files"] == ["/etc/prometheus/alerts.yml"]
    compose = yaml.safe_load((_DEPLOY / "docker-compose.yml").read_text("utf-8"))
    volumes = compose["services"]["prometheus"]["volumes"]
    assert "./prometheus/alerts.yml:/etc/prometheus/alerts.yml:ro" in volumes
