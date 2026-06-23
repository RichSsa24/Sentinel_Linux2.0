"""Tests for the fail-closed rule loader.

Rule files are untrusted config, so the loader must reject anything malformed
and must never let a rule file construct Python objects (``safe_load`` only).
"""

from __future__ import annotations

from pathlib import Path

import pytest

from sentinel.detection.loader import RuleLoadError, load_rules

_VALID = """\
id: example-rule
title: Example
description: A valid rule.
severity: 5
attack: [T1059]
nist_csf: [DE.CM]
condition: {field: process.command_line, op: contains, value: nc}
"""


def _write(directory: Path, name: str, content: str) -> None:
    (directory / name).write_text(content, encoding="utf-8")


class TestLoadHappyPath:
    def test_loads_a_valid_rule(self, tmp_path: Path) -> None:
        _write(tmp_path, "example.yml", _VALID)
        rules = load_rules(tmp_path)
        assert [r.id for r in rules] == ["example-rule"]

    def test_empty_directory_returns_empty(self, tmp_path: Path) -> None:
        assert load_rules(tmp_path) == []

    def test_reads_both_yml_and_yaml(self, tmp_path: Path) -> None:
        _write(tmp_path, "a.yml", _VALID)
        _write(tmp_path, "b.yaml", _VALID.replace("example-rule", "second-rule"))
        assert len(load_rules(tmp_path)) == 2

    def test_loads_nested_boolean_and_threshold_conditions(self, tmp_path: Path) -> None:
        # Exercises every branch of the condition tree walk + regex validation.
        content = (
            "id: combo-rule\ntitle: Combo\ndescription: d\nseverity: 4\n"
            "attack: [T1059]\nnist_csf: [DE.CM]\n"
            "condition:\n"
            "  all:\n"
            "    - {not: {field: process.command_line, op: regex, value: 'a.*b'}}\n"
            "    - threshold:\n"
            "        match: {field: event.action, op: equals, value: process_started}\n"
            "        window_seconds: 60\n"
            "        count: 3\n"
            "        group_by: host.name\n"
        )
        _write(tmp_path, "combo.yml", content)
        assert [r.id for r in load_rules(tmp_path)] == ["combo-rule"]


class TestFailClosed:
    def test_non_mapping_document_is_rejected(self, tmp_path: Path) -> None:
        _write(tmp_path, "bad.yml", "- just\n- a list\n")
        with pytest.raises(RuleLoadError, match="must contain a YAML mapping"):
            load_rules(tmp_path)

    def test_malformed_yaml_is_rejected(self, tmp_path: Path) -> None:
        _write(tmp_path, "bad.yml", "id: [unclosed\n")
        with pytest.raises(RuleLoadError, match="cannot read"):
            load_rules(tmp_path)

    def test_schema_violation_is_rejected(self, tmp_path: Path) -> None:
        _write(tmp_path, "bad.yml", "id: x\ntitle: t\n")  # missing required fields
        with pytest.raises(RuleLoadError, match="invalid rule"):
            load_rules(tmp_path)

    def test_duplicate_id_is_rejected(self, tmp_path: Path) -> None:
        _write(tmp_path, "a.yml", _VALID)
        _write(tmp_path, "b.yml", _VALID)  # same id
        with pytest.raises(RuleLoadError, match="duplicate rule id"):
            load_rules(tmp_path)

    def test_invalid_regex_is_rejected_at_load(self, tmp_path: Path) -> None:
        bad = _VALID.replace(
            "{field: process.command_line, op: contains, value: nc}",
            "{field: process.command_line, op: regex, value: '('}",
        )
        _write(tmp_path, "bad.yml", bad)
        with pytest.raises(RuleLoadError, match="invalid regex"):
            load_rules(tmp_path)

    def test_malformed_attack_id_is_rejected(self, tmp_path: Path) -> None:
        _write(tmp_path, "bad.yml", _VALID.replace("[T1059]", "[NOT-A-TECHNIQUE]"))
        with pytest.raises(RuleLoadError, match="invalid rule"):
            load_rules(tmp_path)


class TestUntrustedConfig:
    @pytest.mark.security
    def test_python_object_tag_is_refused(self, tmp_path: Path) -> None:
        # safe_load must refuse to construct arbitrary Python — a rule file can
        # never reach code execution through a YAML tag.
        payload = (
            "id: evil\ntitle: t\ndescription: d\nseverity: 1\n"
            "attack: [T1059]\nnist_csf: [DE.CM]\n"
            'condition: !!python/object/apply:os.system ["echo pwned"]\n'
        )
        _write(tmp_path, "evil.yml", payload)
        with pytest.raises(RuleLoadError):
            load_rules(tmp_path)
