"""Tests for SARIF parsing."""

import json
import tempfile
from pathlib import Path

from miner.sarif import parse_sarif


def _write_sarif(tmp: Path, data: dict) -> Path:
    path = tmp / "test.sarif"
    path.write_text(json.dumps(data), encoding="utf-8")
    return path


def test_parse_empty_sarif():
    with tempfile.TemporaryDirectory() as tmp:
        path = _write_sarif(Path(tmp), {"version": "2.1.0", "runs": []})
        findings = parse_sarif(path)
        assert findings == []


def test_parse_sarif_with_finding():
    sarif = {
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "CodeQL",
                        "rules": [
                            {
                                "id": "py/sql-injection",
                                "properties": {"tags": ["security-severity:8.5"]},
                            }
                        ],
                    }
                },
                "results": [
                    {
                        "ruleId": "py/sql-injection",
                        "level": "warning",
                        "message": {"text": "SQL injection vulnerability"},
                        "locations": [
                            {
                                "physicalLocation": {
                                    "artifactLocation": {"uri": "src/db.py"},
                                    "region": {
                                        "startLine": 42,
                                        "endLine": 42,
                                        "snippet": {"text": "cursor.execute(query)"},
                                    },
                                }
                            }
                        ],
                    }
                ],
            }
        ],
    }
    with tempfile.TemporaryDirectory() as tmp:
        path = _write_sarif(Path(tmp), sarif)
        findings = parse_sarif(path)
        assert len(findings) == 1
        f = findings[0]
        assert f.rule_id == "py/sql-injection"
        assert f.severity == "warning"
        assert f.message == "SQL injection vulnerability"
        assert f.file == "src/db.py"
        assert f.start_line == 42
        assert f.end_line == 42
        assert f.code_snippet == "cursor.execute(query)"


def test_parse_sarif_multiple_locations():
    sarif = {
        "version": "2.1.0",
        "runs": [
            {
                "tool": {"driver": {"name": "CodeQL", "rules": []}},
                "results": [
                    {
                        "ruleId": "py/xss",
                        "level": "error",
                        "message": {"text": "XSS found"},
                        "locations": [
                            {
                                "physicalLocation": {
                                    "artifactLocation": {"uri": "src/web.py"},
                                    "region": {"startLine": 10},
                                }
                            },
                            {
                                "physicalLocation": {
                                    "artifactLocation": {"uri": "src/templates.py"},
                                    "region": {"startLine": 25},
                                }
                            },
                        ],
                    }
                ],
            }
        ],
    }
    with tempfile.TemporaryDirectory() as tmp:
        path = _write_sarif(Path(tmp), sarif)
        findings = parse_sarif(path)
        assert len(findings) == 2
        assert findings[0].file == "src/web.py"
        assert findings[1].file == "src/templates.py"


def test_parse_sarif_severity_from_tags():
    sarif = {
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "CodeQL",
                        "rules": [
                            {
                                "id": "js/audit",
                                "properties": {"tags": ["security-severity:3.0"]},
                            }
                        ],
                    }
                },
                "results": [
                    {
                        "ruleId": "js/audit",
                        "message": {"text": "Low severity issue"},
                        "locations": [
                            {
                                "physicalLocation": {
                                    "artifactLocation": {"uri": "src/utils.js"},
                                    "region": {"startLine": 5},
                                }
                            }
                        ],
                    }
                ],
            }
        ],
    }
    with tempfile.TemporaryDirectory() as tmp:
        path = _write_sarif(Path(tmp), sarif)
        findings = parse_sarif(path)
        assert len(findings) == 1
        assert findings[0].severity == "none"


def test_parse_sarif_high_severity_from_tags():
    sarif = {
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "CodeQL",
                        "rules": [
                            {
                                "id": "py/injection",
                                "properties": {"tags": ["security-severity:9.5"]},
                            }
                        ],
                    }
                },
                "results": [
                    {
                        "ruleId": "py/injection",
                        "message": {"text": "Critical injection"},
                        "locations": [
                            {
                                "physicalLocation": {
                                    "artifactLocation": {"uri": "app.py"},
                                    "region": {"startLine": 1},
                                }
                            }
                        ],
                    }
                ],
            }
        ],
    }
    with tempfile.TemporaryDirectory() as tmp:
        path = _write_sarif(Path(tmp), sarif)
        findings = parse_sarif(path)
        assert findings[0].severity == "error"
