import json

import pytest

from trivyignore_cli.models import normalize_severities
from trivyignore_cli.runner import ToolError, parse_report


def report(**results) -> str:
    return json.dumps(results)


def test_parses_vulnerabilities():
    payload = report(
        Results=[
            {
                "Vulnerabilities": [
                    {"VulnerabilityID": "CVE-1", "Severity": "HIGH", "PkgName": "zlib"},
                    {"VulnerabilityID": "CVE-2", "Severity": "CRITICAL"},
                ]
            }
        ]
    )
    findings = parse_report(payload)
    assert [f.id for f in findings] == ["CVE-1", "CVE-2"]
    assert findings[0].pkg_name == "zlib"


def test_deduplicates_across_results():
    payload = report(
        Results=[
            {"Vulnerabilities": [{"VulnerabilityID": "CVE-1", "Severity": "HIGH"}]},
            {"Vulnerabilities": [{"VulnerabilityID": "CVE-1", "Severity": "HIGH"}]},
        ]
    )
    assert len(parse_report(payload)) == 1


def test_handles_null_and_missing_sections():
    assert parse_report(report(Results=None)) == []
    assert parse_report(report(Results=[{"Vulnerabilities": None}])) == []
    assert parse_report(report()) == []


def test_empty_output_is_empty_list():
    assert parse_report("") == []
    assert parse_report("   ") == []


def test_invalid_json_raises():
    with pytest.raises(ToolError):
        parse_report("not json")


def test_parses_misconfigurations_and_secrets():
    payload = report(
        Results=[
            {
                "Misconfigurations": [{"ID": "AVD-1", "Severity": "HIGH"}],
                "Secrets": [{"RuleID": "aws-key", "Severity": "CRITICAL"}],
            }
        ]
    )
    findings = {f.id: f.section for f in parse_report(payload)}
    assert findings == {"AVD-1": "misconfigurations", "aws-key": "secrets"}


def test_entries_without_id_are_skipped():
    payload = report(Results=[{"Vulnerabilities": [{"Severity": "HIGH"}]}])
    assert parse_report(payload) == []


def test_missing_severity_defaults_to_unknown():
    payload = report(Results=[{"Vulnerabilities": [{"VulnerabilityID": "CVE-1"}]}])
    assert parse_report(payload)[0].severity == "UNKNOWN"


def test_findings_are_sorted():
    payload = report(
        Results=[
            {
                "Vulnerabilities": [
                    {"VulnerabilityID": "CVE-9", "Severity": "HIGH"},
                    {"VulnerabilityID": "CVE-1", "Severity": "HIGH"},
                ]
            }
        ]
    )
    assert [f.id for f in parse_report(payload)] == ["CVE-1", "CVE-9"]


@pytest.mark.parametrize(
    "raw,expected",
    [
        ("HIGH", ["HIGH"]),
        ("high,critical", ["HIGH", "CRITICAL"]),
        ("CRITICAL,HIGH", ["HIGH", "CRITICAL"]),
        ("HIGH, HIGH", ["HIGH"]),
        (["HIGH", "LOW"], ["LOW", "HIGH"]),
        ("ALL", ["UNKNOWN", "LOW", "MEDIUM", "HIGH", "CRITICAL"]),
    ],
)
def test_normalize_severities(raw, expected):
    assert normalize_severities(raw) == expected


@pytest.mark.parametrize("raw", ["", "SEVERE", "high,bogus"])
def test_normalize_severities_rejects_junk(raw):
    with pytest.raises(ValueError):
        normalize_severities(raw)
