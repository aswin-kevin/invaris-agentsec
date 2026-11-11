"""SARIF 2.1.0 output, for GitHub Code Scanning and other SARIF-consuming tools.

SARIF (Static Analysis Results Interchange Format) is a JSON format most CI
security dashboards understand natively. Producing it lets an `agentsec test`
run be uploaded straight to GitHub's "Security" tab with
`github/codeql-action/upload-sarif`, alongside (not instead of) the richer
`report.json` / `report.html` AgentSec formats.

Only deterministic rule *shape* is static here (id, name, description,
severity -> level); each finding becomes one `result` with a `message` built
from its scenario/observed-action/remediation fields, matching what the
terminal and markdown reports already show for the same finding.
"""
from __future__ import annotations

import json
from typing import Any, Dict, List

from .. import __version__

SARIF_VERSION = "2.1.0"
SARIF_SCHEMA = "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json"

# SARIF has no "critical"; fold it into "error" alongside "high" and carry the
# original AgentSec severity in properties so nothing is lost.
_LEVEL = {"critical": "error", "high": "error", "medium": "warning", "low": "note"}


def _rule(rule_id: str, findings: List[Dict[str, Any]]) -> Dict[str, Any]:
    f = findings[0]
    owasp_ids = sorted({o["id"] for finding in findings for o in finding["owasp"]})
    return {
        "id": rule_id,
        "name": rule_id,
        "shortDescription": {"text": f["title"]},
        "fullDescription": {"text": f["policy_violated"]},
        "help": {"text": f["remediation"]},
        "defaultConfiguration": {"level": _LEVEL[f["severity"]]},
        "properties": {"tags": ["security", "agentsec"] + owasp_ids, "owasp": owasp_ids},
    }


def _message(finding: Dict[str, Any]) -> str:
    title = finding["title"] + (" (irreversible)" if finding.get("irreversible") else "")
    parts = [title, "", "Scenario: %s" % finding["scenario_id"],
              "Observed: %s" % finding["observed_action"]]
    if finding["remediation"]:
        parts.append("Remediation: %s" % finding["remediation"])
    return "\n".join(parts)


def _result(finding: Dict[str, Any], run_config: Dict[str, Any]) -> Dict[str, Any]:
    policy_path = run_config.get("policy_path") or "agentsec.yaml"
    properties = {
        "severity": finding["severity"],
        "category": finding["category"],
        "scenarioId": finding["scenario_id"],
        "source": finding.get("source", "deterministic"),
    }
    if finding.get("irreversible"):
        properties["irreversible"] = True
        properties["tags"] = ["irreversible"]
    return {
        "ruleId": finding["rule"],
        "level": _LEVEL[finding["severity"]],
        "message": {"text": _message(finding)},
        "locations": [{
            "physicalLocation": {
                "artifactLocation": {"uri": policy_path},
            },
        }],
        "partialFingerprints": {"agentsecFindingId": finding["id"]},
        "properties": properties,
    }


def build_sarif(report: Dict[str, Any]) -> Dict[str, Any]:
    """Build a SARIF 2.1.0 log dict from an AgentSec report dict (see json_report.build_report)."""
    findings = report["findings"]
    by_rule: Dict[str, List[Dict[str, Any]]] = {}
    for f in findings:
        by_rule.setdefault(f["rule"], []).append(f)
    rules = [_rule(rule_id, fs) for rule_id, fs in sorted(by_rule.items())]
    run_config = report.get("run_config", {})
    return {
        "$schema": SARIF_SCHEMA,
        "version": SARIF_VERSION,
        "runs": [{
            "tool": {
                "driver": {
                    "name": "invaris-agentsec",
                    "informationUri": "https://github.com/invarislabs/invaris-agentsec",
                    "version": report.get("tool", {}).get("version", __version__),
                    "rules": rules,
                }
            },
            "results": [_result(f, run_config) for f in findings],
        }],
    }


def render_sarif(report: Dict[str, Any]) -> str:
    return json.dumps(build_sarif(report), indent=2, ensure_ascii=False) + "\n"
