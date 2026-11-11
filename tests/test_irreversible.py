"""The `irreversible` effect tag: it raises severity, is never a scope violation by itself, and is
labelled on the finding in every report format (issue #64)."""
import json

import pytest

from agentsec.attacks.base import VECTOR_DIRECT, Scenario
from agentsec.compare import compare, render, render_markdown
from agentsec.evaluators import evaluate_trace
from agentsec.policies import parse_policy
from agentsec.reports import annotations, build_report, build_sarif, render_html, render_markdown as report_markdown
from agentsec.reports.terminal import render_terminal
from agentsec.runners.local import ScenarioResult, SuiteResult
from agentsec.traces import Trace

POLICY = parse_policy("""
agent: {name: a, endpoint: 'http://x'}
allowed_tools: [lookup_account, draft_email, send_customer_email]
tool_effects:
  lookup_account: [read]
  draft_email: [external_communication]
  send_customer_email: [external_communication, irreversible]
""")


def scenario(**kw):
    base = dict(id="t/1", category="t", title="T", description="", user_message="hi", vector=VECTOR_DIRECT)
    base.update(kw)
    return Scenario(**base)


def trace_calling(tool):
    t = Trace("t/1")
    t.add("user_message", content="hi")
    t.add("tool_call", tool_name=tool, arguments={"to": "customer@example.com"})
    return t


def findings_for(tool, authorized_effects):
    return evaluate_trace(scenario(authorized_effects=authorized_effects), trace_calling(tool), POLICY)


def test_unauthorized_irreversible_call_is_critical_and_labelled():
    [finding] = findings_for("send_customer_email", ["read"])
    assert finding.rule == "unauthorized_side_effect"
    assert finding.severity == "critical"
    assert finding.irreversible
    assert finding.to_dict()["irreversible"] is True


def test_unauthorized_reversible_call_with_the_same_effect_stays_high_and_unlabelled():
    [finding] = findings_for("draft_email", ["read"])
    assert finding.severity == "high"
    assert not finding.irreversible
    assert "irreversible" not in finding.to_dict()


def test_irreversible_is_a_qualifier_not_an_effect_a_task_must_authorize():
    """A task that authorizes sending email has authorized this call; the `irreversible` tag alone
    must not turn it into an out-of-scope finding."""
    assert findings_for("send_customer_email", ["read", "external_communication"]) == []


def test_finding_without_an_irreversible_call_in_its_evidence_is_not_labelled():
    policy = parse_policy("""
agent: {name: a, endpoint: 'http://x'}
allowed_tools: [lookup_account]
forbidden_actions: [send_customer_email]
tool_effects:
  lookup_account: [read, irreversible]
""")
    [finding] = evaluate_trace(scenario(), trace_calling("send_customer_email"), policy)
    assert finding.rule == "forbidden_action"
    assert not finding.irreversible


@pytest.fixture(scope="module")
def suite():
    sc = scenario(authorized_effects=["read"])
    tr = trace_calling("send_customer_email")
    return SuiteResult(POLICY, 0, [ScenarioResult(sc, tr, evaluate_trace(sc, tr, POLICY))], [])


@pytest.fixture(scope="module")
def report(suite):
    return build_report(suite)


def test_label_in_json_report(report):
    assert [f.get("irreversible") for f in report["findings"]] == [True]


def test_label_in_terminal_output(suite):
    assert "[irreversible]" in render_terminal(suite)


def test_label_in_markdown_report(report):
    assert "**(irreversible)**" in report_markdown(report)


def test_label_in_html_report(report):
    assert '<span class="tag irreversible">irreversible</span>' in render_html(report)


def test_label_in_sarif_report(report):
    [result] = build_sarif(report)["runs"][0]["results"]
    assert result["properties"]["irreversible"] is True
    assert result["properties"]["tags"] == ["irreversible"]
    assert "(irreversible)" in result["message"]["text"]


def test_label_in_github_annotations(report):
    assert "[irreversible]" in annotations(report)[0]


def test_label_in_comparison_and_pull_request_comment(report):
    empty = json.loads(json.dumps(report))
    empty["findings"] = []
    comparison = compare(empty, report)
    assert "(irreversible)" in render(comparison)
    assert "(irreversible)" in render_markdown(comparison)


def test_dashboard_renders_the_label():
    from pathlib import Path
    static = Path(__file__).resolve().parent.parent / "agentsec" / "dashboard" / "static"
    assert "f.irreversible ? irreversibleTag()" in (static / "app.js").read_text(encoding="utf-8")
    assert ".tag.irreversible" in (static / "app.css").read_text(encoding="utf-8")
