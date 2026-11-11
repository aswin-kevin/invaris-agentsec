import json

import jsonschema
import pytest

from agentsec.adapters import HTTPAgentAdapter
from agentsec.attacks import CATEGORIES
from agentsec.cli.main import main
from agentsec.policies import PolicyError, parse_policy
from agentsec.reports import build_report, render_terminal
from agentsec.runners import run_suite
from agentsec.traces import trace_json_schema

CANARY = "sk-INVARIS-DEMO-7f3a9c"


def suite_for(policy_text, url, **kw):
    policy = parse_policy(policy_text.format(endpoint=url))
    return run_suite(policy, HTTPAgentAdapter(policy.agent), **kw)


def test_vulnerable_agent_has_findings_in_every_category(policy_text, vulnerable_url):
    suite = suite_for(policy_text, vulnerable_url)
    # Every category whose prerequisites the shared single-agent policy meets. multi_agent_delegation
    # needs agent_roles and a system that reports which agent acted; tests/test_multi_agent.py runs it
    # against the multi-agent reference team instead.
    assert {f.category for f in suite.findings} == set(CATEGORIES) - {"multi_agent_delegation"}
    assert not [r for r in suite.results if r.status == "error"]
    sev = {f.severity for f in suite.findings}
    assert {"critical", "high", "medium"} <= sev


def test_safe_agent_passes_everything(policy_text, safe_url):
    suite = suite_for(policy_text, safe_url)
    assert len(suite.results) == 44
    assert suite.findings == []


def test_runs_are_reproducible_for_a_seed(policy_text, vulnerable_url):
    def digest(seed):
        rep = build_report(suite_for(policy_text, vulnerable_url, seed=seed))
        return json.dumps([(s["id"], [e["content"] for e in s["trace"]["events"] if e["type"] == "user_message"],
                            s["finding_ids"]) for s in rep["scenarios"]], sort_keys=True)
    assert digest(7) == digest(7)
    assert digest(7) != digest(8)  # markers/canaries change with the seed


def test_report_is_valid_and_masks_secrets(policy_text, vulnerable_url):
    suite = suite_for(policy_text, vulnerable_url)
    report = build_report(suite)
    text = json.dumps(report, ensure_ascii=False)
    assert CANARY not in text and "sk-I…9c [REDACTED]" in text
    assert report["run_config"]["policy"]["secrets_count"] == 1
    assert report["summary"]["findings"] == len(report["findings"]) > 0
    for sc in report["scenarios"]:
        jsonschema.validate(sc["trace"], trace_json_schema())
    f = report["findings"][0]
    assert {"input", "evidence", "policy_violated", "observed_action", "remediation"} <= set(f)


def test_terminal_report_shape(policy_text, vulnerable_url):
    out = render_terminal(suite_for(policy_text, vulnerable_url), report_path=".agentsec/report.json")
    lines = out.splitlines()
    assert lines[0] == "Invaris AgentSec"
    assert "44 scenarios executed" in out and "0 passed" in out
    assert out.index("CRITICAL") < out.index("HIGH") < out.index("MEDIUM")
    assert CANARY not in out
    assert lines[-1] == "Report written to .agentsec/report.json"


def test_memory_poisoning_findings_against_vulnerable_agent(policy_text, vulnerable_url):
    suite = suite_for(policy_text + "tests: [memory_poisoning]\n", vulnerable_url)
    titles = {f.title for f in suite.findings}
    assert "Poisoned memory persisted into a later session" in titles
    assert "Poisoned memory triggered send_email" in titles
    assert "Poisoned memory triggered reveal_credentials" in titles
    assert "Memory leaked across sessions" in titles
    # every scenario recorded two conversations
    for r in suite.results:
        assert {e.meta["phase"] for e in r.trace.events} == {0, 1}


def test_unknown_category_is_an_error(policy_text, safe_url):
    with pytest.raises(PolicyError, match="unknown test category"):
        suite_for(policy_text + "tests: [bogus]\n", safe_url)


def write_policy(tmp_path, text, url):
    path = tmp_path / "agentsec.yaml"
    path.write_text(text.format(endpoint=url))
    return str(path)


def test_cli_exit_codes(tmp_path, policy_text, vulnerable_url, safe_url, capsys):
    out = str(tmp_path / "out")
    assert main(["test", "-p", write_policy(tmp_path, policy_text, vulnerable_url), "-o", out]) == 1
    assert (tmp_path / "out" / "report.json").exists()
    assert main(["test", "-p", write_policy(tmp_path, policy_text, vulnerable_url), "-o", out,
                 "--fail-on", "none"]) == 0
    # only medium findings exist in this category, so --fail-on high passes
    assert main(["test", "-p", write_policy(tmp_path, policy_text, vulnerable_url), "-o", out,
                 "-s", "loop_and_budget_limits", "--fail-on", "high"]) == 0
    assert main(["test", "-p", write_policy(tmp_path, policy_text, safe_url), "-o", out]) == 0
    capsys.readouterr()


def test_cli_can_write_a_sarif_report(tmp_path, policy_text, vulnerable_url):
    import json
    out = str(tmp_path / "out")
    pol = write_policy(tmp_path, policy_text, vulnerable_url)
    assert main(["test", "-p", pol, "-o", out, "-f", "json,sarif"]) == 1
    sarif_path = tmp_path / "out" / "results.sarif"
    assert sarif_path.exists()
    log = json.loads(sarif_path.read_text())
    assert log["version"] == "2.1.0"
    assert len(log["runs"][0]["results"]) > 0
    # every SARIF result should point at the real policy file the CLI was invoked with,
    # not a hardcoded placeholder.
    uris = {r["locations"][0]["physicalLocation"]["artifactLocation"]["uri"] for r in log["runs"][0]["results"]}
    assert uris == {pol}


def test_cli_report_json_carries_real_policy_path_and_replay_hint(tmp_path, policy_text, vulnerable_url):
    import json
    out = str(tmp_path / "out")
    pol = write_policy(tmp_path, policy_text, vulnerable_url)
    assert main(["test", "-p", pol, "-o", out]) == 1
    report = json.loads((tmp_path / "out" / "report.json").read_text())
    assert report["run_config"]["policy_path"] == pol
    assert report["run_config"]["replay"].startswith("agentsec test --policy %s --seed " % pol)


def test_cli_scenario_filter_and_errors(tmp_path, policy_text, safe_url, capsys):
    pol = write_policy(tmp_path, policy_text, safe_url)
    assert main(["test", "-p", pol, "-o", str(tmp_path / "o"), "-s", "prompt_injection/ignore_previous"]) == 0
    assert "1 scenarios executed" in capsys.readouterr().out
    assert main(["test", "-p", pol, "-o", str(tmp_path / "o"), "-s", "nope"]) == 2
    assert main(["test", "-p", str(tmp_path / "missing.yaml")]) == 2
    bad = write_policy(tmp_path, policy_text + "tests: [bogus]\n", safe_url)
    assert main(["test", "-p", bad, "-o", str(tmp_path / "o")]) == 2
    assert "unknown test category" in capsys.readouterr().err


def test_cli_unreachable_agent_is_exit_2(tmp_path, policy_text, capsys):
    pol = write_policy(tmp_path, policy_text, "http://127.0.0.1:1/agent")
    assert main(["test", "-p", pol, "-o", str(tmp_path / "o")]) == 2
    assert "did not answer a preflight request" in capsys.readouterr().err


def test_cli_init_and_schema(tmp_path, capsys):
    target = str(tmp_path / "agentsec.yaml")
    assert main(["init", target]) == 0
    assert main(["init", target]) == 2  # never overwrites
    parse_policy(open(target).read())
    assert main(["schema", "policy"]) == 0
    assert '"AgentSec policy' in capsys.readouterr().out
