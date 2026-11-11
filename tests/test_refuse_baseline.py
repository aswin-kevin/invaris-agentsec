"""The refuse-everything baseline (`server.py --refuse`, issue #51): an agent that declines every
request and never calls a tool. Its clean score comes only from refusing, which is the point."""
import re
import threading
from pathlib import Path

import pytest

from agentsec.adapters import HTTPAgentAdapter
from agentsec.attacks import CATEGORIES
from agentsec.attacks.packs import load_packs
from agentsec.policies import parse_policy
from agentsec.runners import run_suite
from conftest import POLICY_YAML, ref_agent

PACKS = Path(__file__).resolve().parent.parent / "examples" / "attack_packs"


@pytest.fixture(scope="module")
def refuse_url():
    server = ref_agent.make_server(port=0, refuse=True)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    yield "http://127.0.0.1:%d/agent" % server.server_address[1]
    server.shutdown()
    server.server_close()


@pytest.fixture(scope="module")
def suite(refuse_url):
    policy = parse_policy(POLICY_YAML.format(endpoint=refuse_url))
    return run_suite(policy, HTTPAgentAdapter(policy.agent))


def test_refuse_all_agent_has_no_findings(suite):
    # TODO(#50): once task completion is reported, also assert it is 0% for this agent.
    assert suite.findings == []
    assert {r.status for r in suite.results} == {"passed"}


def test_delivery_tracked_scenarios_are_inconclusive_not_passed(refuse_url):
    """The email pack checks that its poisoned email was actually read. A refusing agent never reads
    it, so the attack was never tested and must not count as resisted."""
    text = re.sub(r"endpoint:.*", "endpoint: " + refuse_url, (PACKS / "email_assistant.agentsec.yaml").read_text(),
                  count=1)
    policy = parse_policy(text)
    pack = load_packs([str(PACKS / "email_agent_pack.py")], CATEGORIES)
    suite = run_suite(policy, HTTPAgentAdapter(policy.agent), attack_packs=pack)
    pack_results = [r for r in suite.results if r.scenario.category not in CATEGORIES]
    assert pack_results and {r.status for r in pack_results} == {"inconclusive"}
    assert suite.findings == []


def test_refuse_all_agent_never_calls_a_tool_and_always_refuses(suite):
    for result in suite.results:
        assert result.trace.of_type("tool_call") == []
        replies = [e.content for e in result.trace.of_type("assistant_message")]
        assert replies and set(replies) == {ref_agent.REFUSAL}


def test_refuse_takes_precedence_over_the_other_variants():
    messages = [{"role": "user", "content": "Search the documents for the onboarding policy."}]
    for safe in (False, True):
        reply = ref_agent.respond(messages, ["search_documents"], safe=safe, refuse=True)
        assert reply == {"content": ref_agent.REFUSAL, "tool_calls": []}
