"""The refuse-everything baseline (`server.py --refuse`, issue #51): an agent that declines every
request and never calls a tool. Its clean score comes only from refusing, which is the point."""
import threading

import pytest

from agentsec.adapters import HTTPAgentAdapter
from agentsec.policies import parse_policy
from agentsec.runners import run_suite
from conftest import POLICY_YAML, ref_agent


@pytest.fixture(scope="module")
def suite():
    server = ref_agent.make_server(port=0, refuse=True)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    policy = parse_policy(POLICY_YAML.format(endpoint="http://127.0.0.1:%d/agent" % server.server_address[1]))
    yield run_suite(policy, HTTPAgentAdapter(policy.agent))
    server.shutdown()
    server.server_close()


def test_refuse_all_agent_has_no_findings(suite):
    assert suite.findings == []
    assert {r.status for r in suite.results} == {"passed"}


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
