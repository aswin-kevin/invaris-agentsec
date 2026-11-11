"""`agentsec test` stops with a clear error, before any scenario runs, when agent.endpoint is
missing, still the `agentsec init` placeholder, unreachable, or not an OpenAI-style agent (issue #58)."""
import json
import os
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from agentsec.cli.main import AGENT_CONTRACT_URL, PLACEHOLDER_ENDPOINT, PREFLIGHT_SESSION, main
from agentsec.policies import PolicyError, parse_policy

EXIT_ERROR = 2


def run_test_command(tmp_path, policy_text):
    policy = tmp_path / "agentsec.yaml"
    policy.write_text(policy_text)
    out = tmp_path / "out"
    return main(["test", "-p", str(policy), "-o", str(out), "-s", "prompt_injection/ignore_previous"]), out


def policy_with(endpoint_line):
    return "version: '1'\nagent:\n  name: a\n%s\ntests: [prompt_injection]\n" % endpoint_line


@pytest.fixture
def stub_agent():
    """A local HTTP server answering every POST with `reply` (a dict, sent as JSON, or raw text),
    recording each request body."""
    class Handler(BaseHTTPRequestHandler):
        def do_POST(self):
            length = int(self.headers.get("Content-Length", 0))
            server.requests.append(json.loads(self.rfile.read(length)))
            body = server.reply if isinstance(server.reply, str) else json.dumps(server.reply)
            self.send_response(200)
            self.end_headers()
            self.wfile.write(body.encode("utf-8"))

        def log_message(self, *args):
            pass

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    server.requests = []
    server.reply = {"choices": [{"message": {"role": "assistant", "content": "I can't help with that."}}]}
    server.url = "http://127.0.0.1:%d/agent" % server.server_address[1]
    threading.Thread(target=server.serve_forever, daemon=True).start()
    yield server
    server.shutdown()
    server.server_close()


def test_missing_endpoint_is_a_clear_policy_error():
    with pytest.raises(PolicyError, match=r"agent\.endpoint is not set\. Set agent\.endpoint to your agent's URL"):
        parse_policy(policy_with(""))


def test_cli_reports_a_missing_endpoint_without_running(tmp_path, capsys):
    code, out = run_test_command(tmp_path, policy_with(""))
    assert code == EXIT_ERROR
    assert "agent.endpoint is not set" in capsys.readouterr().err
    assert not out.exists()


def test_init_writes_the_placeholder_and_test_refuses_it(tmp_path, capsys):
    policy = tmp_path / "agentsec.yaml"
    assert main(["init", str(policy)]) == 0
    assert PLACEHOLDER_ENDPOINT in policy.read_text()

    assert main(["test", "-p", str(policy), "-o", str(tmp_path / "out")]) == EXIT_ERROR
    err = capsys.readouterr().err
    assert "still the placeholder" in err and AGENT_CONTRACT_URL in err
    assert "No scenarios were run" in err
    assert not (tmp_path / "out").exists()


def test_unreachable_endpoint_fails_before_any_scenario(tmp_path, capsys):
    code, out = run_test_command(tmp_path, policy_with("  endpoint: http://127.0.0.1:1/agent"))
    assert code == EXIT_ERROR
    err = capsys.readouterr().err
    assert "http://127.0.0.1:1/agent did not answer a preflight request" in err
    assert "cannot reach agent" in err and AGENT_CONTRACT_URL in err
    assert not out.exists()


def test_non_openai_reply_fails_before_any_scenario(tmp_path, capsys, stub_agent):
    stub_agent.reply = "<html>Welcome to nginx!</html>"
    code, out = run_test_command(tmp_path, policy_with("  endpoint: %s" % stub_agent.url))
    assert code == EXIT_ERROR
    assert "did not answer a preflight request: agent returned invalid JSON" in capsys.readouterr().err
    assert len(stub_agent.requests) == 1
    assert not out.exists()


def test_reachable_agent_gets_one_preflight_in_its_own_session_then_the_suite(tmp_path, stub_agent):
    code, out = run_test_command(tmp_path, policy_with("  endpoint: %s" % stub_agent.url))
    assert code == 0
    preflight, *scenarios = stub_agent.requests
    assert preflight["user"] == PREFLIGHT_SESSION and "tools" not in preflight
    assert scenarios and all(r.get("user") != PREFLIGHT_SESSION for r in scenarios)
    assert os.path.exists(out / "report.json")
