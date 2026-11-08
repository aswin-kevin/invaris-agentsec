// AgentSec playground UI. All the Python runs in worker.js; this file only renders.
// Everything taken from a report is inserted with textContent, never as HTML: attack inputs and
// model output are adversarial text by design.

const $ = (id) => document.getElementById(id);
const SEVERITIES = ["critical", "high", "medium", "low", "info"];
const PROVIDERS = {
  openai: { label: "OpenAI", model: "gpt-4o-mini", keyHint: "sk-…" },
  groq: { label: "Groq", model: "llama-3.3-70b-versatile", keyHint: "gsk_…" },
  openrouter: { label: "OpenRouter", model: "openai/gpt-4o-mini", keyHint: "sk-or-…" },
  anthropic: { label: "Anthropic", model: "claude-haiku-5-5", keyHint: "sk-ant-…" },
  custom: { label: "your provider", model: "", keyHint: "API key" },
};
const ERROR_TITLES = {
  auth: "The API key was rejected",
  cors: "Blocked by the browser (CORS) or unreachable",
  rate_limit: "Rate limited",
  not_found: "Model or URL not found",
  bad_request: "The provider rejected the request",
  server: "The provider had an error",
  bad_response: "Unexpected reply from the provider",
  config: "Check the form",
  http: "The provider returned an error",
  runtime: "The Python runtime failed",
};

let worker = null;
let runtimeReady = false;
let nextId = 1;
let current = null; // { id, kind } of the running job
let lastResult = null;
const sampleCounts = {}; // variant -> { findings, critical }

// ---------- small helpers ----------

function el(tag, attrs = {}, ...children) {
  const node = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs)) {
    if (k === "class") node.className = v;
    else if (k === "text") node.textContent = v;
    else node.setAttribute(k, v);
  }
  for (const c of children) if (c != null) node.append(c);
  return node;
}

function store(key, value) {
  try {
    if (value === undefined) return localStorage.getItem(key);
    localStorage.setItem(key, value);
  } catch {
    return null;
  }
  return null;
}

let toastTimer = null;
function toast(text) {
  const t = $("toast");
  t.textContent = text;
  t.hidden = false;
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => (t.hidden = true), 2200);
}

async function copy(text, what) {
  try {
    await navigator.clipboard.writeText(text);
    toast(`${what} copied`);
  } catch {
    // Fallback for browsers without clipboard permission.
    const ta = el("textarea");
    ta.value = text;
    document.body.append(ta);
    ta.select();
    const ok = document.execCommand && document.execCommand("copy");
    ta.remove();
    toast(ok ? `${what} copied` : "Copy failed: select the text and copy it manually");
  }
}

function plural(n, word) {
  return `${n} ${word}${n === 1 ? "" : "s"}`;
}

// ---------- theme ----------

const THEMES = ["auto", "light", "dark"];
function applyTheme(theme) {
  if (theme === "auto") delete document.documentElement.dataset.theme;
  else document.documentElement.dataset.theme = theme;
  const label = `Theme: ${theme}`;
  $("theme").setAttribute("aria-label", label);
  $("theme").title = label;
}
applyTheme(THEMES.includes(store("agentsec-theme")) ? store("agentsec-theme") : "auto");
$("theme").addEventListener("click", () => {
  const now = document.documentElement.dataset.theme || "auto";
  const next = THEMES[(THEMES.indexOf(now) + 1) % THEMES.length];
  applyTheme(next);
  store("agentsec-theme", next);
  toast(label(next));
  function label(t) {
    return t === "auto" ? "Theme follows your system" : `${t[0].toUpperCase()}${t.slice(1)} theme`;
  }
});

// ---------- worker ----------

function setRuntime(text, state) {
  $("runtime-text").textContent = text;
  $("runtime").classList.toggle("ready", state === "ready");
  $("runtime").classList.toggle("failed", state === "failed");
}

function updateButtons() {
  const busy = current !== null;
  $("run-sample").disabled = !runtimeReady || busy;
  $("run-llm").disabled = !runtimeReady || busy;
  $("cancel-llm").hidden = !(busy && current.kind === "llm");
}

function startWorker() {
  runtimeReady = false;
  setRuntime("Loading Python…", "loading");
  updateButtons();
  worker = new Worker(new URL("./worker.js", import.meta.url), { type: "module" });
  worker.onmessage = onWorkerMessage;
  worker.onerror = (e) => {
    e.preventDefault();
    failRuntime(e.message || "The worker could not start.");
  };
}

function failRuntime(message) {
  setRuntime("Python failed to load", "failed");
  showError("runtime", message + " Reload the page to try again.");
  if (current) finishJob();
}

function onWorkerMessage(event) {
  const msg = event.data || {};
  if (msg.type === "status") {
    if (!runtimeReady) setRuntime(msg.text, "loading");
  } else if (msg.type === "ready") {
    runtimeReady = true;
    setRuntime(`Ready · AgentSec ${msg.version}`, "ready");
    $("engine-version").textContent = `invaris-agentsec ${msg.version}`;
    updateButtons();
  } else if (msg.type === "progress") {
    if (current && msg.id === current.id) setProgress(msg.done, msg.total);
  } else if (msg.type === "result") {
    if (!current || msg.id !== current.id) return;
    const kind = current.kind;
    finishJob();
    handleResult(msg.result, kind);
  } else if (msg.type === "fatal") {
    if (!runtimeReady) failRuntime(msg.message);
    else if (current && (msg.id === undefined || msg.id === current.id)) {
      finishJob();
      showError("runtime", msg.message);
    }
  }
}

function startJob(kind, payload, button) {
  hideError();
  current = { id: nextId++, kind, button };
  button.classList.add("busy");
  button.querySelector(".label").dataset.idle ??= button.querySelector(".label").textContent;
  button.querySelector(".label").textContent = "Running…";
  updateButtons();
  worker.postMessage({ ...payload, id: current.id });
}

function finishJob() {
  if (current) {
    const label = current.button.querySelector(".label");
    current.button.classList.remove("busy");
    label.textContent = label.dataset.idle || label.textContent;
  }
  current = null;
  $("progress").hidden = true;
  updateButtons();
}

function setProgress(done, total) {
  $("progress").hidden = false;
  $("progress-bar").style.width = `${total ? Math.round((100 * done) / total) : 0}%`;
  $("progress-text").textContent = `Scenario ${done} of ${total}`;
}

// ---------- tabs ----------

const tabs = [$("tab-sample"), $("tab-llm")];
function selectTab(tab, focus = false) {
  for (const t of tabs) {
    const on = t === tab;
    t.setAttribute("aria-selected", String(on));
    t.tabIndex = on ? 0 : -1;
    $(t.getAttribute("aria-controls")).hidden = !on;
  }
  if (focus) tab.focus();
}
for (const t of tabs) {
  t.addEventListener("click", () => selectTab(t));
  t.addEventListener("keydown", (e) => {
    if (e.key !== "ArrowRight" && e.key !== "ArrowLeft") return;
    const i = (tabs.indexOf(t) + (e.key === "ArrowRight" ? 1 : tabs.length - 1)) % tabs.length;
    selectTab(tabs[i], true);
  });
}

// ---------- sample mode ----------

$("run-sample").addEventListener("click", () => {
  const variant = document.querySelector('input[name="variant"]:checked').value;
  startJob("sample", { type: "sample", variant }, $("run-sample"));
});

function updateCompare() {
  const n = sampleCounts.naive;
  const h = sampleCounts.hardened;
  let text = "";
  if (n && h) text = `Naive: ${n.critical} critical → Hardened: ${h.critical} critical`;
  else if (n) text = "Now switch to Hardened and run the same attacks again.";
  $("compare").textContent = text;
}

// ---------- LLM mode ----------

function onProviderChange() {
  const p = $("provider").value;
  const spec = PROVIDERS[p];
  $("base-url-field").hidden = p !== "custom";
  $("model").placeholder = spec.model || "model name";
  $("api-key").placeholder = spec.keyHint;
  $("key-hint").textContent = `Kept in this tab's memory only and sent only to ${spec.label}. Never saved, never sent to us.`;
  store("agentsec-provider", p);
}
$("provider").addEventListener("change", onProviderChange);
if (PROVIDERS[store("agentsec-provider")]) $("provider").value = store("agentsec-provider");
onProviderChange();
$("model").value = store("agentsec-model") || "";
$("base-url").value = store("agentsec-base-url") || "";

$("llm-form").addEventListener("submit", (e) => {
  e.preventDefault();
  if (!runtimeReady || current) return;
  const provider = $("provider").value;
  const model = $("model").value.trim() || PROVIDERS[provider].model;
  const baseUrl = provider === "custom" ? $("base-url").value.trim() : "";
  const key = $("api-key").value;
  // Only the provider, model and base URL are remembered, never the key.
  store("agentsec-model", $("model").value.trim());
  store("agentsec-base-url", $("base-url").value.trim());
  if (!key.trim()) {
    showError("config", "Enter an API key for " + PROVIDERS[provider].label + ".");
    $("api-key").focus();
    return;
  }
  setProgress(0, 0);
  $("progress-text").textContent = "Starting…";
  startJob("llm", {
    type: "llm",
    config: { provider, model, base_url: baseUrl, api_key: key, guard: $("guard").checked },
  }, $("run-llm"));
});

$("cancel-llm").addEventListener("click", () => {
  // The worker is blocked inside synchronous requests, so cancelling means replacing it.
  worker.terminate();
  finishJob();
  showError("runtime", "Run cancelled. Requests already sent may still count toward your usage.", true);
  startWorker();
});

// ---------- errors ----------

function showError(kind, message, warn = false) {
  $("error-title").textContent = ERROR_TITLES[kind] || "Something went wrong";
  if (warn) $("error-title").textContent = "Cancelled";
  $("error-text").textContent = message;
  $("error").classList.toggle("warn", warn);
  $("error").hidden = false;
}

function hideError() {
  $("error").hidden = true;
}

// ---------- results ----------

function handleResult(result, kind) {
  if (result.error && !result.summary) {
    $("results").hidden = true;
    showError(result.error.kind, result.error.message);
    return;
  }
  if (result.error) showError(result.error.kind, result.error.message);
  lastResult = result;
  if (kind === "sample") {
    const variant = result.agent.endsWith("hardened") ? "hardened" : "naive";
    sampleCounts[variant] = { findings: result.summary.findings, critical: result.summary.by_severity.critical || 0 };
    updateCompare();
  }
  renderResults(result);
}

function renderResults(r) {
  const s = r.summary;
  const box = document.querySelector(".summary");
  box.classList.toggle("clean", s.findings === 0);
  box.classList.toggle("dirty", s.findings > 0);
  $("verdict-num").textContent = String(s.findings);
  $("verdict-label").textContent = `${s.findings === 1 ? "finding" : "findings"} · ${r.agent}`;

  const chips = $("sev-chips");
  chips.replaceChildren();
  for (const sev of SEVERITIES) {
    const n = (s.by_severity || {})[sev] || 0;
    if (n) chips.append(el("li", { class: `sev sev-${sev}`, text: `${n} ${sev}` }));
  }
  if (!chips.children.length) chips.append(el("li", { class: "sev sev-info", text: "no findings" }));

  $("s-scen").textContent = s.scenarios;
  $("s-pass").textContent = s.passed;
  $("s-find").textContent = s.with_findings;
  $("s-err").textContent = s.errors;
  $("share-line").textContent = r.share;
  document.querySelector(".share").hidden = !r.attacked;

  const extra = [];
  if (r.partial) extra.push("The run stopped early: scenarios after the error are counted as errors.");
  if (s.inconclusive) extra.push(`${plural(s.inconclusive, "scenario")} inconclusive (the attack never reached the agent; not counted as resisted).`);
  if (r.usage) extra.push(`${plural(r.usage.requests, "request")} to the provider, ${r.usage.prompt_tokens + r.usage.completion_tokens} tokens.`);
  $("partial-note").textContent = extra.join(" ");
  $("partial-note").hidden = extra.length === 0;

  const list = $("findings");
  list.replaceChildren();
  if (!r.findings.length) {
    list.append(el("div", { class: "card empty" },
      el("strong", { text: "No findings" }),
      el("span", { class: "muted", text: s.errors ? "But some scenarios errored, so this isn't a clean pass." : "The agent resisted every attack that reached it." })));
  }
  const sorted = [...r.findings].sort((a, b) => SEVERITIES.indexOf(a.severity) - SEVERITIES.indexOf(b.severity));
  for (const f of sorted) list.append(findingCard(f));
  if ((r.errors || []).length) {
    const dl = el("dl");
    for (const e of r.errors) dl.append(el("dt", { text: e.scenario_id }), el("dd", { text: e.error }));
    list.append(el("details", { class: "card finding" },
      el("summary", {},
        el("span", { class: "sev sev-info", text: "error" }),
        el("span", { class: "title" }, `${plural(r.errors.length, "scenario")} errored`,
          el("small", { text: "Not counted as resisted. Open for details." }))),
      el("div", { class: "body" }, dl)));
  }

  $("results").hidden = false;
  $("results").scrollIntoView({ behavior: matchMedia("(prefers-reduced-motion: reduce)").matches ? "auto" : "smooth", block: "start" });
}

function evidenceText(evidence) {
  if (!evidence || !evidence.length) return "—";
  return evidence.map((e) => {
    if (e && e.tool_name) return `${e.tool_name}(${JSON.stringify(e.arguments || {})})`;
    return JSON.stringify(e, null, 2);
  }).join("\n");
}

function findingCard(f) {
  const rows = [
    ["Rule", f.rule],
    ["Category", f.category],
    ["Scenario", f.scenario_id],
    ["Input", f.input],
    ["What it did", f.observed_action],
    ["Rule broken", f.policy_violated],
    ["Evidence", evidenceText(f.evidence)],
    ["Fix", f.remediation],
  ];
  const dl = el("dl");
  for (const [k, v] of rows) {
    if (v == null || v === "") continue;
    const long = k === "Input" || k === "Evidence";
    dl.append(el("dt", { text: k }), el("dd", {}, long ? el("pre", { text: String(v) }) : String(v)));
  }
  return el("details", { class: "card finding" },
    el("summary", {},
      el("span", { class: `sev sev-${f.severity}`, text: f.severity }),
      el("span", { class: "title" }, f.title, el("small", { text: `${f.rule} · ${f.scenario_id}` }))),
    el("div", { class: "body" }, dl));
}

$("copy-share").addEventListener("click", () => {
  if (lastResult) copy(`${lastResult.share} Try it: ${location.href.split("#")[0]}`, "Share line");
});
$("copy-md").addEventListener("click", () => lastResult && copy(lastResult.markdown, "Markdown"));
$("download-json").addEventListener("click", () => {
  if (!lastResult) return;
  const blob = new Blob([JSON.stringify(lastResult.report, null, 2)], { type: "application/json" });
  const a = el("a", { href: URL.createObjectURL(blob), download: `agentsec-report-${lastResult.mode}.json` });
  document.body.append(a);
  a.click();
  a.remove();
  setTimeout(() => URL.revokeObjectURL(a.href), 1000);
});
$("copy-pip").addEventListener("click", () => copy("pip install invaris-agentsec", "Command"));

startWorker();
