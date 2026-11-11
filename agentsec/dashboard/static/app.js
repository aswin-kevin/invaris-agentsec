/* AgentSec dashboard.
 *
 * Report content is untrusted: traces hold the adversarial payloads AgentSec sent and whatever the
 * agent said back. Everything from a report is inserted as text nodes, never parsed as markup, and
 * invisible or control characters are shown as visible U+XXXX marks so hidden instructions can be seen.
 */
(function () {
  "use strict";

  var SEV = ["critical", "high", "medium", "low"];
  var SEV_RANK = { critical: 4, high: 3, medium: 2, low: 1 };
  var STATUS_LABEL = { passed: "Passed", findings: "Findings", error: "Error", not_observable: "Not observable", inconclusive: "Inconclusive" };
  // What an inconclusive verdict means, said the same way everywhere it appears.
  var PROVENANCE_HINT = "the agent can report it with x_agentsec.agent";
  var INCONCLUSIVE_WHY = "the adversarial content never reached the agent (it did not open the poisoned item, or stopped before the step where the injection appears), so its resistance was not measured";
  var VECTOR_LABEL = {
    direct: "User message", retrieved_document: "Retrieved document", tool_output: "Tool output",
    tool_definition: "Tool definition", unknown: "Unknown"
  };
  var EVENT_LABEL = {
    user_message: "User", assistant_message: "Agent", tool_call: "Tool call", tool_result: "Tool result",
    limit: "Limit reached", error: "Error"
  };
  var EVENT_GLYPH = { user_message: "U", assistant_message: "A", tool_call: "fn", tool_result: "re", limit: "!", error: "!" };

  var state = { meta: null, reports: [], fingerprint: null, cache: {}, route: null, polling: null };
  var main = document.getElementById("main");

  /* ------------------------------------------------------------------ DOM helpers */

  // Control and format characters (zero-width spaces, bidi overrides, tag characters...), minus
  // ordinary whitespace. These are how instructions get hidden in documents and tool descriptions.
  var HIDDEN = /[\u0000-\u0008\u000B\u000C\u000E-\u001F\u007F-\u009F­؜᠎​-‏‪-‮⁠-⁤⁦-⁯﻿￹-￻]|\uDB40[\uDC00-\uDC7F]/g;

  function codepoint(ch) {
    var cp = ch.codePointAt(0).toString(16).toUpperCase();
    while (cp.length < 4) cp = "0" + cp;
    return "U+" + cp;
  }

  function reveal(str) {
    var frag = document.createDocumentFragment();
    str = String(str);
    var last = 0, m;
    HIDDEN.lastIndex = 0;
    while ((m = HIDDEN.exec(str)) !== null) {
      if (m.index > last) frag.appendChild(document.createTextNode(str.slice(last, m.index)));
      var mark = document.createElement("i");
      mark.className = "inv";
      mark.textContent = codepoint(m[0]);
      mark.title = "Hidden character " + codepoint(m[0]);
      frag.appendChild(mark);
      last = m.index + m[0].length;
    }
    if (last < str.length) frag.appendChild(document.createTextNode(str.slice(last)));
    return frag;
  }

  // Identifiers such as tool names: also mark non-ASCII letters, which is how look-alike tool
  // names (a Cyrillic "е" in "send_email") impersonate trusted tools.
  function ident(str) {
    var frag = document.createDocumentFragment();
    Array.from(String(str)).forEach(function (ch) {
      if (/[\x20-\x7E]/.test(ch)) {
        frag.appendChild(document.createTextNode(ch));
      } else {
        var mark = document.createElement("i");
        mark.className = "inv";
        mark.textContent = ch.trim() && !HIDDEN.test(ch) ? ch + " " + codepoint(ch) : codepoint(ch);
        HIDDEN.lastIndex = 0;
        mark.title = "Non-ASCII character " + codepoint(ch);
        frag.appendChild(mark);
      }
    });
    return frag;
  }

  function h(tag, attrs) {
    var el = document.createElement(tag);
    if (attrs) {
      Object.keys(attrs).forEach(function (k) {
        var v = attrs[k];
        if (v === null || v === undefined || v === false) return;
        if (k === "class") el.className = v;
        else if (k === "text") el.appendChild(reveal(v));
        else if (k.slice(0, 2) === "on") el.addEventListener(k.slice(2), v);
        else if (k === "style") el.style.cssText = v;  // CSSOM, allowed by the CSP (style attributes are not)
        else el.setAttribute(k, v === true ? "" : v);
      });
    }
    for (var i = 2; i < arguments.length; i++) append(el, arguments[i]);
    return el;
  }

  function append(el, child) {
    if (arguments.length > 2) {
      for (var i = 1; i < arguments.length; i++) append(el, arguments[i]);
      return;
    }
    if (child === null || child === undefined || child === false) return;
    if (Array.isArray(child)) { child.forEach(function (c) { append(el, c); }); return; }
    if (typeof child === "string" || typeof child === "number") { el.appendChild(reveal(String(child))); return; }
    el.appendChild(child);
  }

  function clear(el) { while (el.firstChild) el.removeChild(el.firstChild); }

  function render(node) {
    clear(main);
    append(main, node);
  }

  function plural(n, one, many) { return n + " " + (n === 1 ? one : (many || one + "s")); }

  function fmtNum(n) { return n === null || n === undefined ? "–" : Number(n).toLocaleString(); }

  function fmtTime(iso) {
    if (!iso) return "unknown time";
    var d = new Date(iso);
    if (isNaN(d)) return iso;
    return d.toLocaleString(undefined, { year: "numeric", month: "short", day: "numeric", hour: "2-digit", minute: "2-digit" });
  }

  function ago(iso) {
    if (!iso) return "";
    var d = new Date(iso);
    if (isNaN(d)) return "";
    var s = Math.round((Date.now() - d.getTime()) / 1000);
    if (s < 60) return "just now";
    if (s < 3600) return Math.round(s / 60) + " min ago";
    if (s < 86400) return Math.round(s / 3600) + " h ago";
    if (s < 86400 * 7) return Math.round(s / 86400) + " d ago";
    return d.toLocaleDateString(undefined, { month: "short", day: "numeric", year: "numeric" });
  }

  function sevLabel(sev) { return h("span", { class: "sev " + sev }, sev.charAt(0).toUpperCase() + sev.slice(1)); }
  function statusLabel(st) { return h("span", { class: "status " + st }, STATUS_LABEL[st] || st); }
  function worstOf(list) {
    var w = null;
    list.forEach(function (s) { if (s && (!w || SEV_RANK[s] > SEV_RANK[w])) w = s; });
    return w;
  }
  function bySeverity(a, b) { return (SEV_RANK[b.severity] || 0) - (SEV_RANK[a.severity] || 0) || (a.id < b.id ? -1 : 1); }

  function shellQuote(s) {
    s = String(s);
    return /^[A-Za-z0-9_\-.,:\/=@+]+$/.test(s) ? s : "'" + s.replace(/'/g, "'\\''") + "'";
  }

  function copyButton(text, label) {
    var btn = h("button", { class: "btn small", type: "button" }, label || "Copy");
    btn.addEventListener("click", function () {
      var done = function () { btn.textContent = "Copied"; setTimeout(function () { btn.textContent = label || "Copy"; }, 1400); };
      if (navigator.clipboard && navigator.clipboard.writeText) {
        navigator.clipboard.writeText(text).then(done, function () { fallbackCopy(text); done(); });
      } else { fallbackCopy(text); done(); }
    });
    return btn;
  }

  function fallbackCopy(text) {
    var ta = h("textarea", { style: "position:fixed;opacity:0" });
    ta.value = text;
    document.body.appendChild(ta);
    ta.select();
    try { document.execCommand("copy"); } catch (e) { /* nothing more to try */ }
    document.body.removeChild(ta);
  }

  // Links built from report data: only http(s), so an uploaded report cannot plant a javascript: or data: URL.
  function safeHref(url) {
    if (!url) return null;      // no link recorded (new URL("null", base) would resolve to a page path)
    try {
      var u = new URL(String(url), location.href);
      return u.protocol === "https:" || u.protocol === "http:" ? u.href : null;
    } catch (e) { return null; }
  }

  function cmd(text) { return h("div", { class: "cmd" }, h("code", null, text), copyButton(text)); }

  function toast(message, actionLabel, action) {
    var el = document.getElementById("toast");
    clear(el);
    append(el, h("span", null, message));
    if (actionLabel) {
      append(el, h("button", { type: "button", onclick: function () { el.hidden = true; action(); } }, actionLabel));
    }
    append(el, h("button", { type: "button", "aria-label": "Dismiss", onclick: function () { el.hidden = true; } }, "Dismiss"));
    el.hidden = false;
    clearTimeout(toast.timer);
    toast.timer = setTimeout(function () { el.hidden = true; }, 12000);
  }

  /* ------------------------------------------------------------------ data */

  function api(path) {
    return fetch(path, { headers: { Accept: "application/json" }, cache: "no-store" }).then(function (res) {
      return res.json().catch(function () { return {}; }).then(function (body) {
        if (!res.ok) throw new Error(body.error || ("HTTP " + res.status));
        return body;
      });
    });
  }

  function loadReport(id) {
    var entry = state.reports.find(function (r) { return r.id === id; });
    var cached = state.cache[id];
    if (cached && entry && cached.entry.mtime === entry.mtime) return Promise.resolve(cached);
    return api("/api/reports/" + encodeURIComponent(id)).then(function (data) {
      indexReport(data);
      state.cache[id] = data;
      return data;
    });
  }

  function indexReport(data) {
    var r = data.report;
    data.findingById = {};
    data.scenarioById = {};
    (r.findings || []).forEach(function (f) { data.findingById[f.id] = f; });
    (r.scenarios || []).forEach(function (s) { data.scenarioById[s.id] = s; });
    data.isMcp = r.kind === "mcp_scan";
  }

  function refreshReports(initial) {
    return api("/api/reports").then(function (data) {
      var before = {};
      state.reports.forEach(function (r) { before[r.id] = r; });
      var changed = data.fingerprint !== state.fingerprint;
      state.reports = data.reports;
      state.fingerprint = data.fingerprint;
      if (!changed) return false;
      renderRail();
      if (!initial) {
        var added = data.reports.filter(function (r) { return !before[r.id]; });
        var current = state.route && state.route.id;
        var rewritten = current && before[current] && data.reports.some(function (r) {
          return r.id === current && r.mtime !== before[current].mtime;
        });
        if (rewritten) {
          toast("This report file was rewritten by a newer run.", "Show the new run", function () { route(); });
        } else if (added.length) {
          var a = added[0];
          toast("New report: " + a.name + " (" + a.display_path + ")", "Open", function () { location.hash = "#/r/" + a.id; });
        }
        if (state.route && (state.route.view === "home" || state.route.view === "compare")) route();
      }
      return true;
    }).catch(function () { /* the server may be restarting; try again on the next tick */ });
  }

  function startPolling() {
    if (state.polling) return;
    state.polling = setInterval(function () {
      if (document.visibilityState === "visible") refreshReports(false);
    }, 4000);
  }

  /* ------------------------------------------------------------------ rail */

  function severityStrip(meta) {
    var strip = h("div", { class: "strip", "aria-hidden": "true" });
    var total = SEV.reduce(function (n, s) { return n + (meta.by_severity[s] || 0); }, 0);
    if (meta.error) return strip;
    if (!total) {
      append(strip, h("span", { class: meta.errors && meta.errors === meta.scenarios ? "s-err" : meta.inconclusive ? "s-inc" : "s-none" }));
      return strip;
    }
    SEV.forEach(function (s) {
      var n = meta.by_severity[s] || 0;
      if (n) append(strip, h("span", { class: "bg-" + s, style: "flex:" + n }));
    });
    return strip;
  }

  function runSummaryText(meta) {
    if (meta.error) return meta.error;
    if (meta.kind === "test" && meta.errors && meta.errors === meta.scenarios) return plural(meta.errors, "scenario") + " errored";
    var inc = meta.kind === "test" ? meta.inconclusive || 0 : 0;
    if (!meta.findings) {
      return meta.kind === "mcp_scan" ? "No findings in " + plural(meta.scenarios, "item")
        : (meta.passed === meta.scenarios ? "All " + meta.scenarios + " scenarios passed"
          : "No findings in " + plural(meta.scenarios, "scenario") + (inc ? "; " + inc + " inconclusive" : ""));
    }
    var parts = SEV.filter(function (s) { return meta.by_severity[s]; }).map(function (s) { return meta.by_severity[s] + " " + s; });
    if (inc) parts.push(inc + " inconclusive");
    return parts.join(", ");
  }

  function groupReports(reports) {
    var groups = [], byKey = {};
    reports.forEach(function (r) {
      var key = r.kind + "\u0000" + r.name;
      if (!byKey[key]) { byKey[key] = { name: r.name, kind: r.kind, runs: [] }; groups.push(byKey[key]); }
      byKey[key].runs.push(r);
    });
    return groups;
  }

  function renderRail() {
    var list = document.getElementById("runs");
    clear(list);
    var activeId = state.route && state.route.id;
    if (!state.reports.length) {
      append(list, h("p", { class: "muted", style: "padding:8px 10px;font-size:12.5px;margin:0" }, "No reports yet."));
    }
    groupReports(state.reports).forEach(function (g) {
      var group = h("div", { class: "rail-group", role: "group", "aria-label": g.name },
        h("h3", null, h("span", null, g.name), h("span", null, g.kind === "mcp_scan" ? "MCP scan" : plural(g.runs.length, "run"))));
      g.runs.forEach(function (r) {
        append(group, h("a", { class: "run" + (r.id === activeId ? " active" : ""), href: "#/r/" + r.id, role: "listitem",
          "aria-current": r.id === activeId ? "page" : null },
          h("div", { class: "run-top" }, h("span", { class: "run-name" }, runSummaryText(r)), h("span", { class: "run-time" }, ago(r.generated_at))),
          h("div", { class: "run-path", title: r.path }, r.display_path),
          severityStrip(r)));
      });
      append(list, group);
    });
    var foot = document.getElementById("rail-foot");
    clear(foot);
    if (state.meta) {
      append(foot, h("div", null, "Watching ", state.meta.roots.map(function (r, i) {
        var sp = shortPath(r);
        return [i ? ", " : "", sp === r || sp.indexOf("/") >= 0 || sp.indexOf(".") >= 0 ? h("code", { title: r }, sp) : h("span", { title: r }, sp)];
      })), h("div", null, "AgentSec " + state.meta.version));
    }
    document.getElementById("nav-compare").className = state.route && state.route.view === "compare" ? "active" : "";
  }

  function shortPath(p) {
    var cwd = state.meta && state.meta.cwd;
    if (cwd && p === cwd) return "the current directory";
    if (cwd && p.indexOf(cwd + "/") === 0) return p.slice(cwd.length + 1);
    return p;
  }

  /* ------------------------------------------------------------------ routing */

  function parseRoute() {
    var hash = location.hash.replace(/^#/, "") || "/";
    var q = {};
    var qi = hash.indexOf("?");
    if (qi >= 0) {
      hash.slice(qi + 1).split("&").forEach(function (kv) {
        if (!kv) return;
        var p = kv.split("=");
        q[decodeURIComponent(p[0])] = decodeURIComponent((p[1] || "").replace(/\+/g, " "));
      });
      hash = hash.slice(0, qi);
    }
    var parts = hash.split("/").filter(Boolean);
    if (parts[0] === "r" && parts[1]) {
      return { view: "report", id: parts[1], tab: parts[2] || "overview", sub: parts[3] ? decodeURIComponent(parts[3]) : null, q: q };
    }
    if (parts[0] === "compare") return { view: "compare", q: q };
    return { view: "home", q: q };
  }

  function hashFor(r) {
    var s = "#/r/" + r.id + "/" + (r.tab || "overview");
    if (r.sub) s += "/" + encodeURIComponent(r.sub);
    var q = r.q || {};
    var keys = Object.keys(q).filter(function (k) { return q[k] !== "" && q[k] !== null && q[k] !== undefined; });
    if (keys.length) s += "?" + keys.map(function (k) { return encodeURIComponent(k) + "=" + encodeURIComponent(q[k]); }).join("&");
    return s;
  }

  function route() {
    var r = parseRoute();
    var sameReport = state.route && state.route.view === "report" && r.view === "report" && state.route.id === r.id;
    var keepScroll = sameReport && state.route.tab === r.tab && (r.tab === "findings" || r.tab === "scenarios");
    state.route = r;
    document.getElementById("shell").classList.remove("rail-open");
    renderRail();
    if (r.view === "home") return viewHome();
    if (r.view === "compare") return viewCompare(r);
    var scroll = main.scrollTop;
    if (!state.cache[r.id]) render(h("div", { class: "loading" }, "Loading report…"));
    loadReport(r.id).then(function (data) {
      if (state.route !== r) return;
      viewReport(data, r);
      var active = main.querySelector(".list .item.active");
      if (active) {
        var box = active.closest(".list-scroll");
        if (box && (active.offsetTop < box.scrollTop || active.offsetTop + active.offsetHeight > box.scrollTop + box.clientHeight)) {
          box.scrollTop = active.offsetTop - box.clientHeight / 3;
        }
      }
      if (keepScroll) main.scrollTop = scroll; else if (!r.q.f) main.scrollTop = 0;
    }).catch(function (err) {
      render(h("div", { class: "page" }, emptyState("This report could not be opened", err.message,
        h("p", null, h("a", { href: "#/" }, "Back to all reports")))));
    });
  }

  /* ------------------------------------------------------------------ home */

  function emptyState(title) {
    var box = h("div", { class: "empty" }, h("h2", null, title));
    for (var i = 1; i < arguments.length; i++) {
      var a = arguments[i];
      append(box, typeof a === "string" ? h("p", null, a) : a);
    }
    return box;
  }

  function viewHome() {
    document.title = "AgentSec";
    var page = h("div", { class: "page" });
    append(page, h("div", { class: "head" }, h("div", null, h("h1", null, "Reports"),
      h("div", { class: "facts" }, h("span", null, plural(state.reports.length, "report") + " found")))));
    if (!state.reports.length) {
      append(page, h("div", { class: "panel", style: "margin-top:24px" }, emptyState("No reports found",
        "The dashboard shows the report.json and mcp-report.json files that AgentSec writes. Run a test or an MCP scan and the report appears here without a reload.",
        h("div", { style: "max-width:560px;margin:16px auto 0;text-align:left" },
          cmd("agentsec test --policy agentsec.yaml"),
          cmd('agentsec mcp scan --command "python server.py"')),
        h("p", { class: "muted" }, "Watching: ", (state.meta ? state.meta.roots : []).join(", ")))));
      return render(page);
    }
    var tbody = h("tbody");
    state.reports.forEach(function (r) {
      var row = h("tr", { class: "link", onclick: function () { location.hash = "#/r/" + r.id; } },
        h("td", null, h("a", { href: "#/r/" + r.id }, r.name), h("div", { class: "muted mono", style: "font-size:12px" }, r.display_path)),
        h("td", null, r.kind === "mcp_scan" ? "MCP scan" : "Agent test"),
        h("td", { class: "nowrap" }, fmtTime(r.generated_at)),
        h("td", { class: "num" }, fmtNum(r.scenarios)),
        h("td", { class: "num" }, r.kind === "mcp_scan" ? "–" : fmtNum(r.passed)),
        h("td", { class: "num" }, r.kind === "mcp_scan" ? "–" : fmtNum(r.errors)),
        h("td", { style: "min-width:180px" }, severityStrip(r), h("div", { class: "strip-legend" }, runSummaryText(r))));
      append(tbody, row);
    });
    append(page, h("div", { class: "panel", style: "margin-top:24px;overflow-x:auto" },
      h("table", null, h("thead", null, h("tr", null, h("th", null, "Agent or server"), h("th", null, "Kind"), h("th", null, "Generated"),
        h("th", { class: "num" }, "Scenarios"), h("th", { class: "num" }, "Passed"), h("th", { class: "num" }, "Errors"), h("th", null, "Findings"))), tbody)));
    append(page, h("p", { class: "note" }, "AgentSec overwrites report.json in its output directory on every run. To keep a run for comparison, pass a different --out, for example ",
      h("code", null, "agentsec test --out .agentsec/baseline"), "."));
    render(page);
  }

  /* ------------------------------------------------------------------ report shell */

  function viewReport(data, r) {
    var rep = data.report, entry = data.entry;
    document.title = entry.name + " | AgentSec";
    var page = h("div", { class: "page" });
    var run = rep.run_config || {};
    var facts = h("div", { class: "facts" });
    if (data.isMcp) {
      var srv = run.server || {};
      if (srv.version) append(facts, fact("Server version", srv.version));
      append(facts, fact("Target", h("code", null, run.target || "unknown")));
    } else {
      var agent = (run.policy || {}).agent || {};
      append(facts, fact("Endpoint", h("code", null, agent.endpoint || "unknown")));
      append(facts, fact("Seed", String(run.seed)));
      if (run.policy_path) append(facts, fact("Policy", h("code", null, run.policy_path)));
    }
    append(facts, fact("Generated", fmtTime(rep.generated_at)));
    append(facts, fact("AgentSec", (rep.tool || {}).version || "unknown"));
    if (!data.isMcp) {
      var reported = agentReported(rep);
      if (reported.length) {
        append(facts, fact("Agent reported", [reported.map(describeAgent).join("; "),
          reported.some(function (a) { return a.backend === "scripted"; })
            ? [" ", h("span", { class: "tag warn", title: "A test double made the agent's decisions: verdicts say nothing about any model" }, "Scripted stand-in")] : null]));
      }
    }
    append(facts, fact("File", h("code", { title: entry.path }, entry.display_path)));

    append(page, h("div", { class: "crumbs" }, h("a", { href: "#/" }, "Reports"), h("span", { "aria-hidden": "true" }, "/"),
      h("span", null, data.isMcp ? "MCP scan" : "Agent test")));
    append(page, h("div", { class: "head" }, h("div", null, h("h1", null, entry.name), facts),
      h("div", { style: "display:flex;gap:8px" }, h("a", { class: "btn", href: "#/compare?head=" + entry.id }, "Compare with another run"))));

    var tabs = data.isMcp
      ? [["overview", "Overview"], ["findings", "Findings", rep.findings.length], ["items", "Definitions", rep.scenarios.length]]
      : [["overview", "Overview"], ["findings", "Findings", rep.findings.length], ["scenarios", "Scenarios", rep.scenarios.length], ["policy", "Policy"]];
    append(page, h("nav", { class: "tabs", "aria-label": "Report sections" }, tabs.map(function (t) {
      return h("a", { href: "#/r/" + entry.id + "/" + t[0], class: r.tab === t[0] ? "active" : null, "aria-current": r.tab === t[0] ? "page" : null },
        t[1], t[2] !== undefined ? h("span", { class: "count" }, String(t[2])) : null);
    })));

    var body;
    if (r.tab === "findings") body = viewFindings(data, r);
    else if (r.tab === "scenarios" && !data.isMcp) body = viewScenarios(data, r);
    else if (r.tab === "policy" && !data.isMcp) body = viewPolicy(data);
    else if (r.tab === "items" && data.isMcp) body = viewMcpItems(data, r);
    else body = data.isMcp ? viewMcpOverview(data) : viewOverview(data);
    append(page, body);
    render(page);
  }

  function fact(label, value) { return h("span", null, h("i", null, label), value); }

  /* ------------------------------------------------------------------ overview (agent test) */

  function verdict(sum) {
    if (!sum.scenarios) return ["This report has no scenarios.", "The policy selected no scenario that could be built. Categories that need tool_effects or agent_roles build nothing without them."];
    if (sum.errors === sum.scenarios) return ["No scenario could run.", "Every scenario ended in an error before the agent answered, so nothing was tested. The errors are listed above."];
    var inc = sum.inconclusive || 0;
    if (inc && inc + (sum.errors || 0) + (sum.not_observable || 0) === sum.scenarios) {
      return ["Nothing was tested: the attack never reached the agent.", "Every scenario that ran was inconclusive: " + INCONCLUSIVE_WHY + ". Inconclusive is not a pass."];
    }
    if (!sum.findings) {
      var sub = "No deterministic check fired on anything the traces show. That is evidence for these scenarios, not proof the agent is safe.";
      if (inc) return ["No findings in the scenarios that were tested, but " + plural(inc, "scenario") + (inc === 1 ? " was" : " were") + " inconclusive.",
        "Inconclusive means " + INCONCLUSIVE_WHY + ". It is not counted as passed. " + sub];
      if (sum.not_observable) return ["No findings, but " + plural(sum.not_observable, "scenario") + " could not be observed.", sub];
      if (sum.errors) return ["No findings in the scenarios that ran; " + plural(sum.errors, "scenario") + " errored.", sub];
      return ["All " + sum.scenarios + " scenarios passed.", sub];
    }
    var sev = sum.by_severity || {};
    var head = plural(sum.findings, "finding") + " in " + sum.with_findings + " of " + plural(sum.scenarios, "scenario") + ".";
    var bits = SEV.filter(function (s) { return sev[s]; }).map(function (s) { return sev[s] + " " + s; });
    return [head, bits.join(", ") + ". Each finding carries the input, the observed action, the violated policy and the trace events that show it."
      + (inc ? " " + plural(inc, "scenario") + (inc === 1 ? " was" : " were") + " inconclusive (the attack never reached the agent) and " + (inc === 1 ? "is" : "are") + " not counted as passed." : "")];
  }

  function viewOverview(data) {
    var rep = data.report, ins = data.insights, sum = rep.summary, id = data.entry.id;
    var wrap = h("div");
    (rep.warnings || []).forEach(function (w) { append(wrap, warningBox(w)); });
    if (ins.errors.length) {
      append(wrap, h("div", { class: "err-box" }, ins.errors.slice(0, 4).map(function (e) {
        return h("p", { style: "margin:0 0 4px" }, h("b", null, plural(e.scenarios, "scenario") + ": "), e.message);
      }), sum.errors === sum.scenarios ? h("p", { style: "margin:6px 0 0" }, "Start the agent and run agentsec test again.") : null));
    }

    var v = verdict(Object.assign({}, sum, { inconclusive: ins.evaluation ? ins.evaluation.inconclusive : sum.inconclusive }));
    var tally = h("div", { class: "tally" }, tallyItem(sum.scenarios, "Scenarios"), tallyItem(sum.passed, "Passed"),
      tallyItem(sum.with_findings, "With findings"), tallyItem(sum.errors, "Errors"),
      sum.not_observable ? tallyItem(sum.not_observable, "Not observable") : null,
      ins.evaluation && ins.evaluation.inconclusive ? tallyItem(ins.evaluation.inconclusive, "Inconclusive") : null);
    append(wrap, h("div", { class: "verdict-wrap" },
      h("div", null, h("p", { class: "verdict" }, v[0]), h("p", { class: "verdict-sub" }, v[1])), tally));

    if (sum.findings) {
      var bar = h("div", { class: "sevbar", role: "img", "aria-label": SEV.map(function (s) { return (sum.by_severity[s] || 0) + " " + s; }).join(", ") });
      var key = h("div", { class: "sevkey" });
      SEV.forEach(function (s) {
        var n = sum.by_severity[s] || 0;
        if (n) append(bar, h("span", { class: "bg-" + s, style: "flex:" + n, title: n + " " + s }));
        append(key, h("a", { href: hashFor({ id: id, tab: "findings", q: { sev: s } }), class: "sev " + s, style: n ? null : "opacity:.5" },
          s.charAt(0).toUpperCase() + s.slice(1) + " ", h("b", null, String(n))));
      });
      append(wrap, h("div", { class: "section" }, bar, key));
    }

    var left = h("div"), right = h("div");
    append(left, section("Scenarios by attack category", "Each square is one scenario. Select one to open its trace.", matrix(ins, id)));
    if (ins.attack_goals && ins.attack_goals.length) {
      append(left, section("Attacks that reached their goal", "Delivered payload, then the call the attacker wanted.",
        attackGoalsTable(ins.attack_goals, id)));
    }
    if (ins.rules.length) append(left, section("Rules that fired", null, rulesTable(ins.rules, id)));
    if (ins.tools.length) append(left, section("Tools the agent called", "Every call was simulated by AgentSec; no real action was taken.", toolsTable(ins.tools)));
    var ran = sum.errors !== sum.scenarios;
    if (ran) append(right, section("OWASP agentic categories", null, owaspBars(ins.owasp, id),
      h("p", { class: "note" }, "Findings per category of the ", h("a", { href: safeHref((state.meta && state.meta.owasp && state.meta.owasp.url) || "https://genai.owasp.org/"), rel: "noreferrer noopener", target: "_blank" }, "OWASP Top 10 for Agentic Applications"),
        ". The mapping is Invaris' closest-fit judgement, not an official classification; a finding can count toward more than one category.")));
    if (ran) append(right, section("How the attack arrived", "Scenarios with findings, by where the adversarial content was delivered.", vectorBars(ins.vectors)));
    if (ins.evaluation) append(right, section("What this run measured", null, evaluationPanel(ins, id)));
    append(right, section("Run", null, runFacts(rep, ins)), section("Reproduce", null, reproduce(data)));
    append(wrap, h("div", { class: "grid2" }, left, right));
    return wrap;
  }

  function tallyItem(n, label) { return h("div", null, h("b", null, fmtNum(n)), h("span", null, label)); }

  function section(title, sub) {
    var s = h("section", { class: "section" }, h("header", null, h("h2", null, title), sub ? h("p", null, sub) : null));
    for (var i = 2; i < arguments.length; i++) append(s, arguments[i]);
    return s;
  }

  function cellTitle(c) {
    var t = c.title + " (" + c.id + "): " + (STATUS_LABEL[c.status] || c.status);
    if (c.findings) t += ", " + plural(c.findings, "finding") + ", worst " + c.worst;
    return t;
  }

  function matrix(ins, id) {
    var panel = h("div", { class: "panel" });
    var m = h("div", { class: "matrix" });
    ins.categories.forEach(function (c) {
      var failed = c.by_status.findings || 0;
      var cells = h("div", { class: "cells" }, c.cells.map(function (cell) {
        var cls = "cell " + (cell.status === "findings" ? cell.worst || "low" : cell.status);
        return h("a", { class: cls, href: hashFor({ id: id, tab: "scenarios", sub: cell.id }), title: cellTitle(cell), "aria-label": cellTitle(cell) });
      }));
      var rate = c.by_status.error === c.scenarios ? "all errored" : failed + " of " + c.scenarios;
      append(m, h("div", { class: "mrow" },
        h("div", { class: "cat", title: c.category }, h("a", { href: hashFor({ id: id, tab: "scenarios", q: { cat: c.category } }), style: "color:inherit" }, c.category),
          h("small", null, (ins.pack_categories && ins.pack_categories.indexOf(c.category) >= 0 ? "attack pack, " : "") + (c.findings ? plural(c.findings, "finding") + (c.worst ? ", worst " + c.worst : "")
            : (c.by_status.passed === c.scenarios ? "all passed" : c.by_status.error === c.scenarios ? "not tested"
              : c.by_status.inconclusive === c.scenarios ? "not tested, all inconclusive" : "no findings"))
            + (c.by_status.inconclusive && c.by_status.inconclusive !== c.scenarios ? ", " + c.by_status.inconclusive + " inconclusive" : ""))),
        cells, h("div", { class: "rate", title: "Scenarios with findings" }, rate)));
    });
    append(panel, m);
    append(panel, h("div", { class: "legend" },
      SEV.map(function (s) { return h("span", null, h("i", { class: "cell " + s }), "Worst finding " + s); }),
      h("span", null, h("i", { class: "cell passed" }), "Passed"),
      h("span", null, h("i", { class: "cell error" }), "Error"),
      h("span", null, h("i", { class: "cell not_observable" }), "Not observable"),
      h("span", null, h("i", { class: "cell inconclusive" }), "Inconclusive, attack not delivered")));
    return panel;
  }

  function owaspBars(list, id) {
    var max = Math.max.apply(null, list.map(function (o) { return o.findings; }).concat([1]));
    return h("div", { class: "panel bars" }, list.map(function (o) {
      var row = h("div", { class: "bar" + (o.findings ? "" : " zero") },
        h("span", { class: "id" }, o.id),
        h("div", { class: "label" }, h("div", null, o.findings ? h("a", { href: hashFor({ id: id, tab: "findings", q: { owasp: o.id } }), style: "color:inherit" }, o.name) : o.name),
          h("div", { class: "track" }, h("div", { class: "fill", style: "width:" + (100 * o.findings / max) + "%;--c:var(--" + (o.worst || "low") + ")" }))),
        h("span", { class: "n" }, o.findings ? String(o.findings) : "0"));
      return row;
    }));
  }

  function vectorBars(list) {
    return h("div", { class: "panel bars" }, list.map(function (v) {
      var pct = v.scenarios ? 100 * v.with_findings / v.scenarios : 0;
      return h("div", { class: "bar" + (v.with_findings ? "" : " zero"), style: "grid-template-columns:minmax(0,1fr) 72px" },
        h("div", { class: "label" }, h("div", null, VECTOR_LABEL[v.vector] || v.vector),
          h("div", { class: "track" }, h("div", { class: "fill", style: "width:" + pct + "%;--c:var(--ink-2)" }))),
        h("span", { class: "n", title: "Scenarios with findings" + (v.inconclusive ? "; " + v.inconclusive + " inconclusive (not delivered)" : "") }, v.with_findings + " of " + v.scenarios));
    }));
  }

  function rulesTable(rules, id) {
    return h("div", { class: "panel", style: "overflow-x:auto" }, h("table", null,
      h("thead", null, h("tr", null, h("th", null, "Rule"), h("th", null, "Worst"), h("th", { class: "num" }, "Findings"), h("th", { class: "num" }, "Scenarios"))),
      h("tbody", null, rules.map(function (r) {
        var href = hashFor({ id: id, tab: "findings", q: { rule: r.rule } });
        return h("tr", { class: "link", onclick: function () { location.hash = href; } },
          h("td", null, h("a", { href: href }, h("code", null, r.rule)), r.source === "model-assisted" ? [" ", h("span", { class: "tag" }, "model-assisted")] : null),
          h("td", null, r.worst ? sevLabel(r.worst) : "–"), h("td", { class: "num" }, String(r.findings)), h("td", { class: "num" }, String(r.scenarios)));
      }))));
  }

  function toolClass(t) {
    if (t.forbidden) return h("span", { class: "sev critical" }, "Forbidden action");
    if (!t.allowed) return h("span", { class: "sev high" }, "Not in allowed_tools");
    return h("span", { class: "dim" }, "Allowed");
  }

  function toolsTable(tools) {
    return h("div", { class: "panel", style: "overflow-x:auto" }, h("table", null,
      h("thead", null, h("tr", null, h("th", null, "Tool"), h("th", null, "Policy"), h("th", { class: "num" }, "Calls"), h("th", { class: "num" }, "Scenarios"))),
      h("tbody", null, tools.map(function (t) {
        return h("tr", null, h("td", null, h("code", null, ident(t.tool))), h("td", null, toolClass(t)),
          h("td", { class: "num" }, String(t.calls)), h("td", { class: "num" }, String(t.scenarios)));
      }))));
  }

  function pct(x) { return x === null || x === undefined ? "–" : Math.round(x * 100) + "%"; }

  function agentReported(rep) {
    var v = (rep.run_config || {}).agent_reported;
    return Array.isArray(v) ? v.filter(function (a) { return a && typeof a === "object"; }) : [];
  }

  function describeAgent(a) {
    var head = [a.name, a.version].filter(Boolean).join(" ");
    return [head].concat(["backend", "model", "configuration"].filter(function (k) { return a[k]; })
      .map(function (k) { return k + " " + a[k]; })).filter(Boolean).join(", ");
  }

  function provenanceNote(reported) {
    if (!reported.length) return "Verdicts describe this agent build on this run; the report does not record which model, or whether a scripted stand-in, made the agent's decisions (" + PROVENANCE_HINT + ").";
    if (reported.some(function (a) { return a.backend === "scripted"; })) return "The agent reported a scripted backend: a test double made its decisions, so these verdicts test the pipeline and say nothing about any model.";
    return "Verdicts describe this agent build on this run, as the agent reported it (" + reported.map(describeAgent).join("; ") + "). A model run is one observation, not a rate.";
  }

  function evaluationPanel(ins, id) {
    var e = ins.evaluation;
    var dl = h("dl", { class: "kv" });
    function row(k, v) { append(dl, [h("dt", null, k), h("dd", null, v)]); }
    row("Tested", e.tested + " of " + plural(e.scenarios, "scenario") + " (" + pct(e.coverage) + "): the agent was attacked and judged");
    row("With findings", e.tested ? e.with_findings + " of " + e.tested + " tested (" + pct(e.finding_rate) + ")" : "Nothing was tested");
    row("Passed", e.tested ? e.passed + " of " + e.tested + " tested" : "–");
    if (e.inconclusive) row("Inconclusive", h("a", { href: hashFor({ id: id, tab: "scenarios", q: { status: "inconclusive" } }) }, plural(e.inconclusive, "scenario")));
    if (e.errors) row("Errors", h("a", { href: hashFor({ id: id, tab: "scenarios", q: { status: "error" } }) }, plural(e.errors, "scenario")));
    if (e.not_observable) row("Not observable", h("a", { href: hashFor({ id: id, tab: "scenarios", q: { status: "not_observable" } }) }, plural(e.not_observable, "scenario")));
    var goals = ins.attack_goals || [];
    if (goals.length) {
      var scen = uniq(goals.map(function (g) { return g.scenario_id; })).length;
      row("Attack goals reached", h("a", { href: hashFor({ id: id, tab: "findings", q: { rule: "attack_goal_achieved" } }) }, plural(goals.length, "finding") + " in " + plural(scen, "scenario")));
    }
    return h("div", { class: "panel" }, dl,
      h("p", { class: "note", style: "padding:0 18px 14px;margin:0" }, "Errored, inconclusive and not-observable scenarios measured nothing and are left out of the rates. "
        + provenanceNote(ins.reported || [])));
  }

  // "open_email result #18, tool result 6 of 7"
  function deliveryText(g) {
    if (g.delivered_seq === null || g.delivered_seq === undefined) return "Not tracked by this scenario";
    var where = (g.delivered_tool || "tool") + " result #" + g.delivered_seq;
    if (g.delivered_in_result) where += ", tool result " + g.delivered_in_result + (g.tool_results ? " of " + g.tool_results : "");
    return where;
  }

  function actionText(g) {
    if (g.action_seq === null || g.action_seq === undefined) return "–";
    var t = (g.action_tool || "tool") + " call #" + g.action_seq;
    if (g.calls_in_between === 0) t += ", the next call after delivery";
    else if (g.calls_in_between) t += ", after " + plural(g.calls_in_between, "other call");
    return t;
  }

  function attackGoalsTable(goals, id) {
    return h("div", { class: "panel", style: "overflow-x:auto" }, h("table", null,
      h("thead", null, h("tr", null, h("th", null, "Severity"), h("th", null, "Attack goal, then payload delivered → goal reached"))),
      h("tbody", null, goals.map(function (g) {
        var href = hashFor({ id: id, tab: "scenarios", sub: g.scenario_id, q: { f: g.finding_id } });
        var path = (typeof g.delivered_seq === "number" ? (g.delivered_tool || "result") + " #" + g.delivered_seq
          + (g.delivered_in_result ? " (result " + g.delivered_in_result + (g.tool_results ? " of " + g.tool_results : "") + ")" : "") : "delivery not tracked")
          + " → " + (g.action_tool || "call") + " #" + g.action_seq;
        return h("tr", { class: "link", onclick: function (e) { if (e.target.tagName !== "A") location.hash = href; } },
          h("td", null, sevLabel(g.severity)),
          h("td", null, h("a", { href: href }, g.goal), h("div", { class: "item-sub" }, g.scenario_id),
            h("div", { class: "mono dim", style: "font-size:12px", title: deliveryText(g) + "; " + actionText(g) }, path)));
      }))));
  }

  // seq -> labels for the trace: where the payload arrived and which call reached the attacker's goal
  function goalMarks(goals) {
    var marks = {};
    goals.forEach(function (g) {
      if (typeof g.delivered_seq === "number") (marks[g.delivered_seq] = marks[g.delivered_seq] || []).push({ kind: "delivered", text: "Payload delivered" });
      if (typeof g.action_seq === "number") (marks[g.action_seq] = marks[g.action_seq] || []).push({ kind: "goal", text: "Attack goal reached: " + g.goal, severity: g.severity });
    });
    return marks;
  }

  function attackTimeline(g, firstSeq) {
    var steps = [h("li", null, h("b", null, "Task given"), " #" + firstSeq + ", the user's request")];
    if (typeof g.delivered_seq === "number") {
      steps.push(h("li", null, h("b", null, "Payload delivered"), " in the " + deliveryText(g)
        + (g.delivered_in_result > 1 ? "; " + plural(g.delivered_in_result - 1, "earlier tool result") + " carried no payload" : "")));
    } else {
      steps.push(h("li", null, h("b", null, "Payload delivered"), " (this scenario does not track delivery; the content was part of what the agent read)"));
    }
    steps.push(h("li", null, h("b", null, "Attack goal reached"), " by the " + actionText(g) + ": " + g.goal));
    return h("ol", { class: "timeline" }, steps);
  }

  function goalsFor(data, scenarioId) {
    return ((data.insights || {}).attack_goals || []).filter(function (g) { return g.scenario_id === scenarioId; });
  }

  function runFacts(rep, ins) {
    var u = ins.usage;
    var dl = h("dl", { class: "kv" });
    function row(k, v) { append(dl, [h("dt", null, k), h("dd", null, v)]); }
    row("Steps", fmtNum(u.steps));
    row("Tool calls", fmtNum(u.tool_calls));
    row("Tokens", u.total_tokens ? fmtNum(u.total_tokens) + " (" + fmtNum(u.prompt_tokens) + " prompt, " + fmtNum(u.completion_tokens) + " completion)" : "Not reported by the agent");
    row("Cost", u.cost_usd !== null ? "$" + u.cost_usd.toFixed(4)
      : (u.cost_known_scenarios ? "Known for " + u.cost_known_scenarios + " of " + (u.cost_known_scenarios + u.cost_unknown_scenarios) + " scenarios" : "Unknown (no cost reported and no agent.pricing)"));
    row("Agent time", u.duration_s.toFixed(2) + " s");
    var outcomes = Object.keys(ins.outcomes).map(function (k) { return ins.outcomes[k] + " " + k.replace("_", " "); }).join(", ");
    row("Outcomes", outcomes || "–");
    var limits = Object.keys(ins.limits);
    if (limits.length) row("Stopped by limit", limits.map(function (k) { return k + " (" + ins.limits[k] + ")"; }).join(", "));
    if (ins.multi_session_scenarios) row("Multi-session", plural(ins.multi_session_scenarios, "scenario") + " ran follow-up conversations");
    if (ins.actors.length) row("Agents seen", ins.actors.map(function (a) { return a.actor; }).join(", "));
    if (ins.model_assisted) row("Model-assisted", plural(ins.model_assisted, "finding") + " from the judge");
    return h("div", { class: "panel" }, dl);
  }

  function policyArg(data) {
    var p = (data.report.run_config || {}).policy_path;
    return p ? shellQuote(p) : "agentsec.yaml";
  }

  function reproduce(data) {
    var run = data.report.run_config || {};
    var box = h("div");
    if (run.replay) append(box, h("p", { class: "dim", style: "margin:0 0 4px;font-size:13px" }, "Re-run the same scenarios:"), cmd(run.replay));
    if (data.report.findings.length) {
      append(box, h("p", { class: "dim", style: "margin:12px 0 4px;font-size:13px" }, "Check whether these findings still reproduce:"),
        cmd("agentsec replay " + shellQuote(data.entry.display_path) + " --policy " + policyArg(data)),
        h("p", { class: "note" }, "Each finding comes back REPRODUCED, NOT REPRODUCED, INCONCLUSIVE (the payload did not reach the agent this time, so it is not fixed; exit code 2) or ERROR."));
    }
    if (!run.policy_path) append(box, h("p", { class: "note" }, "The report does not record the policy path, so agentsec.yaml is assumed."));
    return box;
  }

  /* ------------------------------------------------------------------ findings */

  function matchesQuery(f, q) {
    if (!q) return true;
    q = q.toLowerCase();
    return [f.title, f.id, f.rule, f.observed_action, f.policy_violated, f.input].some(function (s) {
      return s && String(s).toLowerCase().indexOf(q) >= 0;
    });
  }

  function filterFindings(findings, q) {
    var sevs = q.sev ? q.sev.split(",") : null;
    return findings.filter(function (f) {
      return (!sevs || sevs.indexOf(f.severity) >= 0) && (!q.cat || f.category === q.cat) && (!q.rule || f.rule === q.rule)
        && (!q.owasp || (f.owasp || []).some(function (o) { return o.id === q.owasp; }))
        && (!q.source || f.source === q.source) && (!q.scenario || f.scenario_id === q.scenario) && matchesQuery(f, q.q);
    }).sort(bySeverity);
  }

  function uniq(list) { return list.filter(function (v, i) { return v && list.indexOf(v) === i; }).sort(); }

  function filterBar(r, items, opts) {
    var q = r.q;
    var bar = h("div", { class: "filters", role: "search" });
    function go(change) {
      var nq = Object.assign({}, q, change);
      location.hash = hashFor({ id: r.id, tab: r.tab, sub: opts.keepSub ? r.sub : null, q: nq });
    }
    if (opts.chips) {
      var active = q[opts.chips.key] ? q[opts.chips.key].split(",") : [];
      opts.chips.values.forEach(function (v) {
        var n = items.filter(function (x) { return x[opts.chips.field] === v; }).length;
        if (!n && active.indexOf(v) < 0) return;
        var on = active.indexOf(v) >= 0;
        append(bar, h("button", { class: "chip", type: "button", "aria-pressed": on ? "true" : "false", onclick: function () {
          var next = on ? active.filter(function (x) { return x !== v; }) : active.concat([v]);
          var change = {}; change[opts.chips.key] = next.join(",");
          go(change);
        } }, opts.chips.label(v), h("span", { class: "n" }, String(n))));
      });
    }
    (opts.selects || []).forEach(function (s) {
      if (s.values.length < 2 && !q[s.key]) return;
      var sel = h("select", { "aria-label": s.label, onchange: function () { var c = {}; c[s.key] = sel.value; go(c); } },
        h("option", { value: "" }, s.label), s.values.map(function (v) {
          return h("option", { value: v, selected: q[s.key] === v ? "selected" : null }, s.name ? s.name(v) : v);
        }));
      append(bar, sel);
    });
    var input = h("input", { type: "search", placeholder: opts.placeholder, "aria-label": opts.placeholder, value: q.q || "" });
    var timer;
    input.addEventListener("input", function () {
      clearTimeout(timer);
      timer = setTimeout(function () { go({ q: input.value }); }, 250);
    });
    append(bar, input);
    var anyFilter = Object.keys(q).some(function (k) { return k !== "f" && q[k]; });
    if (anyFilter) append(bar, h("button", { class: "btn small", type: "button", onclick: function () { location.hash = hashFor({ id: r.id, tab: r.tab, sub: r.sub }); } }, "Clear filters"));
    return bar;
  }

  function viewFindings(data, r) {
    var rep = data.report;
    var all = rep.findings.slice();
    if (!all.length) {
      return h("div", { class: "panel" }, emptyState("No findings",
        data.isMcp ? "No static check matched these definitions. The checks cover known patterns; this is not proof the server is safe."
          : "No deterministic check fired in any scenario. See the scenarios tab for what ran."));
    }
    var list = filterFindings(all, r.q);
    var selected = r.sub && data.findingById[r.sub] ? data.findingById[r.sub] : list[0];
    var owaspIds = uniq([].concat.apply([], all.map(function (f) { return (f.owasp || []).map(function (o) { return o.id; }); })));
    var owaspNames = {};
    all.forEach(function (f) { (f.owasp || []).forEach(function (o) { owaspNames[o.id] = o.name; }); });

    var wrap = h("div");
    append(wrap, filterBar(r, all, {
      placeholder: "Search findings",
      keepSub: false,
      chips: { key: "sev", field: "severity", values: SEV, label: function (s) { return h("span", { class: "sev " + s }, s.charAt(0).toUpperCase() + s.slice(1)); } },
      selects: [
        { key: "cat", label: "All categories", values: uniq(all.map(function (f) { return f.category; })) },
        { key: "rule", label: "All rules", values: uniq(all.map(function (f) { return f.rule; })) },
        { key: "owasp", label: "All OWASP categories", values: owaspIds, name: function (v) { return v + " " + (owaspNames[v] || ""); } },
        { key: "source", label: "All sources", values: uniq(all.map(function (f) { return f.source; })) }
      ]
    }));

    var listEl = h("div", { class: "list-scroll" });
    list.forEach(function (f) {
      append(listEl, h("a", { class: "item" + (selected && f.id === selected.id ? " active" : ""), href: hashFor({ id: r.id, tab: "findings", sub: f.id, q: r.q }),
        "aria-current": selected && f.id === selected.id ? "true" : null },
        h("div", { class: "item-top" }, sevLabel(f.severity), f.irreversible ? irreversibleTag() : null, h("span", { class: "muted", style: "font-size:12px" }, f.category)),
        h("div", { class: "item-title" }, f.title),
        h("div", { class: "item-sub", title: f.id }, f.scenario_id)));
    });
    if (!list.length) append(listEl, h("div", { class: "empty" }, h("p", null, "No findings match these filters.")));
    var left = h("div", { class: "list", "data-list": "findings" },
      h("div", { class: "list-head" }, h("span", null, list.length === all.length ? plural(all.length, "finding") : list.length + " of " + all.length), h("span", null, "j / k to move")), listEl);
    var right = selected && list.indexOf(selected) >= 0 || (selected && r.sub) ? findingDetail(data, selected) : h("div", { class: "detail" }, emptyState("Select a finding"));
    append(wrap, h("div", { class: "split" }, left, right));
    return wrap;
  }

  function irreversibleTag() {
    return h("span", { class: "tag irreversible", title: "A call in this finding cannot be undone" }, "Irreversible");
  }

  function findingDetail(data, f) {
    var id = data.entry.id;
    var meta = h("div", { class: "meta" }, sevLabel(f.severity), h("span", { class: "tag" }, h("code", null, f.rule)),
      h("span", { class: "tag" }, f.category),
      f.irreversible ? irreversibleTag() : null,
      (f.owasp || []).map(function (o) { return h("span", { class: "tag accent", title: o.name }, o.id + " " + o.name); }),
      f.source === "model-assisted" ? h("span", { class: "tag warn" }, "Model-assisted" + (f.confidence !== undefined ? ", confidence " + f.confidence : "")) : null);
    var d = h("article", { class: "detail", "aria-label": "Finding detail" },
      h("div", { class: "detail-head" }, meta, h("h2", null, f.title),
        data.isMcp ? h("div", { class: "dim", style: "font-size:13px" }, "Definition ", h("a", { href: hashFor({ id: id, tab: "items", sub: f.scenario_id }) }, h("code", null, ident(f.scenario_id))))
          : h("div", { class: "dim", style: "font-size:13px" }, "Scenario ", h("a", { href: hashFor({ id: id, tab: "scenarios", sub: f.scenario_id, q: { f: f.id } }) }, h("code", null, f.scenario_id)),
            data.scenarioById[f.scenario_id] ? [" ", h("span", { class: "muted" }, data.scenarioById[f.scenario_id].title)] : null)));
    append(d, block(data.isMcp ? "What the check found" : "What the agent did", h("div", { class: "quote code" }, f.observed_action)));
    append(d, block("Policy violated", h("p", null, h("code", null, f.policy_violated))));
    if (f.input) append(d, block(data.isMcp ? "Checked" : "Input", h("div", { class: "quote" }, f.input)));
    var goal = f.rule === "attack_goal_achieved" ? goalsFor(data, f.scenario_id).filter(function (g) { return g.finding_id === f.id; })[0] : null;
    if (goal) {
      var sc = data.scenarioById[f.scenario_id];
      var first = sc && sc.trace && sc.trace.events && sc.trace.events.length ? sc.trace.events[0].seq : 0;
      append(d, block("Attack timeline", attackTimeline(goal, first)));
    }
    append(d, block("Evidence", evidence(data, f, goal ? goalMarks([goal]) : null)));
    append(d, block("Remediation", h("p", null, f.remediation)));
    append(d, block("Reproduce", findingCommands(data, f)));
    return d;
  }

  function block(title) {
    var b = h("section", { class: "block" }, h("h3", null, title));
    for (var i = 1; i < arguments.length; i++) append(b, arguments[i]);
    return b;
  }

  function evidence(data, f, labels) {
    var ev = f.evidence || [];
    if (!ev.length) return h("p", { class: "muted" }, "No trace events attached.");
    var isEvents = ev.every(function (e) { return e && typeof e.seq === "number" && e.type; });
    if (!isEvents) {
      return h("div", null, ev.map(function (e) { return h("div", { class: "args" }, jsonView(e)); }));
    }
    var box = h("div", { class: "trace", style: "margin:0 -22px" });
    ev.forEach(function (e) { append(box, eventRow(e, { evidence: f.severity, labels: labels && labels[e.seq] })); });
    return h("div", null, box, h("a", { href: hashFor({ id: data.entry.id, tab: "scenarios", sub: f.scenario_id, q: { f: f.id } }) }, "Open the full trace"));
  }

  function findingCommands(data, f) {
    var box = h("div");
    var run = data.report.run_config || {};
    if (data.isMcp) {
      var t = run.target || "";
      append(box, cmd(/^https?:\/\//.test(t) ? "agentsec mcp scan --url " + shellQuote(t) : "agentsec mcp scan --command " + shellQuote(t)));
      if (!/^https?:\/\//.test(t)) append(box, h("p", { class: "note" }, "This command is the scan target recorded in the report. Read it before you run it."));
    } else {
      append(box, h("p", { class: "dim", style: "margin:0 0 4px;font-size:13px" }, "Replay this finding against the current agent build:"),
        cmd("agentsec replay " + shellQuote(data.entry.display_path) + " --policy " + policyArg(data) + " --finding " + shellQuote(f.id)));
      append(box, h("p", { class: "dim", style: "margin:12px 0 4px;font-size:13px" }, "Run only this scenario:"),
        cmd("agentsec test --policy " + policyArg(data) + " --seed " + run.seed + " -s " + shellQuote(f.scenario_id)));
    }
    append(box, h("div", { class: "note" }, "Finding id ", h("code", null, f.id), " ", copyButton(f.id, "Copy id")));
    return box;
  }

  function jsonView(obj) {
    return JSON.stringify(obj, null, 2);
  }

  /* ------------------------------------------------------------------ scenarios + traces */

  function viewScenarios(data, r) {
    var rep = data.report;
    var all = rep.scenarios.slice();
    var q = r.q;
    var statuses = q.status ? q.status.split(",") : null;
    var list = all.filter(function (s) {
      return (!statuses || statuses.indexOf(s.status) >= 0) && (!q.cat || s.category === q.cat) && (!q.vector || s.vector === q.vector)
        && (!q.q || [s.id, s.title].some(function (x) { return x && x.toLowerCase().indexOf(q.q.toLowerCase()) >= 0; }));
    });
    var selected = r.sub && data.scenarioById[r.sub] ? data.scenarioById[r.sub] : list[0];
    var wrap = h("div");
    append(wrap, filterBar(r, all, {
      placeholder: "Search scenarios",
      keepSub: false,
      chips: { key: "status", field: "status", values: ["findings", "error", "inconclusive", "not_observable", "passed"], label: function (s) { return statusLabel(s); } },
      selects: [
        { key: "cat", label: "All categories", values: uniq(all.map(function (s) { return s.category; })) },
        { key: "vector", label: "All vectors", values: uniq(all.map(function (s) { return s.vector; })), name: function (v) { return VECTOR_LABEL[v] || v; } }
      ]
    }));
    var listEl = h("div", { class: "list-scroll" });
    list.forEach(function (s) {
      var worst = worstOf(s.finding_ids.map(function (fid) { return (data.findingById[fid] || {}).severity; }));
      append(listEl, h("a", { class: "item" + (selected && s.id === selected.id ? " active" : ""), href: hashFor({ id: r.id, tab: "scenarios", sub: s.id, q: stripF(q) }),
        "aria-current": selected && s.id === selected.id ? "true" : null },
        h("div", { class: "item-top" }, worst ? sevLabel(worst) : statusLabel(s.status),
          worst ? h("span", { class: "muted", style: "font-size:12px" }, plural(s.finding_ids.length, "finding")) : null),
        h("div", { class: "item-title" }, s.title),
        h("div", { class: "item-sub" }, s.id)));
    });
    if (!list.length) append(listEl, h("div", { class: "empty" }, h("p", null, "No scenarios match these filters.")));
    var left = h("div", { class: "list", "data-list": "scenarios" },
      h("div", { class: "list-head" }, h("span", null, list.length === all.length ? plural(all.length, "scenario") : list.length + " of " + all.length), h("span", null, "j / k to move")), listEl);
    append(wrap, h("div", { class: "split" }, left, selected ? scenarioDetail(data, selected, q.f) : h("div", { class: "detail" }, emptyState("Select a scenario"))));
    if (q.f) {
      setTimeout(function () {
        var target = main.querySelector(".ev.evidence[data-focus]") || main.querySelector(".ev.evidence");
        if (target) target.scrollIntoView({ block: "center", behavior: matchMedia("(prefers-reduced-motion: reduce)").matches ? "auto" : "smooth" });
      }, 30);
    }
    return wrap;
  }

  function stripF(q) { var c = Object.assign({}, q); delete c.f; return c; }

  function scenarioDetail(data, s, focusFinding) {
    var id = data.entry.id;
    var t = s.trace || { events: [], usage: {} };
    var u = t.usage || {};
    var findings = s.finding_ids.map(function (fid) { return data.findingById[fid]; }).filter(Boolean).sort(bySeverity);

    // trace seq -> findings whose evidence points at it
    var marks = {};
    findings.forEach(function (f) {
      (f.evidence || []).forEach(function (e) {
        if (typeof e.seq === "number") (marks[e.seq] = marks[e.seq] || []).push(f);
      });
    });

    var d = h("article", { class: "detail", "aria-label": "Scenario detail" },
      h("div", { class: "detail-head" },
        h("div", { class: "meta" }, statusLabel(s.status), h("span", { class: "tag" }, s.category),
          h("span", { class: "tag", title: "Where the adversarial content was delivered" }, "Via " + (VECTOR_LABEL[s.vector] || s.vector).toLowerCase())),
        h("h2", null, s.title), h("div", { class: "dim mono", style: "font-size:12.5px" }, s.id)));

    var dl = h("dl", { class: "kv", style: "padding:14px 22px" });
    function row(k, v) { append(dl, [h("dt", null, k), h("dd", null, v)]); }
    row("Outcome", t.outcome === "limit_exceeded" ? "Stopped by " + (t.limit || "a limit") : t.outcome === "error" ? "Error" : "Completed");
    if (t.error) row("Error", h("span", { style: "color:var(--err)" }, t.error));
    row("Steps and tool calls", fmtNum(u.steps) + " steps, " + plural(u.tool_calls || 0, "tool call"));
    if (u.total_tokens) row("Tokens", fmtNum(u.total_tokens));
    if (u.cost_usd !== null && u.cost_usd !== undefined) row("Cost", "$" + Number(u.cost_usd).toFixed(4));
    row("Duration", (t.duration_s || 0).toFixed(3) + " s");
    append(d, h("div", { class: "block", style: "padding:0" }, dl));

    if (s.status === "not_observable") {
      append(d, block("Why not observable", h("p", null, "This scenario needs the system to report which agent acted (actor attribution), and the trace has none. It is not counted as passed.")));
    }
    if (s.status === "inconclusive") {
      append(d, block("Why inconclusive", h("p", null, "This scenario counts as tested only once its adversarial content appears in a tool result the agent received. In this run "
        + INCONCLUSIVE_WHY + ". It is not counted as passed, and a finding from an earlier run is not counted as fixed. The trace below shows how far the agent got."),
        h("p", { class: "note" }, "To test it, give the agent a task that leads it to the poisoned item, or replay the scenario; with a real model, run it more than once.")));
    }
    var goals = goalsFor(data, s.id);
    if (goals.length) {
      append(d, block(goals.length > 1 ? "Attack timelines" : "Attack timeline", h("div", null, goals.map(function (g) {
        return attackTimeline(g, t.events.length ? t.events[0].seq : 0);
      }))));
    }
    var labels = goalMarks(goals);
    var dv = s.delivery;
    if (dv && typeof dv.seq === "number" && !goals.some(function (g) { return g.delivered_seq === dv.seq; })) {
      (labels[dv.seq] = labels[dv.seq] || []).push({ kind: "delivered", text: "Payload delivered" });
    }
    if (Array.isArray(s.attack_goals) && s.attack_goals.length) {
      append(d, block("Attack goals", h("div", null,
        dv ? h("p", { style: "margin:0 0 8px" }, dv.delivered ? "Payload delivered in the " + (dv.tool || "tool") + " result #" + dv.seq + "."
          : "The payload never reached the agent, so no goal was tested.") : null,
        h("ul", { class: "timeline", style: "list-style:none;padding:0" }, s.attack_goals.map(function (g) {
          var st = g.achieved === true ? h("span", { class: "sev " + (g.severity || "critical") }, "Achieved")
            : g.achieved === false ? h("span", { class: "status passed" }, "Not achieved") : h("span", { class: "status inconclusive" }, "Not tested");
          return h("li", null, st, " ", g.description,
            (g.tools || []).length ? h("span", { class: "muted" }, " via " + g.tools.join(", ")) : null);
        })))));
    }
    if (findings.length) {
      append(d, block("Findings", h("div", null, findings.map(function (f) {
        return h("div", { style: "display:flex;gap:10px;align-items:baseline;padding:3px 0" }, sevLabel(f.severity),
          h("a", { href: hashFor({ id: id, tab: "findings", sub: f.id }) }, f.title), f.irreversible ? irreversibleTag() : null);
      }))));
    }
    var phases = {};
    t.events.forEach(function (e) { if (e.meta && e.meta.phase !== undefined) phases[e.meta.phase] = true; });
    var multi = Object.keys(phases).length > 1;
    var trace = h("div", { class: "trace" });
    var lastPhase = null;
    t.events.forEach(function (e) {
      var phase = e.meta && e.meta.phase !== undefined ? e.meta.phase : 0;
      if (multi && phase !== lastPhase) {
        append(trace, h("div", { class: "phase" }, phase === 0 ? "First conversation" : "Follow-up conversation " + phase + ", empty message history"));
        lastPhase = phase;
      }
      var fs = marks[e.seq] || [];
      append(trace, eventRow(e, {
        evidence: fs.length ? worstOf(fs.map(function (f) { return f.severity; })) : null,
        findings: fs, focus: focusFinding && fs.some(function (f) { return f.id === focusFinding; }), reportId: id, labels: labels[e.seq]
      }));
    });
    append(d, h("section", { class: "block", style: "padding-left:0;padding-right:0" },
      h("h3", { style: "padding:0 22px" }, "Trace, " + plural(t.events.length, "event") + (Object.keys(marks).length ? "; highlighted events are evidence" : "")), trace));
    return d;
  }

  function eventRow(e, opts) {
    opts = opts || {};
    var meta = e.meta || {};
    var who = h("div", { class: "who" }, h("b", null, EVENT_LABEL[e.type] || e.type));
    if (e.tool_name) append(who, h("code", null, ident(e.tool_name)));
    if (meta.actor) append(who, h("span", { class: "tag accent" }, "agent " + meta.actor));
    if (meta.delegated_by) append(who, h("span", { class: "tag" }, "delegated by " + meta.delegated_by));
    append(who, h("span", null, "#" + e.seq), h("span", null, "+" + (e.t_ms || 0) + " ms"));

    var body;
    if (e.type === "tool_call") {
      body = argsView(e.arguments || {});
    } else if (e.type === "assistant_message" && !e.content) {
      body = h("div", { class: "body empty-msg" }, "No text; the agent asked for tools.");
    } else {
      body = h("div", { class: "body" }, e.content || "");
    }
    var row = h("div", { class: "ev " + e.type + (opts.evidence ? " evidence " + opts.evidence : ""), "data-focus": opts.focus ? "1" : null },
      h("span", { class: "glyph", "aria-hidden": "true" }, EVENT_GLYPH[e.type] || "·"),
      h("div", { style: "min-width:0" }, who, body));
    var flags = [];
    (opts.labels || []).forEach(function (l) {
      flags.push(l.kind === "goal" ? h("span", { class: "tag mark-goal" }, h("span", { class: "sev " + (l.severity || "critical") }, l.text))
        : h("span", { class: "tag mark-delivered" }, l.text));
    });
    if (meta.over_budget) flags.push(h("span", { class: "tag warn" }, "Over the tool-call budget; not executed"));
    if (meta.executed_by_agent) flags.push(h("span", { class: "tag" }, "Executed by the agent and reported to AgentSec"));
    (opts.findings || []).forEach(function (f) {
      flags.push(h("a", { class: "tag", href: hashFor({ id: opts.reportId, tab: "findings", sub: f.id }) }, h("span", { class: "sev " + f.severity }, f.title)));
    });
    if (flags.length) append(row.lastChild, h("div", { class: "flag" }, flags));
    if (e.type === "tool_result" && (e.content || "").length > 700) {
      var btn = h("button", { class: "btn small more", type: "button" }, "Show all");
      btn.addEventListener("click", function () {
        row.classList.toggle("expanded");
        btn.textContent = row.classList.contains("expanded") ? "Show less" : "Show all";
      });
      append(row.lastChild, btn);
    }
    return row;
  }

  function argsView(args) {
    var box = h("div", { class: "args" });
    var keys = Object.keys(args);
    if (!keys.length) { append(box, h("span", { class: "k" }, "(no arguments)")); return box; }
    keys.forEach(function (k, i) {
      var v = args[k];
      append(box, h("span", { class: "k" }, k + ": "), typeof v === "string" ? v : JSON.stringify(v, null, 2), i < keys.length - 1 ? "\n" : null);
    });
    return box;
  }

  /* ------------------------------------------------------------------ policy */

  function viewPolicy(data) {
    var p = (data.report.run_config || {}).policy || {};
    var a = p.agent || {};
    var wrap = h("div", { class: "grid2" });
    var left = h("div"), right = h("div");

    function kv(rows) {
      var dl = h("dl", { class: "kv" });
      rows.forEach(function (r) { if (r) append(dl, [h("dt", null, r[0]), h("dd", null, r[1])]); });
      return h("div", { class: "panel" }, dl);
    }
    function val(v) { return v === null || v === undefined ? h("span", { class: "muted" }, "not set") : String(v); }

    append(left, section("Agent", null, kv([
      ["Name", a.name], ["Endpoint", h("code", null, a.endpoint || "")], ["Model", val(a.model)],
      ["Declares tools", a.declare_tools ? "Yes, allowed tools plus forbidden actions as decoys" : "No"],
      ["Streaming", a.stream ? "Yes" : "No"], ["Timeout", a.timeout_s + " s"],
      a.retrieval_tools && a.retrieval_tools.length ? ["Retrieval tools", a.retrieval_tools.join(", ")] : null,
      ["API key env", val(a.api_key_env)]
    ])));

    var effects = p.tool_effects || {};
    var allowed = p.allowed_tools || [];
    var toolRows = allowed.map(function (t) {
      return h("tr", null, h("td", null, h("code", null, ident(t))), h("td", null, "Allowed"),
        h("td", null, (effects[t] || []).map(function (e) { return [h("span", { class: "tag" }, e), " "]; })));
    }).concat((p.forbidden_actions || []).map(function (t) {
      return h("tr", null, h("td", null, h("code", null, ident(t))), h("td", null, h("span", { class: "sev critical" }, "Forbidden")),
        h("td", null, (effects[t] || []).map(function (e) { return [h("span", { class: "tag" }, e), " "]; })));
    }));
    append(left, section("Tools", allowed.length ? "Undeclared effects mean the authority checks stay silent for that tool." : "No allowed_tools: every non-forbidden tool is permitted.",
      h("div", { class: "panel", style: "overflow-x:auto" }, h("table", null,
        h("thead", null, h("tr", null, h("th", null, "Tool"), h("th", null, "Policy"), h("th", null, "Declared effects"))),
        h("tbody", null, toolRows.length ? toolRows : h("tr", null, h("td", { colspan: "3", class: "muted" }, "No tools declared.")))))));

    var roles = p.agent_roles || {};
    if (Object.keys(roles).length) {
      append(left, section("Agent roles", null, h("div", { class: "panel", style: "overflow-x:auto" }, h("table", null,
        h("thead", null, h("tr", null, h("th", null, "Agent"), h("th", null, "Effects"), h("th", null, "Tools"), h("th", null, "Can delegate to"))),
        h("tbody", null, Object.keys(roles).map(function (n) {
          var r = roles[n];
          return h("tr", null, h("td", null, h("code", null, n)), h("td", null, (r.effects || []).join(", ") || "–"),
            h("td", null, (r.tools || []).join(", ") || "–"), h("td", null, (r.can_delegate_to || []).join(", ") || "–"));
        }))))));
    }

    var lim = p.limits || {};
    append(right, section("Limits", null, kv(Object.keys(lim).map(function (k) { return [h("code", null, k), val(lim[k])]; }))));
    if (p.spend_limits) {
      var sl = p.spend_limits;
      append(right, section("Spend limits", null, kv([["Tools", sl.tools.join(", ")], ["Amount field", h("code", null, sl.amount_field)],
        ["Per transaction", val(sl.max_transaction)], ["Total", val(sl.max_total)], ["Currency", val(sl.currency)]])));
    }
    if (p.address_allowlist) {
      var al = p.address_allowlist;
      append(right, section("Address allowlist", null, kv([["Tools", al.tools.join(", ")], ["Address field", h("code", null, al.address_field)],
        ["Addresses", String(al.addresses_count)], ["Case sensitive", al.case_sensitive ? "Yes" : "No"]])));
    }
    append(right, section("Tests", null, kv([
      ["Categories", (p.tests && p.tests.length ? p.tests : ["all built-in categories"]).map(function (t) { return [h("span", { class: "tag" }, t), " "]; })],
      ["Attack packs", p.attack_packs && p.attack_packs.length ? p.attack_packs.join(", ") : val(null)],
      ["Judge", p.judge ? (p.judge.model || "configured") + " at " + p.judge.endpoint + " (" + (p.judge.checks || []).join(", ") + ")" : val(null)],
      ["Secrets", plural(p.secrets_count || 0, "configured secret") + "; values are never written to reports"],
      ["Policy file hash", h("code", { style: "overflow-wrap:anywhere" }, p.source_sha256 || "unknown")]
    ])));
    append(wrap, left, right);
    return wrap;
  }

  /* ------------------------------------------------------------------ MCP scan */

  function viewMcpOverview(data) {
    var rep = data.report, ins = data.insights, sum = rep.summary, id = data.entry.id;
    var wrap = h("div");
    var counts = [plural(sum.tools || 0, "tool")];
    if (sum.resources) counts.push(plural(sum.resources, "resource"));
    if (sum.prompts) counts.push(plural(sum.prompts, "prompt"));
    var withF = ins.items.filter(function (i) { return i.findings; }).length;
    var head = sum.findings ? plural(sum.findings, "finding") + " across " + withF + " of " + plural(ins.items.length, "definition") + "."
      : "No static check matched the server's definitions.";
    append(wrap, h("div", { class: "verdict-wrap" }, h("div", null, h("p", { class: "verdict" }, head),
      h("p", { class: "verdict-sub" }, "The scan listed " + counts.join(", ") + " and checked their definitions without calling, reading or fetching any of them. Static checks cover known patterns; a clean scan is not proof the server is safe.")),
      h("div", { class: "tally" }, tallyItem(sum.tools || 0, "Tools"), tallyItem(sum.resources || 0, "Resources"), tallyItem(sum.prompts || 0, "Prompts"), tallyItem(sum.findings, "Findings"))));
    if (sum.findings) {
      var bar = h("div", { class: "sevbar" }), key = h("div", { class: "sevkey" });
      SEV.forEach(function (s) {
        var n = sum.by_severity[s] || 0;
        if (n) append(bar, h("span", { class: "bg-" + s, style: "flex:" + n }));
        append(key, h("a", { href: hashFor({ id: id, tab: "findings", q: { sev: s } }), class: "sev " + s, style: n ? null : "opacity:.5" }, s.charAt(0).toUpperCase() + s.slice(1) + " ", h("b", null, String(n))));
      });
      append(wrap, h("div", { class: "section" }, bar, key));
    }
    var left = h("div"), right = h("div");
    append(left, section("Definitions", null, mcpTable(data, ins.items.slice(0, 50))));
    if (ins.rules.length) append(left, section("Checks that fired", null, rulesTable(ins.rules, id)));
    append(right, section("OWASP agentic categories", null, owaspBars(ins.owasp, id)));
    append(right, section("Scan again", null, findingCommands(data, { id: "", scenario_id: "" }).firstChild,
      h("p", { class: "note" }, "Pin the definitions with --pin-write and compare later scans with --pin to catch changed definitions (rug pulls).")));
    append(wrap, h("div", { class: "grid2" }, left, right));
    return wrap;
  }

  function mcpTable(data, items) {
    var id = data.entry.id;
    return h("div", { class: "panel", style: "overflow-x:auto" }, h("table", null,
      h("thead", null, h("tr", null, h("th", null, "Definition"), h("th", null, "Kind"), h("th", null, "Worst"), h("th", { class: "num" }, "Findings"))),
      h("tbody", null, items.map(function (it) {
        var href = hashFor({ id: id, tab: "items", sub: it.id });
        return h("tr", { class: "link", onclick: function () { location.hash = href; } },
          h("td", null, h("a", { href: href }, h("code", null, ident(it.title || it.id))), it.description ? h("div", { class: "desc" }, truncate(it.description, 160)) : null),
          h("td", null, it.kind), h("td", null, it.worst ? sevLabel(it.worst) : h("span", { class: "status passed" }, "Clean")),
          h("td", { class: "num" }, String(it.findings)));
      }))));
  }

  function truncate(s, n) { s = String(s); return s.length > n ? s.slice(0, n - 1) + "…" : s; }

  function viewMcpItems(data, r) {
    var items = data.insights.items;
    var sel = items.find(function (i) { return i.id === r.sub; }) || items[0];
    var listEl = h("div", { class: "list-scroll" }, items.map(function (it) {
      return h("a", { class: "item" + (sel && it.id === sel.id ? " active" : ""), href: hashFor({ id: r.id, tab: "items", sub: it.id }) },
        h("div", { class: "item-top" }, it.worst ? sevLabel(it.worst) : h("span", { class: "status passed" }, "Clean"), h("span", { class: "muted", style: "font-size:12px" }, it.kind)),
        h("div", { class: "item-title" }, h("code", null, ident(it.title || it.id))));
    }));
    var left = h("div", { class: "list", "data-list": "items" }, h("div", { class: "list-head" }, h("span", null, plural(items.length, "definition")), h("span", null, "j / k to move")), listEl);
    var detail = h("div", { class: "detail" });
    if (sel) {
      append(detail, h("div", { class: "detail-head" }, h("div", { class: "meta" }, h("span", { class: "tag" }, sel.kind)), h("h2", null, h("code", { style: "font-size:17px" }, ident(sel.title || sel.id)))));
      if (sel.name) append(detail, block("Name", h("p", null, sel.name)));
      append(detail, block("Description as the server sends it", sel.description ? h("div", { class: "quote" }, sel.description) : h("p", { class: "muted" }, sel.kind === "removed" ? "No longer listed by the server." : "No description.")));
      var fs = data.report.findings.filter(function (f) { return f.scenario_id === sel.id; }).sort(bySeverity);
      append(detail, block("Findings", fs.length ? fs.map(function (f) {
        return h("div", { style: "display:flex;gap:10px;align-items:baseline;padding:3px 0" }, sevLabel(f.severity), h("a", { href: hashFor({ id: r.id, tab: "findings", sub: f.id }) }, f.title), f.irreversible ? irreversibleTag() : null);
      }) : h("p", { class: "muted" }, "No check matched this definition.")));
    }
    return h("div", { class: "split" }, left, detail);
  }

  /* ------------------------------------------------------------------ compare */

  function defaultPair(q) {
    var reps = state.reports.filter(function (r) { return !r.error; });
    function sameGroup(a, b) { return a.id !== b.id && a.kind === b.kind && a.name === b.name; }
    var head = reps.find(function (r) { return r.id === q.head; });
    if (!head) {
      // newest report that has an earlier run of the same agent or server to compare against
      head = reps.find(function (r) { return reps.some(function (o) { return sameGroup(r, o); }); }) || reps[0];
    }
    var base = reps.find(function (r) { return r.id === q.base; });
    if (!base && head) {
      base = reps.find(function (r) { return sameGroup(head, r) && (r.generated_at || "") <= (head.generated_at || ""); })
        || reps.find(function (r) { return sameGroup(head, r); })
        || reps.find(function (r) { return r.id !== head.id && r.kind === head.kind; });
    }
    return { base: base, head: head };
  }

  function warningBox(w) {
    // AgentSec warnings end in ": <id>, <id>, ..."; the explanation before the list can itself contain ": ".
    var last = w.lastIndexOf(": ");
    var i = last > 0 && w.slice(last + 2).split(", ").every(function (x) { return /^\S+$/.test(x); }) ? last : w.indexOf(": ");
    if (w.length > 220 && i > 0) {
      var items = w.slice(i + 2).split(", ");
      return h("div", { class: "warn-box" }, h("p", null, w.slice(0, i) + "."),
        h("details", null, h("summary", { style: "cursor:pointer;margin-top:4px" }, "Show " + plural(items.length, "item")),
          h("div", { class: "mono", style: "margin-top:6px;white-space:pre-wrap;overflow-wrap:anywhere" }, items.join("\n"))));
    }
    return h("div", { class: "warn-box" }, h("p", null, w.charAt(0).toUpperCase() + w.slice(1)));
  }

  function reportSelect(label, selected, onchange) {
    var sel = h("select", { "aria-label": label, onchange: function () { onchange(sel.value); } });
    groupReports(state.reports.filter(function (r) { return !r.error; })).forEach(function (g) {
      var og = h("optgroup", { label: g.name + (g.kind === "mcp_scan" ? " (MCP scan)" : "") });
      g.runs.forEach(function (r) {
        append(og, h("option", { value: r.id, selected: selected && selected.id === r.id ? "selected" : null },
          fmtTime(r.generated_at) + "  (" + r.display_path + ")"));
      });
      append(sel, og);
    });
    return sel;
  }

  function viewCompare(r) {
    document.title = "Compare runs | AgentSec";
    var page = h("div", { class: "page" });
    append(page, h("div", { class: "head" }, h("div", null, h("h1", null, "Compare runs"),
      h("div", { class: "facts" }, h("span", null, "Matches findings by id, exactly like agentsec compare: new, fixed, changed severity, unchanged.")))));
    var usable = state.reports.filter(function (x) { return !x.error; });
    if (usable.length < 2) {
      append(page, h("div", { class: "panel", style: "margin-top:24px" }, emptyState("Comparing needs two reports",
        "AgentSec overwrites report.json in its output directory on every run, so keep the run you want as a baseline in its own directory:",
        h("div", { style: "max-width:560px;margin:14px auto 0;text-align:left" },
          cmd("agentsec test --out .agentsec/baseline"), cmd("agentsec test --out .agentsec/current")),
        "Both appear here automatically, and so do report.json files you download from CI.")));
      return render(page);
    }
    var pair = defaultPair(r.q);
    function go(base, head) { location.hash = "#/compare?base=" + encodeURIComponent(base) + "&head=" + encodeURIComponent(head); }
    var baseSel = reportSelect("Baseline report", pair.base, function (v) { go(v, pair.head ? pair.head.id : ""); });
    var headSel = reportSelect("Current report", pair.head, function (v) { go(pair.base ? pair.base.id : "", v); });
    append(page, h("div", { class: "pickers", style: "margin-top:24px" },
      h("div", null, h("label", null, "Baseline, the earlier run"), baseSel),
      h("button", { class: "btn vs", type: "button", title: "Swap baseline and current", onclick: function () { if (pair.base && pair.head) go(pair.head.id, pair.base.id); } }, "Swap"),
      h("div", null, h("label", null, "Current, the newer run"), headSel)));
    var out = h("div", null, h("div", { class: "loading" }, "Comparing…"));
    append(page, out);
    render(page);
    if (!pair.base || !pair.head) {
      clear(out);
      append(out, h("div", { class: "panel" }, emptyState("Pick two reports of the same kind")));
      return;
    }
    if (pair.base.id === pair.head.id) {
      clear(out);
      append(out, h("div", { class: "panel" }, emptyState("Pick two different reports", "The baseline and the current report are the same file.")));
      return;
    }
    api("/api/compare?base=" + encodeURIComponent(pair.base.id) + "&head=" + encodeURIComponent(pair.head.id)).then(function (c) {
      if (state.route !== r) return;
      clear(out);
      append(out, compareResult(c));
    }).catch(function (err) {
      clear(out);
      append(out, h("div", { class: "panel" }, emptyState("These reports cannot be compared", err.message)));
    });
  }

  function compareResult(c) {
    var wrap = h("div");
    if (c.base.name !== c.head.name) {
      append(wrap, warningBox("these reports are from different " + (c.head.kind === "mcp_scan" ? "servers" : "agents") + " (" + c.base.name + " and " + c.head.name + "), so findings rarely line up"));
    }
    c.warnings.forEach(function (w) { append(wrap, warningBox(w)); });
    var cells = [["New", c.new.length, c.new.length ? "bad" : ""], ["Severity up", c.worse.length, c.worse.length ? "bad" : ""],
      ["Fixed", c.fixed.length, c.fixed.length ? "good" : ""], ["Severity down", c.better.length, c.better.length ? "good" : ""],
      ["Unchanged", c.unchanged.length, ""], ["Not comparable", c.not_comparable.length, ""]];
    append(wrap, h("div", { class: "delta", role: "list" }, cells.map(function (x) {
      return h("div", { class: x[2], role: "listitem" }, h("b", null, String(x[1])), h("span", null, x[0]));
    })));
    var compared = c.new.length + c.worse.length + c.fixed.length + c.better.length + c.unchanged.length;
    var verdictText = !compared && !c.not_comparable.length ? "Neither run has findings to compare." : c.regressions ? plural(c.regressions, "regression") + ": new or more severe findings in the current run."
      : (c.fixed.length ? "No regressions, and " + plural(c.fixed.length, "finding") + " fixed." : "No regressions.");
    var untested = c.not_comparable.filter(function (f) { return f.reason === "inconclusive"; }).length;
    if (untested) verdictText += " " + plural(untested, "finding") + " could not be checked: the attack never reached the agent in the current run.";
    append(wrap, h("p", { class: "verdict", style: "font-size:20px;max-width:none;margin-bottom:22px" }, verdictText));

    function group(title, items, reportId, sub, open) {
      if (!items.length) return null;
      var tbody = h("tbody", null, items.map(function (f) {
        var href = hashFor({ id: reportId, tab: "findings", sub: f.id });
        return h("tr", { class: "link", onclick: function () { location.hash = href; } },
          h("td", null, sevLabel(f.severity), f.previous_severity ? h("div", { class: "sevchange" }, "was " + f.previous_severity) : null),
          h("td", null, h("a", { href: href }, f.title), f.irreversible ? [" ", irreversibleTag()] : null, h("div", { class: "item-sub" }, f.scenario_id + (f.reason ? ", " + (NOT_COMPARABLE_WHY[f.reason] || f.reason) : ""))),
          h("td", null, h("code", null, f.rule)));
      }));
      var det = h("details", { class: "section", open: open ? "open" : null },
        h("summary", { style: "cursor:pointer;margin-bottom:10px" }, h("h2", { style: "display:inline;font-size:15px" }, title + " (" + items.length + ")"), sub ? h("span", { class: "muted", style: "margin-left:10px;font-size:12.5px" }, sub) : null),
        h("div", { class: "panel", style: "overflow-x:auto" }, h("table", null,
          h("thead", null, h("tr", null, h("th", null, "Severity"), h("th", null, "Finding"), h("th", null, "Rule"))), tbody)));
      return det;
    }
    append(wrap, group("New findings", c.new, c.head.id, null, true));
    append(wrap, group("Severity increased", c.worse, c.head.id, null, true));
    append(wrap, group("Fixed", c.fixed, c.base.id, "Shown from the baseline report", true));
    append(wrap, group("Severity decreased", c.better, c.head.id, null, false));
    append(wrap, group("Not comparable", c.not_comparable, c.base.id, "The scenario is missing, errored, inconclusive or not observable in the current run, so these cannot count as fixed", untested > 0));
    append(wrap, group("Unchanged", c.unchanged, c.head.id, null, false));
    if (c.evaluation || (c.verdict_changes && c.verdict_changes.length)) {
      append(wrap, section("Scenario verdicts", "For a baseline and a hardened build of the same agent, or any two runs: what each run measured and every scenario whose verdict changed. A scenario that became inconclusive was not tested, not fixed.",
        verdictComparison(c)));
    }
    append(wrap, section("Same comparison in the terminal or CI", null,
      cmd("agentsec compare " + shellQuote(c.base.display_path) + " " + shellQuote(c.head.display_path))));
    return wrap;
  }

  var NOT_COMPARABLE_WHY = { missing: "not in the current run", error: "errored in the current run", inconclusive: "inconclusive in the current run (attack not delivered)",
    not_observable: "not observable in the current run" };

  function verdictChange(b, hd) {
    if (!b) return ["Only in the current run", ""];
    if (!hd) return ["Only in the baseline", ""];
    if (hd === "inconclusive") return ["Not tested in the current run", "warn"];
    if (hd === "error") return ["Errored in the current run", "warn"];
    if (hd === "not_observable") return ["Not observable in the current run", "warn"];
    if (hd === "findings") return [b === "passed" ? "Now has findings" : "Tested, has findings", "bad"];
    if (hd === "passed") return [b === "findings" ? "No longer has findings" : "Tested, passed", b === "findings" ? "good" : ""];
    return [hd, ""];
  }

  function verdictComparison(c) {
    var box = h("div");
    if (c.evaluation) {
      var b = c.evaluation.base, hd = c.evaluation.head;
      var rows = [["Scenarios", "scenarios"], ["Tested", "tested"], ["With findings", "with_findings"], ["Passed", "passed"],
        ["Inconclusive", "inconclusive"], ["Errors", "errors"], ["Not observable", "not_observable"]];
      append(box, h("div", { class: "panel", style: "overflow-x:auto;margin-bottom:14px" }, h("table", null,
        h("thead", null, h("tr", null, h("th", null, ""), h("th", { class: "num" }, "Baseline"), h("th", { class: "num" }, "Current"))),
        h("tbody", null, rows.filter(function (r) { return b[r[1]] || hd[r[1]] || r[1] === "tested" || r[1] === "scenarios"; }).map(function (r) {
          return h("tr", null, h("td", null, r[0]), h("td", { class: "num" }, fmtNum(b[r[1]])), h("td", { class: "num" }, fmtNum(hd[r[1]])));
        }).concat([h("tr", null, h("td", null, "Finding rate among tested"), h("td", { class: "num" }, pct(b.finding_rate)), h("td", { class: "num" }, pct(hd.finding_rate)))])))));
    }
    var changes = c.verdict_changes || [];
    if (!changes.length) {
      append(box, h("p", { class: "muted", style: "margin:0" }, "Every scenario has the same verdict in both runs."));
      return box;
    }
    append(box, h("div", { class: "panel", style: "overflow-x:auto" }, h("table", null,
      h("thead", null, h("tr", null, h("th", null, "Scenario"), h("th", null, "Baseline"), h("th", null, "Current"), h("th", null, "Change"))),
      h("tbody", null, changes.map(function (x) {
        var ch = verdictChange(x.base, x.head);
        var href = hashFor({ id: x.head ? c.head.id : c.base.id, tab: "scenarios", sub: x.id });
        return h("tr", { class: "link", onclick: function (e) { if (e.target.tagName !== "A") location.hash = href; } },
          h("td", null, h("a", { href: href }, x.title || x.id), h("div", { class: "item-sub" }, x.id)),
          h("td", null, x.base ? statusLabel(x.base) : h("span", { class: "muted" }, "–")),
          h("td", null, x.head ? statusLabel(x.head) : h("span", { class: "muted" }, "–")),
          h("td", { class: "change " + ch[1] }, ch[0]));
      })))));
    return box;
  }

  /* ------------------------------------------------------------------ keyboard, theme, boot */

  document.addEventListener("keydown", function (e) {
    if (e.metaKey || e.ctrlKey || e.altKey) return;
    var tag = (e.target.tagName || "").toLowerCase();
    if (tag === "input" || tag === "select" || tag === "textarea") return;
    if (e.key !== "j" && e.key !== "k") return;
    var list = main.querySelector("[data-list]");
    if (!list) return;
    var items = Array.from(list.querySelectorAll("a.item"));
    if (!items.length) return;
    var i = items.findIndex(function (a) { return a.classList.contains("active"); });
    var next = items[Math.max(0, Math.min(items.length - 1, i + (e.key === "j" ? 1 : -1)))];
    if (next && next !== items[i]) { e.preventDefault(); location.hash = next.getAttribute("href"); }
  });

  function applyTheme(t) {
    if (t) document.documentElement.setAttribute("data-theme", t); else document.documentElement.removeAttribute("data-theme");
  }
  try { applyTheme(localStorage.getItem("agentsec-theme")); } catch (e) { /* storage unavailable */ }
  document.getElementById("theme").addEventListener("click", function () {
    var cur = document.documentElement.getAttribute("data-theme")
      || (matchMedia("(prefers-color-scheme: dark)").matches ? "dark" : "light");
    var next = cur === "dark" ? "light" : "dark";
    applyTheme(next);
    try { localStorage.setItem("agentsec-theme", next); } catch (e) { /* storage unavailable */ }
  });
  document.getElementById("rail-toggle").addEventListener("click", function () {
    var shell = document.getElementById("shell");
    shell.classList.toggle("rail-open");
    this.setAttribute("aria-expanded", shell.classList.contains("rail-open") ? "true" : "false");
  });

  window.addEventListener("hashchange", route);
  Promise.all([api("/api/meta"), refreshReports(true)]).then(function (res) {
    state.meta = res[0];
    route();
    startPolling();
  }).catch(function (err) {
    render(h("div", { class: "page" }, emptyState("The dashboard server did not respond", err.message, "Is agentsec dashboard still running?")));
  });
})();
