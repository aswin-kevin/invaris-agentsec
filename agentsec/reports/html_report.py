"""Self-contained HTML report (no external assets, no JavaScript)."""
from __future__ import annotations

import html
import json
from typing import Any, Dict, List

_SEV_ORDER = ["critical", "high", "medium", "low"]

_CSS = """
:root{--bg:#f6f7f9;--card:#fff;--fg:#1a1d23;--muted:#5b6472;--line:#e2e5ea;--code:#f0f2f5;
--critical:#b42318;--high:#d9480f;--medium:#a16207;--low:#0b6e99;--ok:#1a7f4b;--err:#6b46c1}
@media (prefers-color-scheme:dark){:root{--bg:#0f1216;--card:#171b21;--fg:#e8eaee;--muted:#98a2b3;
--line:#2a313b;--code:#1f252d;--critical:#f97066;--high:#fb923c;--medium:#facc15;--low:#5cc8f5;
--ok:#4ade80;--err:#b794f6}}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--fg);
font:15px/1.5 system-ui,-apple-system,"Segoe UI",Roboto,sans-serif}
main{max-width:1000px;margin:0 auto;padding:24px 16px 64px}
h1{font-size:22px;margin:0 0 4px}h2{font-size:17px;margin:32px 0 12px}
.sub{color:var(--muted);font-size:13px}
.cards{display:grid;grid-template-columns:repeat(auto-fit,minmax(130px,1fr));gap:12px;margin:20px 0}
.card{background:var(--card);border:1px solid var(--line);border-radius:10px;padding:12px 14px}
.card b{display:block;font-size:26px;line-height:1.2}.card span{color:var(--muted);font-size:13px}
.pill{display:inline-block;border-radius:999px;padding:1px 9px;font-size:12px;font-weight:600;
border:1px solid currentColor;text-transform:uppercase;letter-spacing:.02em}
.critical{color:var(--critical)}.high{color:var(--high)}.medium{color:var(--medium)}.low{color:var(--low)}
.passed{color:var(--ok)}.findings{color:var(--high)}.error{color:var(--err)}
.inconclusive,.not_observable{color:var(--muted)}
details{background:var(--card);border:1px solid var(--line);border-radius:10px;margin:8px 0;padding:0}
summary{cursor:pointer;padding:10px 14px;list-style:none}summary::-webkit-details-marker{display:none}
summary::before{content:"\\25B8";color:var(--muted);margin-right:8px;display:inline-block}
details[open]>summary::before{content:"\\25BE"}
.body{padding:2px 14px 14px;border-top:1px solid var(--line)}
dl{display:grid;grid-template-columns:150px 1fr;gap:6px 12px;margin:12px 0}
dt{color:var(--muted);font-size:13px}dd{margin:0;overflow-wrap:anywhere}
pre{background:var(--code);border-radius:8px;padding:10px 12px;overflow:auto;font-size:12.5px;margin:6px 0}
code{font-family:ui-monospace,SFMono-Regular,Menlo,monospace;font-size:12.5px}
table{width:100%;border-collapse:collapse;background:var(--card);border:1px solid var(--line);
border-radius:10px;overflow:hidden}
th,td{text-align:left;padding:8px 12px;border-bottom:1px solid var(--line);font-size:14px}
th{color:var(--muted);font-weight:600;font-size:12px;text-transform:uppercase;letter-spacing:.04em}
tr:last-child td{border-bottom:0}.tag{background:var(--code);border-radius:6px;padding:1px 7px;
font-size:12px;margin-right:4px;white-space:nowrap}
.tag.irreversible{color:var(--critical);border:1px solid var(--critical);font-weight:600}
.warn{background:var(--card);border-left:4px solid var(--medium);padding:8px 12px;border-radius:6px}
@media (max-width:600px){dl{grid-template-columns:1fr}}
"""


def _e(x: Any) -> str:
    return html.escape(str(x), quote=True)


def _pill(sev: str) -> str:
    return '<span class="pill %s">%s</span>' % (_e(sev), _e(sev))


def _tags(finding: Dict[str, Any]) -> str:
    out = "".join('<span class="tag">%s %s</span>' % (_e(o["id"]), _e(o["name"]))
                  for o in finding.get("owasp", []))
    if finding.get("irreversible"):
        out += '<span class="tag irreversible">irreversible</span>'
    if finding.get("source") == "model-assisted":
        out += '<span class="tag">model-assisted</span>'
    return out


def _json(obj: Any) -> str:
    return "<pre><code>%s</code></pre>" % _e(json.dumps(obj, indent=2, ensure_ascii=False))


def render_html(report: Dict[str, Any]) -> str:
    summary = report["summary"]
    findings: List[Dict[str, Any]] = sorted(
        report["findings"], key=lambda f: _SEV_ORDER.index(f["severity"]))
    cfg = report["run_config"]
    agent = cfg["policy"]["agent"]
    parts: List[str] = []
    a = parts.append

    a("<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\">"
      "<meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">"
      "<title>AgentSec report</title><style>%s</style></head><body><main>" % _CSS)
    a("<h1>Invaris AgentSec report</h1>")
    a("<div class=\"sub\">Agent <b>%s</b> at %s &middot; seed %s &middot; %s &middot; AgentSec %s</div>" % (
        _e(agent["name"]), _e(agent["endpoint"]), _e(cfg["seed"]), _e(report["generated_at"]),
        _e(report["tool"]["version"])))

    a("<div class=\"cards\">")
    for label, value in (("Scenarios", summary["scenarios"]), ("Passed", summary["passed"]),
                         ("Findings", summary["findings"]), ("Errors", summary["errors"])):
        a("<div class=\"card\"><b>%s</b><span>%s</span></div>" % (_e(value), label))
    a("</div>")
    sev = summary["by_severity"]
    a("<p>%s</p>" % " &nbsp; ".join("%s <b>%d</b>" % (_pill(s), sev.get(s, 0)) for s in _SEV_ORDER))
    for w in report.get("warnings", []):
        a("<p class=\"warn\">%s</p>" % _e(w))

    # OWASP coverage
    by_owasp = summary.get("by_owasp") or {}
    if by_owasp:
        cats = report.get("owasp_framework", {}).get("categories", {})
        a("<h2>OWASP agentic categories hit</h2><table><tr><th>ID</th><th>Category</th>"
          "<th>Findings</th></tr>")
        for k, n in by_owasp.items():
            a("<tr><td>%s</td><td>%s</td><td>%d</td></tr>" % (_e(k), _e(cats.get(k, "")), n))
        a("</table><p class=\"sub\">Mapping is Invaris&#39; judgement of the closest category, not an "
          "official OWASP classification.</p>")

    a("<h2>Findings (%d)</h2>" % len(findings))
    if not findings:
        a("<p>No findings. Every executed scenario passed.</p>")
    for f in findings:
        a("<details><summary>%s <b>%s</b><div class=\"sub\">%s &middot; %s</div></summary>"
          "<div class=\"body\"><dl>" % (_pill(f["severity"]), _e(f["title"]), _e(f["scenario_id"]),
                                        _tags(f)))
        for label, key in (("Policy violated", "policy_violated"), ("Observed", "observed_action"),
                           ("Input", "input"), ("Remediation", "remediation")):
            a("<dt>%s</dt><dd>%s</dd>" % (label, _e(f[key])))
        if "confidence" in f:
            a("<dt>Judge confidence</dt><dd>%s</dd>" % _e(f["confidence"]))
        a("<dt>Finding id</dt><dd><code>%s</code></dd></dl>" % _e(f["id"]))
        a("<div class=\"sub\">Evidence</div>%s</div></details>" % _json(f["evidence"]))

    a("<h2>Scenarios (%d)</h2><table><tr><th>Scenario</th><th>Vector</th><th>Status</th>"
      "<th>Steps</th><th>Tool calls</th></tr>" % len(report["scenarios"]))
    for s in report["scenarios"]:
        u = s["trace"]["usage"]
        a("<tr><td>%s</td><td>%s</td><td><span class=\"%s\">%s</span></td><td>%d</td><td>%d</td></tr>" % (
            _e(s["id"]), _e(s["vector"]), _e(s["status"]), _e(s["status"]), u["steps"], u["tool_calls"]))
    a("</table>")

    a("<h2>Traces</h2><p class=\"sub\">Full event record for each scenario. Secrets are masked.</p>")
    for s in report["scenarios"]:
        t = s["trace"]
        a("<details><summary><span class=\"%s\">&#9679;</span> %s <span class=\"sub\">%s, %d events"
          "</span></summary><div class=\"body\">%s</div></details>" % (
              _e(s["status"]), _e(s["id"]), _e(t["outcome"]), len(t["events"]), _json(t)))

    a("<p class=\"sub\" style=\"margin-top:32px\">Replay: <code>%s</code></p>" % _e(cfg["replay"]))
    a("</main></body></html>")
    return "".join(parts)
