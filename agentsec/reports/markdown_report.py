"""Compact Markdown summary, used for the GitHub Actions job summary."""
from __future__ import annotations

from typing import Any, Dict

from ..verdicts import agent_reported, describe_agent

_ICON = {"critical": "🟥", "high": "🟧", "medium": "🟨", "low": "🟦"}
_ORDER = ["critical", "high", "medium", "low"]


def _cell(text: Any) -> str:
    return str(text).replace("|", "\\|").replace("\n", " ")


def render_markdown(report: Dict[str, Any]) -> str:
    s = report["summary"]
    lines = ["## Invaris AgentSec", ""]
    verdict = ("No findings." if not s["findings"]
               else "%d finding%s." % (s["findings"], "" if s["findings"] == 1 else "s"))
    lines.append("**%d** scenarios executed, **%d** passed. %s" % (s["scenarios"], s["passed"], verdict))
    if s["errors"]:
        lines.append("")
        lines.append("**%d scenario(s) errored** (agent unreachable or invalid reply)." % s["errors"])
    if s.get("not_observable"):
        lines.append("")
        lines.append("**%d scenario(s) not observable** (the agent did not report what they need to judge)."
                     % s["not_observable"])
    if s.get("inconclusive"):
        lines.append("")
        lines.append("**%d scenario(s) inconclusive** (the attack never reached the agent; not counted as passed)."
                     % s["inconclusive"])
    reported = agent_reported(report)
    if reported:
        lines.append("")
        lines.append("Agent reported: %s." % "; ".join(_cell(describe_agent(a)) for a in reported))
    lines.append("")
    if report["findings"]:
        sev = s["by_severity"]
        lines.append(" · ".join("%s %s %d" % (_ICON[k], k, sev.get(k, 0)) for k in _ORDER if sev.get(k)))
        lines += ["", "| Severity | Finding | Scenario | OWASP |", "|---|---|---|---|"]
        for f in sorted(report["findings"], key=lambda f: _ORDER.index(f["severity"])):
            owasp = ", ".join(o["id"] for o in f.get("owasp", []))
            title = _cell(f["title"]) + (" **(irreversible)**" if f.get("irreversible") else "")
            lines.append("| %s %s | %s | `%s` | %s |" % (
                _ICON[f["severity"]], f["severity"], title, f["scenario_id"], owasp))
    for w in report.get("warnings", []):
        lines += ["", "> %s" % w]
    lines += ["", "Seed `%s` · policy `%s`" % (report["run_config"]["seed"],
                                                report["run_config"]["policy"]["source_sha256"][:12]), ""]
    return "\n".join(lines)
