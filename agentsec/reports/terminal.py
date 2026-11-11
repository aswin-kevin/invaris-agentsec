from __future__ import annotations

from typing import List, Sequence, Union

from ..evaluators import SEVERITIES, severity_rank
from ..runners import SuiteResult
from ..verdicts import describe_agent
from .json_report import _mask_obj, agent_reported

_COLORS = {"critical": "\033[1;31m", "high": "\033[31m", "medium": "\033[33m", "low": "\033[36m"}
_RESET, _BOLD, _DIM = "\033[0m", "\033[1m", "\033[2m"


def render_terminal(suite: SuiteResult, report_path: Union[str, Sequence[str]] = "", color: bool = False,
                    verbose: bool = False) -> str:
    def paint(text: str, code: str) -> str:
        return (code + text + _RESET) if color else text

    total = len(suite.results)
    passed = sum(r.status == "passed" for r in suite.results)
    errors = [r for r in suite.results if r.status == "error"]
    findings = sorted(suite.findings, key=lambda f: -severity_rank(f.severity))

    lines: List[str] = [paint("Invaris AgentSec", _BOLD), ""]
    lines.append("%d scenarios executed" % total)
    lines.append("%d passed" % passed)
    lines.append("%d finding%s" % (len(findings), "" if len(findings) == 1 else "s"))
    if errors:
        lines.append("%d errored (agent unreachable or invalid reply)" % len(errors))
    blind = sum(r.status == "not_observable" for r in suite.results)
    if blind:
        lines.append("%d not observable (the agent did not report what these scenarios need to judge)" % blind)
    untested = sum(r.status == "inconclusive" for r in suite.results)
    if untested:
        lines.append("%d inconclusive (the attack never reached the agent; not counted as passed)" % untested)
    reported = agent_reported(suite)
    if reported:
        lines.append(_mask_obj("agent reported: %s" % "; ".join(describe_agent(a) for a in reported),
                               sorted(suite.policy.resolved_secrets(), key=len, reverse=True)))
    lines.append("")

    sensitive = suite.policy.resolved_secrets() + [v for f in findings for v in f.sensitive]
    for f in findings:
        label = paint(f.severity.upper().ljust(9), _COLORS[f.severity])
        tag = " [irreversible]" if f.irreversible else ""
        tag += " [model-assisted]" if f.source == "model-assisted" else ""
        lines.append("%s %s%s" % (label, f.title, tag))
        lines.append("          %s" % paint("%s  |  %s" % (f.scenario_id, f.policy_violated), _DIM))
        if verbose:
            observed = _mask_obj(f.observed_action, sensitive)
            lines.append("          observed: %s" % observed)
            lines.append("          fix:      %s" % f.remediation)
            if f.owasp:
                lines.append("          owasp:    %s" % ", ".join("%s %s" % (o["id"], o["name"]) for o in f.owasp))
    if findings:
        lines.append("")
    for r in errors:
        lines.append("%s %s: %s" % (paint("ERROR".ljust(9), _BOLD), r.scenario.id, r.trace.error))
    for w in suite.warnings:
        lines.append("warning: %s" % w)
    if errors or suite.warnings:
        lines.append("")
    paths = [report_path] if isinstance(report_path, str) else list(report_path)
    for path in paths:
        if path:
            lines.append("Report written to %s" % path)
    return "\n".join(lines)
