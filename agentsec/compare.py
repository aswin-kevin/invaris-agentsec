"""Compare two report.json files to spot security regressions between runs."""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any, Dict, List

from .evaluators import severity_rank
from .verdicts import TESTED, evaluation, verdict_changes

# Statuses under which a new run says nothing about a baseline finding: the scenario errored, its attack was
# never delivered, or the agent did not report what the scenario needs to be judged.
NOT_MEASURED = ("error", "inconclusive", "not_observable")


class CompareError(Exception):
    pass


def load(path: str) -> Dict[str, Any]:
    try:
        with open(path, encoding="utf-8") as fh:
            data = json.load(fh)
    except (OSError, ValueError) as exc:
        raise CompareError("cannot read report %s: %s" % (path, exc))
    if not isinstance(data, dict) or "findings" not in data or "scenarios" not in data:
        raise CompareError("%s is not an AgentSec report.json" % path)
    return data


@dataclass
class Comparison:
    new: List[Dict[str, Any]] = field(default_factory=list)
    fixed: List[Dict[str, Any]] = field(default_factory=list)
    unchanged: List[Dict[str, Any]] = field(default_factory=list)
    worse: List[Dict[str, Any]] = field(default_factory=list)      # severity went up
    better: List[Dict[str, Any]] = field(default_factory=list)     # severity went down
    not_comparable: List[Dict[str, Any]] = field(default_factory=list)  # scenario not (cleanly) rerun
    warnings: List[str] = field(default_factory=list)
    # Per-scenario verdict changes and what each run measured (agentsec.verdicts); the same data the
    # local and hosted dashboards show, so all three agree.
    verdict_changes: List[Dict[str, Any]] = field(default_factory=list)
    base_evaluation: Dict[str, Any] = field(default_factory=dict)
    head_evaluation: Dict[str, Any] = field(default_factory=dict)

    def untested(self) -> List[Dict[str, Any]]:
        """Scenarios tested in the baseline that the new run did not test (inconclusive, error, not
        observable or missing): coverage lost, which is never an improvement."""
        return [x for x in self.verdict_changes if x["base"] in TESTED and x["head"] not in TESTED]

    def regressions(self, min_severity: str = "low") -> List[Dict[str, Any]]:
        floor = severity_rank(min_severity)
        return [f for f in self.new + self.worse if severity_rank(f["severity"]) >= floor]


def compare(base: Dict[str, Any], head: Dict[str, Any]) -> Comparison:
    out = Comparison()
    b_run, h_run = base.get("run_config", {}), head.get("run_config", {})
    if b_run.get("seed") != h_run.get("seed"):
        out.warnings.append("seeds differ (%s vs %s): canaries and markers differ, so results may not line up"
                            % (b_run.get("seed"), h_run.get("seed")))
    b_sc = {s["id"]: s for s in base["scenarios"]}
    h_sc = {s["id"]: s for s in head["scenarios"]}
    only_base = sorted(set(b_sc) - set(h_sc))
    only_head = sorted(set(h_sc) - set(b_sc))
    if only_base:
        out.warnings.append("%d scenario(s) only in the baseline (their findings are not counted as fixed): %s"
                            % (len(only_base), ", ".join(only_base)))
    if only_head:
        out.warnings.append("%d scenario(s) only in the new run: %s" % (len(only_head), ", ".join(only_head)))
    b_pol = (b_run.get("policy") or {})
    h_pol = (h_run.get("policy") or {})
    if b_pol != h_pol:
        out.warnings.append("the policy differs between the two runs")

    b_f = {f["id"]: f for f in base["findings"]}
    h_f = {f["id"]: f for f in head["findings"]}
    for fid, f in h_f.items():
        if fid not in b_f:
            out.new.append(f)
        else:
            old = severity_rank(b_f[fid]["severity"])
            new = severity_rank(f["severity"])
            (out.worse if new > old else out.better if new < old else out.unchanged).append(f)
    for fid, f in b_f.items():
        if fid in h_f:
            continue
        sc = h_sc.get(f["scenario_id"])
        if sc is None or sc.get("status") in NOT_MEASURED:
            out.not_comparable.append(f)   # cannot claim it was fixed: the new run measured nothing there
        else:
            out.fixed.append(f)
    out.verdict_changes = verdict_changes(base, head)
    out.base_evaluation, out.head_evaluation = evaluation(base), evaluation(head)
    return out


def _status_name(status: Any) -> str:
    return "missing" if status is None else str(status).replace("_", " ")


def _irreversible_mark(finding: Dict[str, Any]) -> str:
    return " (irreversible)" if finding.get("irreversible") else ""


def render(c: Comparison) -> str:
    lines: List[str] = []
    for w in c.warnings:
        lines.append("warning: " + w)
    if lines:
        lines.append("")

    def block(title, items, mark):
        if items:
            lines.append("%s (%d)" % (title, len(items)))
            for f in sorted(items, key=lambda x: (-severity_rank(x["severity"]), x["id"])):
                lines.append("  %s %-8s %s%s  [%s]" % (mark, f["severity"], f["title"], _irreversible_mark(f),
                                                      f["scenario_id"]))
            lines.append("")

    block("NEW findings", c.new, "+")
    block("Severity increased", c.worse, "^")
    block("Fixed", c.fixed, "-")
    block("Severity decreased", c.better, "v")
    block("Unchanged", c.unchanged, "=")
    block("Not comparable (scenario missing, errored, inconclusive or not observable in the new run)", c.not_comparable, "?")
    lost = c.untested()
    if lost:
        lines.append("Not tested in the new run (%d), so not an improvement" % len(lost))
        for x in lost:
            lines.append("  ! %s -> %s  [%s]" % (x["base"], _status_name(x["head"]), x["id"]))
        lines.append("")
    lines.append("%d new, %d worse, %d fixed, %d better, %d unchanged" % (
        len(c.new), len(c.worse), len(c.fixed), len(c.better), len(c.unchanged)))
    if c.base_evaluation and c.head_evaluation:
        b, h = c.base_evaluation, c.head_evaluation
        lines.append("tested %d -> %d of %d -> %d scenarios; inconclusive %d -> %d; %d scenario verdict(s) changed" % (
            b["tested"], h["tested"], b["scenarios"], h["scenarios"], b["inconclusive"], h["inconclusive"],
            len(c.verdict_changes)))
    return "\n".join(lines)


def render_markdown(c: Comparison, baseline_label: str = "baseline", current_label: str = "current") -> str:
    """Markdown for a PR comment or job summary. `agentsec compare BASELINE CURRENT --format` has no
    markdown mode of its own; this is used by the GitHub Action's baseline-report comparison."""
    lines: List[str] = ["Comparing `%s` against `%s`." % (baseline_label, current_label), ""]
    for w in c.warnings:
        lines.append("> \u26a0\ufe0f %s" % w)
    if c.warnings:
        lines.append("")
    lines.append("| | Count |")
    lines.append("|---|---:|")
    for label, items in (("New", c.new), ("Severity increased", c.worse), ("Fixed", c.fixed),
                         ("Severity decreased", c.better), ("Unchanged", c.unchanged),
                         ("Not comparable", c.not_comparable)):
        lines.append("| %s | %d |" % (label, len(items)))
    if c.base_evaluation and c.head_evaluation:
        lines.append("| Tested scenarios | %d → %d |" % (c.base_evaluation["tested"], c.head_evaluation["tested"]))
        if c.base_evaluation["inconclusive"] or c.head_evaluation["inconclusive"]:
            lines.append("| Inconclusive scenarios | %d → %d |" % (c.base_evaluation["inconclusive"],
                                                              c.head_evaluation["inconclusive"]))
    lines.append("")

    def section(title: str, items: List[Dict[str, Any]]) -> None:
        if not items:
            return
        lines.append("<details%s>" % (" open" if title == "New findings" else ""))
        lines.append("<summary>%s (%d)</summary>" % (title, len(items)))
        lines.append("")
        for f in sorted(items, key=lambda x: (-severity_rank(x["severity"]), x["id"])):
            lines.append("- **%s** %s%s (`%s`)" % (f["severity"].upper(), f["title"], _irreversible_mark(f),
                                                  f["scenario_id"]))
        lines.append("")
        lines.append("</details>")
        lines.append("")

    section("New findings", c.new)
    section("Severity increased", c.worse)
    section("Fixed", c.fixed)
    section("Severity decreased", c.better)
    lost = c.untested()
    if lost:
        lines.append("<details open>")
        lines.append("<summary>Not tested in the current run (%d)</summary>" % len(lost))
        lines.append("")
        for x in lost:
            lines.append("- `%s`: %s → %s (the attack was not measured; not an improvement)"
                         % (x["id"], x["base"], _status_name(x["head"])))
        lines.append("")
        lines.append("</details>")
        lines.append("")
    if not (c.new or c.worse or c.fixed):
        lines.append("No new or worsened findings.")
    return "\n".join(lines)
