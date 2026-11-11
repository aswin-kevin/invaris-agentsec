from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from ..owasp import map_finding

SEVERITIES = ("critical", "high", "medium", "low")


def severity_rank(sev: str) -> int:
    return len(SEVERITIES) - SEVERITIES.index(sev)  # critical=4 ... low=1


@dataclass
class Finding:
    rule: str
    scenario_id: str
    category: str
    severity: str
    title: str
    policy_violated: str
    observed_action: str
    input: str
    evidence: List[Dict[str, Any]]
    remediation: str
    key: str = ""
    source: str = "deterministic"        # or "model-assisted"
    confidence: Optional[float] = None   # only for model-assisted findings
    # The evidence includes a call to a tool the policy tags `irreversible` (see agentsec/effects.py).
    irreversible: bool = False
    # Values that must be masked when the finding is written to a report.
    sensitive: List[str] = field(default_factory=list, repr=False)

    @property
    def id(self) -> str:
        return "%s:%s%s" % (self.scenario_id, self.rule, (":" + self.key) if self.key else "")

    @property
    def owasp(self) -> List[Dict[str, str]]:
        return map_finding(self.rule, self.category)

    def to_dict(self) -> Dict[str, Any]:
        d: Dict[str, Any] = {
            "id": self.id, "rule": self.rule, "scenario_id": self.scenario_id,
            "category": self.category, "severity": self.severity, "title": self.title,
            "source": self.source, "owasp": self.owasp,
            "policy_violated": self.policy_violated, "observed_action": self.observed_action,
            "input": self.input, "evidence": self.evidence, "remediation": self.remediation,
        }
        if self.confidence is not None:
            d["confidence"] = self.confidence
        if self.irreversible:
            d["irreversible"] = True
        return d


@dataclass
class JudgeCheck:
    """A pack-provided question for the optional model-assisted judge.

    Packs that export a ``JUDGE_CHECKS`` mapping of name -> JudgeCheck let a
    policy's ``judge.checks`` list refer to them by name, the same way
    ``EVALUATORS`` lets a policy's deterministic pass pick up pack rules.
    Unlike the built-in checks (``goal_hijack``, ``paraphrased_leak``), a
    pack-provided check runs unconditionally once per scenario whenever it
    is selected -- there is no per-scenario gating -- so the ``question``
    itself is responsible for asking the judge to say "no violation" when
    it doesn't apply.
    """

    question: str
    title: str
    policy_violated: str
    remediation: str


def excerpt(trace, *seqs: int) -> List[Dict[str, Any]]:
    wanted = set(seqs)
    return [e.to_dict() for e in trace.events if e.seq in wanted]


class Evaluator:
    name = "evaluator"

    def evaluate(self, scenario, trace, policy) -> List[Finding]:
        raise NotImplementedError
