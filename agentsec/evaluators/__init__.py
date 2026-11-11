from typing import List, Optional

from ..effects import is_irreversible
from .authorization import ActionAuthorizationEvaluator
from .claims import ActionClaimEvaluator
from .dataflow import DataFlowEvaluator
from .delegation import DelegationEvaluator
from .goals import AttackGoalEvaluator
from .identity import IdentityBoundaryEvaluator
from .base import SEVERITIES, Evaluator, Finding, severity_rank
from .injection import InjectionFollowedEvaluator
from .judge import JudgeEvaluator
from .limits import LimitsEvaluator
from .secrets import SecretLeakEvaluator
from .spend import AddressAllowlistEvaluator, SpendPolicyEvaluator
from .tools import ToolPolicyEvaluator

DEFAULT_EVALUATORS = (ToolPolicyEvaluator, SecretLeakEvaluator, InjectionFollowedEvaluator, LimitsEvaluator,
                      SpendPolicyEvaluator, AddressAllowlistEvaluator, ActionAuthorizationEvaluator,
                      DataFlowEvaluator, ActionClaimEvaluator, IdentityBoundaryEvaluator, DelegationEvaluator,
                      AttackGoalEvaluator)


def evaluate_trace(scenario, trace, policy, judge: Optional[JudgeEvaluator] = None,
                   extra_evaluators: Optional[List[type]] = None) -> List[Finding]:
    """Run the deterministic evaluators -- built-in, then any attack-pack-provided ones -- then
    (if given) the optional judge on what they all missed. `extra_evaluators` are Evaluator
    subclasses from `agentsec.attacks.packs.load_packs_evaluators`; see docs/extending.md."""
    findings: List[Finding] = []
    for cls in DEFAULT_EVALUATORS:
        findings.extend(cls().evaluate(scenario, trace, policy))
    for cls in (extra_evaluators or []):
        findings.extend(cls().evaluate(scenario, trace, policy))
    if judge is not None:
        findings.extend(judge.evaluate(scenario, trace, policy, findings))
    for finding in findings:
        finding.irreversible = finding.irreversible or _calls_irreversible_tool(finding, policy)
    return findings


def _calls_irreversible_tool(finding: Finding, policy) -> bool:
    return any(ev.get("type") == "tool_call" and is_irreversible(policy, ev.get("tool_name"))
               for ev in finding.evidence)


__all__ = ["SEVERITIES", "Evaluator", "Finding", "severity_rank", "evaluate_trace", "JudgeEvaluator",
           "ToolPolicyEvaluator", "SecretLeakEvaluator", "InjectionFollowedEvaluator", "LimitsEvaluator",
           "SpendPolicyEvaluator", "AddressAllowlistEvaluator", "ActionAuthorizationEvaluator",
           "DataFlowEvaluator", "ActionClaimEvaluator", "IdentityBoundaryEvaluator",
           "DelegationEvaluator", "AttackGoalEvaluator"]
