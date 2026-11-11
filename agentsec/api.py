"""Python API: run AgentSec scenarios from code and assert on the outcome.

    from agentsec import AgentTarget, SecuritySuite

    target = AgentTarget(
        endpoint="http://localhost:8000/agent",
        allowed_tools={"search_documents", "create_draft"},
        forbidden_tools={"send_email", "execute_payment"},
    )
    result = SecuritySuite(target).run("indirect_prompt_injection")

    assert result.secret_leaks == []
    assert result.forbidden_tool_calls == []
    assert result.total_tool_calls <= 10
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any, Dict, Iterable, List, Optional

from .adapters import AgentAdapter, HTTPAgentAdapter
from .attacks import CATEGORIES
from .evaluators import Finding, severity_rank
from .policies import AgentConfig, Limits, Policy, PolicyError, Pricing, load_policy
from .policies.loader import check_tool_effects
from .policies.schema import _sha
from .runners import ScenarioResult, SuiteResult, run_suite


class AgentTarget:
    """Describes the agent under test. Equivalent to an agentsec.yaml policy."""

    def __init__(self, endpoint: str, *, name: Optional[str] = None,
                 allowed_tools: Optional[Iterable[str]] = None,
                 forbidden_tools: Iterable[str] = (), secrets: Iterable[str] = (),
                 tool_effects: Optional[Dict[str, Iterable[str]]] = None,
                 model: str = "agentsec-target", api_key_env: Optional[str] = None,
                 headers: Optional[Dict[str, str]] = None, timeout_s: float = 30.0,
                 declare_tools: bool = True, stream: bool = False, retrieval_tools: Iterable[str] = (),
                 pricing: Optional[Pricing] = None, max_steps: int = 12, max_tool_calls: int = 10,
                 max_repeated_calls: int = 3, max_tokens: Optional[int] = None,
                 max_seconds: Optional[float] = None, max_cost_usd: Optional[float] = None,
                 judge: Optional[Any] = None, attack_packs: Iterable[str] = ()):
        if not endpoint.startswith(("http://", "https://")):
            raise PolicyError("endpoint must start with http:// or https://")
        tool_effects = {k: list(v) for k, v in (tool_effects or {}).items()}
        check_tool_effects(tool_effects)
        agent = AgentConfig(
            name=name or endpoint, endpoint=endpoint, model=model, api_key_env=api_key_env,
            headers=dict(headers or {}), timeout_s=timeout_s, declare_tools=declare_tools, stream=stream,
            retrieval_tools=sorted(retrieval_tools), pricing=pricing)
        self.policy = Policy(
            agent=agent,
            allowed_tools=sorted(allowed_tools) if allowed_tools is not None else None,
            forbidden_actions=sorted(forbidden_tools), secrets=list(secrets),
            tool_effects=tool_effects,
            limits=Limits(max_steps=max_steps, max_tool_calls=max_tool_calls,
                          max_repeated_calls=max_repeated_calls, max_tokens=max_tokens,
                          max_seconds=max_seconds, max_cost_usd=max_cost_usd),
            judge=judge, attack_packs=list(attack_packs))
        self.policy.source_sha256 = _sha(json.dumps(self.policy.to_report_dict(), sort_keys=True))

    @classmethod
    def from_policy(cls, policy: Policy) -> "AgentTarget":
        target = cls.__new__(cls)
        target.policy = policy
        return target

    @classmethod
    def from_file(cls, path: str = "agentsec.yaml") -> "AgentTarget":
        return cls.from_policy(load_policy(path))


@dataclass
class ToolCallRecord:
    scenario_id: str
    name: str
    arguments: Dict[str, Any]


@dataclass
class RunResult:
    """Outcome of one `SecuritySuite.run`. Compare the list attributes to `[]`."""
    suite: SuiteResult

    @property
    def results(self) -> List[ScenarioResult]:
        return self.suite.results

    @property
    def findings(self) -> List[Finding]:
        return self.suite.findings

    @property
    def errors(self) -> List[ScenarioResult]:
        return [r for r in self.results if r.status == "error"]

    @property
    def passed(self) -> bool:
        """No findings, no errors, and every attack that tracks delivery actually reached the agent."""
        return not self.findings and not self.errors and not self.inconclusive

    @property
    def not_observable(self) -> List[ScenarioResult]:
        """Scenarios that could not be judged because the agent did not report what they need
        (e.g. which agent acted, for multi-agent scenarios). Not failures -- and not passes."""
        return [r for r in self.results if r.status == "not_observable"]

    @property
    def inconclusive(self) -> List[ScenarioResult]:
        """Scenarios whose adversarial content never reached the agent (it did not open the
        poisoned email or page, or stopped before the injection step), so they tested nothing.
        Not failures -- and not passes. See Scenario.exposure."""
        return [r for r in self.results if r.status == "inconclusive"]

    @property
    def secret_leaks(self) -> List[Finding]:
        return [f for f in self.findings if f.rule == "secret_leak"]

    @property
    def unauthorized_side_effects(self) -> List[Finding]:
        """Allowed tool calls whose effects (Policy.tool_effects) exceeded what the scenario's
        own task authorized (Scenario.authorized_effects) -- see
        agentsec/attacks/action_without_authorization.py."""
        return [f for f in self.findings if f.rule == "unauthorized_side_effect"]

    @property
    def forbidden_tool_calls(self) -> List[ToolCallRecord]:
        forbidden = set(self.suite.policy.forbidden_actions)
        return [ToolCallRecord(r.scenario.id, e.tool_name, e.arguments or {})
                for r in self.results for e in r.trace.of_type("tool_call") if e.tool_name in forbidden]

    @property
    def unauthorized_tool_calls(self) -> List[ToolCallRecord]:
        allowed = self.suite.policy.allowed_tools
        if allowed is None:
            return []
        return [ToolCallRecord(r.scenario.id, e.tool_name, e.arguments or {})
                for r in self.results for e in r.trace.of_type("tool_call")
                if e.tool_name not in allowed and e.tool_name not in self.suite.policy.forbidden_actions]

    @property
    def tool_calls_by_scenario(self) -> Dict[str, int]:
        return {r.scenario.id: len(r.trace.of_type("tool_call")) for r in self.results}

    @property
    def total_tool_calls(self) -> int:
        """The most tool calls any single scenario made (compare with `limits.max_tool_calls`)."""
        return max(self.tool_calls_by_scenario.values(), default=0)

    def findings_at_least(self, severity: str) -> List[Finding]:
        return [f for f in self.findings if severity_rank(f.severity) >= severity_rank(severity)]

    def format(self, fail_on: str = "low") -> str:
        lines = []
        for f in sorted(self.findings_at_least(fail_on), key=lambda f: -severity_rank(f.severity)):
            mark = " [irreversible]" if f.irreversible else ""
            lines.append("  [%s] %s%s (%s)" % (f.severity.upper(), f.title, mark, f.scenario_id))
        for r in self.errors:
            lines.append("  [ERROR] %s: %s" % (r.scenario.id, r.trace.error))
        return "\n".join(lines)

    def assert_clean(self, fail_on: str = "low") -> None:
        """Raise AssertionError if a finding at or above `fail_on` exists, or any scenario errored."""
        bad = self.findings_at_least(fail_on)
        if bad or self.errors:
            raise AssertionError("AgentSec: %d finding(s) at or above %r, %d errored scenario(s)\n%s"
                                 % (len(bad), fail_on, len(self.errors), self.format(fail_on)))


class SecuritySuite:
    def __init__(self, target: AgentTarget, seed: int = 0, adapter: Optional[AgentAdapter] = None,
                 judge: bool = False, mcp_host: Optional[Any] = None,
                 attack_packs: Optional[Dict[str, Any]] = None):
        self.target = target
        self.mcp_host = mcp_host
        self.attack_packs = attack_packs
        self.seed = seed
        self.adapter = adapter or HTTPAgentAdapter(target.policy.agent)
        self.judge = judge

    def run(self, *names: str, seed: Optional[int] = None) -> RunResult:
        """Run categories and/or scenario ids. With no names, every category (built-in plus any
        attack packs from the policy or from `SecuritySuite(attack_packs=...)`) runs."""
        known = dict(CATEGORIES)
        if self.target.policy.attack_packs or self.attack_packs:
            from .attacks.packs import load_packs
            if self.target.policy.attack_packs:
                known.update(load_packs(self.target.policy.attack_packs, CATEGORIES))
            if self.attack_packs:
                known.update(self.attack_packs)
        names_l = list(names)
        if names_l:
            wanted = {n.split("/", 1)[0] for n in names_l}
            unknown = sorted(wanted - set(known))
            if unknown:
                raise PolicyError("unknown test category %r; available: %s"
                                  % (unknown[0], ", ".join(sorted(known))))
            categories = [c for c in known if c in wanted]
        else:
            categories = list(known)
        # Whole categories are selected by `categories`; only scenario ids need the `only` filter.
        # (A category whose prerequisites the policy doesn't declare -- e.g. tool_effects for
        # action_without_authorization, agent_roles for multi_agent_delegation -- legitimately
        # builds no scenarios; that is an empty run, not an error.)
        ids = [n for n in names_l if "/" in n]
        suite = run_suite(self.target.policy, self.adapter, seed=self.seed if seed is None else seed,
                          only=ids or None, categories=categories, judge=self.judge,
                          host=self.mcp_host, attack_packs=self.attack_packs)
        return RunResult(suite)
