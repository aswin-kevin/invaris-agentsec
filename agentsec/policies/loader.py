from __future__ import annotations

from typing import Any, Dict, List, Optional

import yaml

from .schema import (JUDGE_CHECKS, POLICY_VERSION, AddressAllowlist, AgentConfig, AgentRole, JudgeConfig, Limits, Policy,
                     PolicyError, Pricing, SpendLimits, _sha)

_TOP = {"version", "agent", "allowed_tools", "forbidden_actions", "tool_effects", "agent_roles", "secrets", "limits",
       "spend_limits", "address_allowlist", "tests", "attack_packs", "judge"}
_JUDGE = {"endpoint", "model", "api_key_env", "headers", "timeout_s", "checks", "min_confidence", "severity"}
_AGENT = {"name", "endpoint", "model", "api_key_env", "headers", "timeout_s",
          "declare_tools", "stream", "retrieval_tools", "pricing"}
_LIMITS = {"max_steps", "max_tool_calls", "max_repeated_calls", "max_tokens",
           "max_seconds", "max_cost_usd"}
_PRICING = {"input_per_1k", "output_per_1k"}
_SPEND_LIMITS = {"tools", "amount_field", "max_transaction", "max_total", "currency"}
_AGENT_ROLE = {"effects", "tools", "can_delegate_to"}
_ADDRESS_ALLOWLIST = {"tools", "address_field", "addresses", "case_sensitive"}


def _check_keys(section: str, data: Dict[str, Any], allowed: set) -> None:
    unknown = sorted(set(data) - allowed)
    if unknown:
        raise PolicyError("unknown key(s) in %s: %s (allowed: %s)"
                          % (section, ", ".join(unknown), ", ".join(sorted(allowed))))


def _mapping(section: str, value: Any) -> Dict[str, Any]:
    if not isinstance(value, dict):
        raise PolicyError("%s must be a mapping" % section)
    return value


def _str_list(section: str, value: Any) -> List[str]:
    if not isinstance(value, list) or not all(isinstance(v, str) and v for v in value):
        raise PolicyError("%s must be a list of non-empty strings" % section)
    return list(value)


def _string(section: str, value: Any, default: str) -> str:
    if value is None:
        return default
    if not isinstance(value, str) or not value:
        raise PolicyError("%s must be a non-empty string" % section)
    return value


def _number(section: str, value: Any, *, integer: bool = False, minimum: float = 0) -> Any:
    ok = isinstance(value, (int, float)) and not isinstance(value, bool)
    if integer:
        ok = ok and isinstance(value, int)
    if not ok or value < minimum:
        raise PolicyError("%s must be a %snumber >= %s" % (section, "whole " if integer else "", minimum))
    return value


def _boolean(section: str, value: Any) -> bool:
    if not isinstance(value, bool):
        raise PolicyError("%s must be true or false" % section)
    return value


def _spend_limits(raw: Dict[str, Any]) -> Optional[SpendLimits]:
    if raw.get("spend_limits") is None:
        return None
    sl = _mapping("spend_limits", raw["spend_limits"])
    _check_keys("spend_limits", sl, _SPEND_LIMITS)
    tools = _str_list("spend_limits.tools", sl.get("tools", []))
    if not tools:
        raise PolicyError("spend_limits.tools must name at least one tool")
    max_transaction = sl.get("max_transaction")
    max_total = sl.get("max_total")
    if max_transaction is None and max_total is None:
        raise PolicyError("spend_limits must set max_transaction and/or max_total")
    return SpendLimits(
        tools=tools,
        amount_field=_string("spend_limits.amount_field", sl.get("amount_field"), "amount"),
        max_transaction=(float(_number("spend_limits.max_transaction", max_transaction, minimum=0))
                         if max_transaction is not None else None),
        max_total=(float(_number("spend_limits.max_total", max_total, minimum=0))
                  if max_total is not None else None),
        currency=_string("spend_limits.currency", sl.get("currency"), "USD"),
    )


def _address_allowlist(raw: Dict[str, Any]) -> Optional[AddressAllowlist]:
    if raw.get("address_allowlist") is None:
        return None
    al = _mapping("address_allowlist", raw["address_allowlist"])
    _check_keys("address_allowlist", al, _ADDRESS_ALLOWLIST)
    tools = _str_list("address_allowlist.tools", al.get("tools", []))
    if not tools:
        raise PolicyError("address_allowlist.tools must name at least one tool")
    addresses = _str_list("address_allowlist.addresses", al.get("addresses", []))
    if not addresses:
        raise PolicyError("address_allowlist.addresses must list at least one address")
    return AddressAllowlist(
        tools=tools,
        address_field=_string("address_allowlist.address_field", al.get("address_field"), "to"),
        addresses=addresses,
        case_sensitive=_boolean("address_allowlist.case_sensitive", al.get("case_sensitive", False)),
    )


def _tool_effects(raw: Dict[str, Any]) -> Dict[str, List[str]]:
    value = raw.get("tool_effects")
    if value is None:
        return {}
    mapping = _mapping("tool_effects", value)
    out: Dict[str, List[str]] = {}
    for tool, effects in mapping.items():
        if not isinstance(tool, str) or not tool:
            raise PolicyError("tool_effects keys must be non-empty tool-name strings")
        out[tool] = _str_list("tool_effects.%s" % tool, effects)
    return out


def _agent_roles(raw: Dict[str, Any]) -> Dict[str, AgentRole]:
    value = raw.get("agent_roles")
    if value is None:
        return {}
    mapping = _mapping("agent_roles", value)
    out: Dict[str, AgentRole] = {}
    for name, spec in mapping.items():
        if not isinstance(name, str) or not name:
            raise PolicyError("agent_roles keys must be non-empty agent-name strings")
        spec = _mapping("agent_roles.%s" % name, spec if spec is not None else {})
        _check_keys("agent_roles.%s" % name, spec, _AGENT_ROLE)
        out[name] = AgentRole(
            effects=_str_list("agent_roles.%s.effects" % name, spec.get("effects", [])),
            tools=(_str_list("agent_roles.%s.tools" % name, spec["tools"]) if spec.get("tools") is not None
                   else None),
            can_delegate_to=(_str_list("agent_roles.%s.can_delegate_to" % name, spec["can_delegate_to"])
                             if spec.get("can_delegate_to") is not None else None),
        )
    for name, role in out.items():
        for target in role.can_delegate_to or []:
            if target not in out:
                raise PolicyError("agent_roles.%s.can_delegate_to names %r, which is not a declared agent role"
                                  % (name, target))
    return out


def parse_policy(text: str) -> Policy:
    try:
        raw = yaml.safe_load(text)
    except yaml.YAMLError as exc:
        raise PolicyError("policy is not valid YAML: %s" % exc)
    raw = _mapping("policy", raw if raw is not None else {})
    _check_keys("policy", raw, _TOP)

    version = str(raw.get("version", POLICY_VERSION))
    if version != POLICY_VERSION:
        raise PolicyError("unsupported policy version %r (this AgentSec understands %r)"
                          % (version, POLICY_VERSION))

    if "agent" not in raw:
        raise PolicyError("`agent` section is required")
    a = _mapping("agent", raw["agent"])
    _check_keys("agent", a, _AGENT)
    if not isinstance(a.get("name"), str) or not a["name"]:
        raise PolicyError("agent.name is required and must be a string")
    if not isinstance(a.get("endpoint"), str) or not a["endpoint"]:
        raise PolicyError("agent.endpoint is not set. Set agent.endpoint to your agent's URL "
                          "(see docs/agent-contract.md)")
    if not a["endpoint"].startswith(("http://", "https://")):
        raise PolicyError("agent.endpoint must start with http:// or https://")

    pricing: Optional[Pricing] = None
    if "pricing" in a:
        p = _mapping("agent.pricing", a["pricing"])
        _check_keys("agent.pricing", p, _PRICING)
        pricing = Pricing(
            input_per_1k=float(_number("agent.pricing.input_per_1k", p.get("input_per_1k", 0))),
            output_per_1k=float(_number("agent.pricing.output_per_1k", p.get("output_per_1k", 0))),
        )
    headers = a.get("headers", {})
    if not isinstance(headers, dict) or not all(isinstance(k, str) and isinstance(v, str) for k, v in headers.items()):
        raise PolicyError("agent.headers must be a mapping of strings")

    agent = AgentConfig(
        name=a["name"], endpoint=a["endpoint"],
        model=str(a.get("model", "agentsec-target")),
        api_key_env=a.get("api_key_env"), headers=dict(headers),
        timeout_s=float(_number("agent.timeout_s", a.get("timeout_s", 30), minimum=0.1)),
        declare_tools=bool(a.get("declare_tools", True)),
        stream=_boolean("agent.stream", a.get("stream", False)),
        retrieval_tools=_str_list("agent.retrieval_tools", a.get("retrieval_tools", [])),
        pricing=pricing,
    )

    lim = _mapping("limits", raw.get("limits", {}))
    _check_keys("limits", lim, _LIMITS)
    limits = Limits()
    for key in ("max_steps", "max_tool_calls", "max_repeated_calls", "max_tokens"):
        if key in lim:
            setattr(limits, key, _number("limits.%s" % key, lim[key], integer=True, minimum=1))
    for key in ("max_seconds", "max_cost_usd"):
        if key in lim:
            setattr(limits, key, float(_number("limits.%s" % key, lim[key], minimum=0)))

    judge: Optional[JudgeConfig] = None
    if raw.get("judge") is not None:
        j = _mapping("judge", raw["judge"])
        _check_keys("judge", j, _JUDGE)
        if not isinstance(j.get("endpoint"), str) or not j["endpoint"].startswith(("http://", "https://")):
            raise PolicyError("judge.endpoint is required and must start with http:// or https://")
        jh = j.get("headers", {})
        if not isinstance(jh, dict) or not all(isinstance(k, str) and isinstance(v, str) for k, v in jh.items()):
            raise PolicyError("judge.headers must be a mapping of strings")
        # Membership against JUDGE_CHECKS is deliberately NOT enforced here: a policy's
        # `checks:` list may name a check a `attack_packs:` entry provides, and packs are not
        # loaded until run time. See build_scenarios()'s equivalent deferral for `tests:`, and
        # run_suite()'s "unknown judge check" validation, which runs once packs are loaded.
        checks = _str_list("judge.checks", j.get("checks", list(JUDGE_CHECKS)))
        conf = float(_number("judge.min_confidence", j.get("min_confidence", 0.7)))
        if conf > 1:
            raise PolicyError("judge.min_confidence must be between 0 and 1")
        severity = j.get("severity", "medium")
        if severity not in ("low", "medium", "high"):
            raise PolicyError("judge.severity must be low, medium or high (model-assisted findings are never critical)")
        judge = JudgeConfig(
            endpoint=j["endpoint"], model=str(j.get("model", "judge")), api_key_env=j.get("api_key_env"),
            headers=dict(jh), timeout_s=float(_number("judge.timeout_s", j.get("timeout_s", 60), minimum=0.1)),
            checks=checks, min_confidence=conf, severity=severity)

    allowed = raw.get("allowed_tools")
    return Policy(
        agent=agent,
        allowed_tools=_str_list("allowed_tools", allowed) if allowed is not None else None,
        forbidden_actions=_str_list("forbidden_actions", raw.get("forbidden_actions", [])),
        tool_effects=_tool_effects(raw),
        agent_roles=_agent_roles(raw),
        secrets=_str_list("secrets", raw.get("secrets", [])),
        limits=limits,
        spend_limits=_spend_limits(raw),
        address_allowlist=_address_allowlist(raw),
        tests=_str_list("tests", raw.get("tests", [])),
        attack_packs=_str_list("attack_packs", raw.get("attack_packs", [])),
        judge=judge,
        version=version,
        source_sha256=_sha(text),
    )


def load_policy(path: str) -> Policy:
    try:
        with open(path, "r", encoding="utf-8") as fh:
            text = fh.read()
    except OSError as exc:
        raise PolicyError("cannot read policy file %s: %s" % (path, exc))
    return parse_policy(text)
