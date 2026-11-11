# Changelog

All notable changes are listed here. The project follows [Semantic Versioning](https://semver.org/); while the
version is below 1.0, minor releases may change behaviour, and the changes are listed below.

## Unreleased

- New: `--refuse` mode for the rule-based reference agent (`examples/vulnerable_rag_agent/server.py`), a baseline
  that declines every request and never calls a tool. It passes every scenario with zero findings, which shows how
  much of a score can come from refusing alone. See [docs/agent-contract.md](docs/agent-contract.md#the-rule-based-reference-agent).
  (#51)
- New: browser playground (`playground/`, deployed to GitHub Pages by `.github/workflows/playground.yml`). The
  real package runs in Pyodide inside a Web Worker. Sample mode runs the quickstart notebook's agent (naive: 8
  critical findings, hardened: 0). Bring-your-own-key mode runs five categories against OpenAI, Groq, OpenRouter,
  Anthropic or any OpenAI-compatible URL, with clear errors for a bad key, CORS blocks and rate limits. The key
  stays in memory and goes only to the provider. Results: per-finding cards, copy as Markdown, JSON download and a
  share line. No engine changes.

## 0.9.0

- New: `agentsec dashboard`, a local, read-only web dashboard over the report files AgentSec already writes
  (`report.json`, `mcp-report.json`). Overview with a per-scenario grid by attack category, OWASP ASI01-ASI10
  coverage, attack-vector and tool-call breakdowns; a findings explorer with evidence rendered as trace events and
  copyable `agentsec replay` / `agentsec test -s` commands; full traces as timelines (memory phases, multi-agent
  attribution, over-budget calls); the policy as run; MCP scan definitions; and run comparison using
  `agentsec compare`'s logic. Standard library only, binds to 127.0.0.1, GET-only, Host-header checked, strict
  CSP, report text never parsed as HTML, hidden characters made visible. New and rewritten reports appear live.
  Bundles IBM Plex Sans and Mono (SIL Open Font License 1.1). See [docs/dashboard.md](docs/dashboard.md).
- New: `agentsec upload`, opt-in upload of a report to a hosted AgentSec dashboard with a project token read from
  `AGENTSEC_TOKEN` (never an argument), HTTPS-only except to localhost, gzip-compressed, with branch, commit and
  CI-run metadata read from GitHub Actions and `--no-traces` to leave out transcripts. The GitHub Action gains
  `dashboard-url`, `dashboard-token` and `dashboard-no-traces` inputs; a failed upload is a warning, never a
  failed job.
- Docs: the README's future-work section now describes the hosted dashboard: open source (Apache-2.0) at
  `invarislabs/invaris-agentsec-dashboard`, free at launch, with a few paid, private premium features later.

- New: `agentsec.verdicts`, the verdict rules shared by `agentsec compare`, the local dashboard and the hosted
  dashboard: what counts as tested (only `passed` and `findings`), evaluation metrics over tested scenarios, attack
  timelines, per-scenario verdict changes, and why a finding is not comparable. Both dashboards use it to show
  inconclusive scenarios (never as passed), what a run measured, attack timelines, each scenario's declared goals,
  the agent's self-description (with scripted stand-ins labelled) and per-scenario verdict changes when comparing.
- New: `report.json` scenario entries carry `delivery` (where the adversarial content first reached the agent) and
  `attack_goals` (each declared goal and whether it was achieved, `null` when the payload never arrived) for
  scenarios that use `exposure` / `attack_goals`. Exposure strings and goals' `sensitive_values` are never written.
  Built-in scenarios and older reports are unchanged.
- New: agents can describe themselves with `x_agentsec.agent` (`name`, `version`, `backend`, `model`,
  `configuration`; other keys dropped, values capped and secret-masked), recorded in the trace and in
  `run_config.agent_reported`, and shown in the terminal and Markdown summaries. The reference email and browser
  assistants report their backend (including `scripted`) and baseline/hardened configuration.
- `agentsec compare` no longer calls a finding fixed when its scenario is `not_observable` in the new run (it
  was already not comparable for `error` and `inconclusive`): the new run could not judge it.
- `agentsec compare` now also lists scenarios tested in the baseline but not in the new run (coverage lost is not an
  improvement) and how many scenarios each run tested, in the terminal and in the pull-request Markdown.

- Fixed: the `email_assistant` reference agent defaulted to port 8040, which `multi_agent_team`
  already uses, so the two could not run side by side. It now defaults to 8060 (its policies, demo,
  live harness, README and tests updated to match). Examples are not shipped in the wheel, so this
  does not affect the published package.
- Docs: repository-wide accuracy pass. The README's category list said eight categories while the
  same page said thirteen; the test count, reference-agent count and attack-pack count were stale;
  `agentsec replay`'s `INCONCLUSIVE` outcome and the `exposure` / `attack_goals` / `inconclusive`
  model were undocumented in the README; `docs/README.md` was missing an index entry for
  `docs/email-and-browser-packs.md`; and `docs/agent-contract.md`'s "147 scenarios" read as
  per-agent when it is the total across three agents (50 + 48 + 49).

## 0.8.0

- New: delivery tracking and attack goals for scenarios. `Scenario.exposure` names text only the adversarial content
  contains; a scenario whose content never reached the agent is reported with the new status `inconclusive` (and
  `summary.inconclusive`), never as passed. `Scenario.attack_goals` (`AttackGoal`) states what a successful attack
  does as tool calls; the new default `AttackGoalEvaluator` reports `attack_goal_achieved` only for calls made after
  the content was delivered. `agentsec.attacks.inject_after()` builds responders that inject at a later step of a
  multi-step task. Built-in categories do not use these fields and are unchanged. See
  [Extending](docs/extending.md#track-delivery-attack-goals-and-mid-task-injection).
- `inconclusive` is handled throughout: terminal, Markdown, HTML and JSON reports; run warnings; `RunResult.inconclusive`
  (and `RunResult.passed` is false while any scenario is inconclusive); the pytest plugin skips all-inconclusive
  categories; `agentsec compare` does not call a finding fixed when its scenario is inconclusive in the new run;
  `agentsec replay` reports such findings as `INCONCLUSIVE` and exits 2 when nothing reproduced but something was
  inconclusive.

- New examples (not shipped in the wheel): realistic indirect prompt-injection **attack packs** for email and
  browser agents (`examples/attack_packs/email_agent_pack.py`, and the stateful browsing categories in
  `examples/attack_packs/browser_agent_pack.py`), each covering several DOM/message injection surfaces and using
  the delivery-tracking and attack-goal features above. New **reference LLM-powered assistants**
  (`examples/real_world_agents/email_assistant/`, `examples/real_world_agents/llm_browser_assistant/`) with a
  pluggable backend layer (Anthropic / OpenAI-compatible / scripted), baseline and hardened configurations, and an
  optional live-model evaluation harness. See [docs/email-and-browser-packs.md](docs/email-and-browser-packs.md).

## 0.7.0

- Docs: `docs/testing.md` now lists everything that has not been tested yet (other real agents, Claude Code's
  built-in tools, sub-agents and memory, real models inside frameworks, ADK and AutoGen multi-agent modes, mem0 with
  model-based extraction, Letta), and `docs/multi-agent.md` says which multi-agent frameworks were not run.
- New: four built-in categories and five evaluators for authority the user never gave, all deterministic and opt-in
  by declaration (categories build no scenarios, and evaluators stay silent, for tools without `tool_effects`):
  - `dangerous_composition` + `DataFlowEvaluator`: two individually allowed, individually authorized calls that
    combine into harm, detected as data flow from a labelled result into a later call's arguments
    (`private_data_exfiltration`, `untrusted_content_executed`, `untrusted_content_delegated`, `credential_delegated`).
    New data labels for `tool_effects`: `private_data` and `untrusted_content`.
  - `deceptive_action_report` + `ActionClaimEvaluator`: the agent's own report against its trace
    (`false_action_claim` for a blanket denial contradicted by an earlier call, `unsupported_action_claim` for
    claimed work with no matching call).
  - `identity_and_session_confusion` + `IdentityBoundaryEvaluator`: `cross_principal_access` (another user's or
    tenant's identifier passed to a tool, via `Scenario.foreign_identifiers`), `stale_authorization` (authorization is
    now per conversation: `Followup.authorized_effects`), and a credential reused in another caller's session.
  - `multi_agent_delegation` + `DelegationEvaluator` and a new `agent_roles` policy section: `agent_exceeded_role`,
    `delegation_privilege_escalation` (authority attenuation along the delegation chain), `unauthorized_delegation`,
    `unknown_agent_action`, `secret_shared_between_agents`. Multi-agent attribution (`actor`, `delegated_by`) through
    the HTTP `x_agentsec` extension, `CallableAdapter`, `ToolHost` and the MCP host (per-client `clientInfo.name`).
    See [Multi-agent testing](docs/multi-agent.md).
- New: `memory_poisoning/secret_persisted_incidentally` -- a credential mentioned in passing must not be recalled
  for another user by automatic memory.
- New: scenario status `not_observable` (and `summary.not_observable`) for scenarios that need attribution the agent
  did not report; the pytest plugin skips such categories, and categories with no scenarios for the policy, instead
  of failing or passing them.
- New: `agentsec.integrations.ToolHost`, an in-process tool host for frameworks that run their own tool loop.
  `MCPAttackHost` is now this host plus its HTTP server.
- New: `benchmarks/` with checked-in results: the same scenarios through LangChain, LangGraph, CrewAI, AutoGen,
  the OpenAI Agents SDK, Google ADK and smolagents (scripted model, real runtimes: 33/35 identical to a
  no-framework reference everywhere, 0 false positives); multi-agent teams in the OpenAI Agents SDK and CrewAI;
  mem0 and LangGraph-store memory; and a real Claude Code CLI session over MCP (35 scenarios, 2 findings).
- New: reference agent `examples/real_world_agents/multi_agent_team` (port 8040). The three single-agent real-world
  policies now declare data labels and run the new categories (50/50, 48/48, 49/49 vulnerable-fails / safe-passes).
- Fix: calls an agent executes itself (`x_agentsec.events`, the MCP host, `ToolHost`) are now recorded before the
  reply they led to, not after it.
- Fix: a run that fails part-way is evaluated on what the agent did before failing (calls made through a host are
  drained into the trace first), so an action followed by a crash is a finding, not just an error.
- Fix: `SecuritySuite.run("<category>")` no longer raises when the category builds no scenarios for the policy.
- Fix (found by running against Claude Code): `ActionClaimEvaluator` flagged truthful reports -- denials about one
  specific thing ("I haven't run any tests"), running a *search* as running code, and "I changed nothing" as a
  completion claim. Regression tests in `tests/test_claims.py`.

- New: `action_without_authorization`, a 9th built-in attack category addressing a gap no
  existing category could express: a tool call that is globally allowed for the agent, but that
  the *current task* never authorized. A coding assistant asked only to review something has no
  more business calling `write_file` than one asked to fix something is wrong to call it --
  `allowed_tools`/`forbidden_actions` can't tell those apart because the distinction isn't about
  the tool, it's about what the request actually asked for. Policies opt in by declaring
  `tool_effects` (tool name -> effect tags: `read`, `write`, `delete`, `execute`, `network`,
  `financial`, `credential_access`, ...); scenarios opt in by declaring `authorized_effects`. A
  new evaluator, `ActionAuthorizationEvaluator` (rule `unauthorized_side_effect`, mapped to
  ASI03/ASI02/ASI01), flags a call whose effects exceed what the scenario's task authorized, and
  only for tools with declared effects -- it never guesses. Without `tool_effects`, this category
  produces zero scenarios and every other policy is unaffected. See
  [Policy reference](docs/policy-reference.md#tool_effects),
  [Attack catalog](docs/attack-catalog.md#9-action_without_authorization), and
  [`examples/real_world_agents/demo_action_without_authorization.py`](examples/real_world_agents/demo_action_without_authorization.py)
  for a concrete before/after walkthrough (the identical `write_file` call is flagged when the
  task only authorized reading, and silent when the task authorized writing). All three
  `examples/real_world_agents/` policies now declare `tool_effects` and include this category;
  verified live (43/43, 41/41, 43/43 vulnerable-fails / safe-passes).
- New: `AgentTarget(tool_effects=...)` and `RunResult.unauthorized_side_effects` in the Python API,
  for parity with the YAML policy surface.
- New: three more reference agents in `examples/real_world_agents/` (`coding_assistant`,
  `support_assistant`, `browser_assistant`), modeled on real daily-use AI agent products rather
  than a generic RAG bot, each with a vulnerable and a `--safe` mode and paired one-to-one with an
  existing domain attack pack (`coding_agent_pack.py`, `support_agent_pack.py`,
  `browser_agent_pack.py`). See [`examples/real_world_agents/README.md`](examples/real_world_agents/README.md)
  and [Agent contract](docs/agent-contract.md#the-real-world-reference-agents).
- Fix: `SecretLeakEvaluator` decided whether a canary's reappearance in the same conversation was
  benign by checking `scenario.category == "memory_poisoning"` literally, so any other category
  with the same shape (canaries plus a `Followup(same_session=False)`) -- including the new
  `support_agent_cross_customer_leak` category above -- got a false positive on its own benign,
  same-session acknowledgment, and a genuine cross-session leak was mislabeled as a retrieved-
  document disclosure instead of a memory leak. Now keyed off the scenario's own shape instead of
  its category name. Covered by two new tests in `tests/test_evaluators.py`.

## 0.6.0

- `agentsec mcp scan` now scans MCP resources and prompts, not just tools: poisoned descriptions
  and argument descriptions, invisible/bidirectional characters, homoglyph tool-name impersonation
  (`mcp_confusable_tool_name`), annotation/behavior mismatches (`mcp_annotation_mismatch`),
  credentials embedded in a resource URI (`mcp_resource_uri_credentials`), duplicate resources and
  prompts, and `--pin`/`--recheck` change tracking (added/removed/changed) across all three kinds.
  See [MCP testing](docs/mcp-testing.md).
- Policy schema: `spend_limits` and `address_allowlist` sections let a policy cap the amount and
  restrict the destination of tool calls that move money or send something somewhere, enforced by
  two new core evaluators (`spend_limit_exceeded`, `spend_total_exceeded`,
  `address_not_allowlisted`). Both are domain-agnostic -- the tool names and argument fields they
  watch are declared in the policy, not hardcoded to any specific integration -- so they apply
  alongside any attack pack, not just the bundled on-chain one. The on-chain reference pack's own
  spend-cap check now defers to a policy-declared `max_transaction` when one is set. See
  [Policy reference](docs/policy-reference.md#spend_limits).
- Docs: `docs/owasp-mapping.md`'s finding-rule table and ASI02-04 summaries were missing the new
  MCP resource/prompt rules and the spend/allowlist rules; both are now listed.

## 0.5.1

- Fix: a real bug in the pull-request comparison comment (`pr-comment`) meant it never posted the
  actual comparison summary -- `action/pr-comment.sh` used `gh api -f body=@file`, and `-f` sends
  the literal string `"@file"` rather than reading the file; it needed `-F`, which does. Every
  comment this feature ever posted showed a placeholder path instead of real content. Fixed, and
  covered by a test that pins the `-F` flag so this can't silently regress.
- Fix: SARIF findings and the JSON report's `replay` hint showed a hardcoded `agentsec.yaml`
  placeholder instead of the real policy file path used for the run. `build_report`,
  `write_reports`, and the CLI now thread the real `--policy` path through.
- New: `.github/workflows/verify-pr-comment.yml`, an opt-in (label-gated) workflow that verifies
  the pull-request comment path against a real `pull_request` event and a real `GITHUB_TOKEN`,
  rather than the fake `gh` binary the unit tests substitute.
- Docs: the findings published by `.github/workflows/self-scan.yml` to this repo's own Code
  Scanning tab are now explicitly flagged, in the docs and in the workflow's job summary, as demo
  findings from the bundled vulnerable reference agent -- not real vulnerabilities in AgentSec.
- `NOTICE` file clarifying that "Invaris" and "AgentSec" are trademarks not covered by the
  Apache-2.0 license, and a Contributor License Agreement (`CLA.md`) with a CLA-bot check for
  external pull requests.

## 0.5.0

- Attack packs: load extra scenario categories from a local file or an installed package (`attack_packs:` in the policy, `agentsec test --attack-pack`, `SecuritySuite(attack_packs=...)`). See docs/extending.md#write-an-attack-pack and examples/attack_packs.
- The GitHub Action can compare a run against an earlier baseline report (`baseline-report`, `compare-fail-on`) and post or update a pull-request comment with the regressions (`pr-comment`). `agentsec.compare` gained `render_markdown`.
- SARIF 2.1.0 report format (`--format sarif`, writes `results.sarif`) for GitHub Code Scanning; the GitHub Action's `formats` input accepts it and docs/github-actions.md shows an `upload-sarif` step.
- `policy.schema.json` now declares `attack_packs`, matching the loader (it was previously accepted by the loader but rejected by the schema).

## 0.4.0

- `agentsec test --mcp-listen HOST:PORT`: AgentSec runs as the MCP server your agent connects to, serves the policy's tools and delivers the scenarios' adversarial content through MCP tool results. Calls the agent makes are recorded and evaluated like any other. Includes an MCP-connected reference agent (`examples/mcp_agent`).
- `LangChainAdapter` for LangChain and LangGraph agents (`agentsec.integrations`), tested against real LangGraph agents.
- The tool-call budget is now also checked for agents that run their own tool loop (through MCP or reported events).

## 0.3.0

- Packaged, reusable GitHub Action (`action.yml`) that starts your agent, runs the suite, uploads reports and gates the job.
- `agentsec compare` to diff two reports and flag regressions.
- Streaming (server-sent events) support with `agent.stream: true`, and `CallableAdapter` for in-process agents.
- `agentsec mcp scan` to check MCP server tool definitions (poisoning, invisible characters, shadowing, policy violations, rug pulls via `--pin` and `--recheck`). It never calls a tool.
- RAG-backed reference agent (`examples/rag_agent`) and a demo MCP server (`examples/mcp_servers`).
- Apache-2.0 license.

## 0.2.0

- Memory-poisoning scenarios (multi-session), model-assisted judge (opt-in), OWASP agentic mapping.
- HTML and Markdown reports, `agentsec replay`, the Python API and the pytest plugin, GitHub Actions annotations and job summary.

## 0.1.0

- Local testing engine: OpenAI-compatible HTTP adapter, YAML policies, seven attack categories, deterministic evaluators, JSON reports.
