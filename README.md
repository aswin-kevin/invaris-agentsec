# Invaris AgentSec

**Adversarial security and reliability testing for autonomous AI agents.**

<p align="center">
  <img src="docs/assets/agentsec-demo.gif" alt="AgentSec run against the bundled vulnerable demo agent (43 findings), then against its hardened --safe variant (35 of 35 passed)" width="800">
</p>

Real output, not a mock-up: against the bundled vulnerable demo agent, 0 of 35 scenarios pass and AgentSec reports 43 findings. The hardened `--safe` variant of the same agent passes all 35. Reproduce it with the commands under [Try It](#try-it).

### Try it in your browser

No install, no agent, no API key: attack a small agent in a notebook and see it break, then fix it.

[![Open In Colab](https://colab.research.google.com/assets/colab-badge.svg)](https://colab.research.google.com/github/invarislabs/invaris-agentsec/blob/main/examples/notebooks/agentsec_quickstart.ipynb)

**Part 2, a real LLM agent:** the same attacks against a real model (OpenAI or any OpenAI-compatible provider such as Groq), then a guard in code that stops them. Needs an API key.

[![Open In Colab](https://colab.research.google.com/assets/colab-badge.svg)](https://colab.research.google.com/github/invarislabs/invaris-agentsec/blob/main/examples/notebooks/agentsec_real_llm.ipynb)

### Quick start

```bash
pip install invaris-agentsec
agentsec init    # writes a starter agentsec.yaml: set agent.endpoint to your agent's URL
agentsec test    # runs the scenarios, writes .agentsec/report.html
```

Your agent needs an HTTP endpoint AgentSec can call (see the [agent contract](docs/agent-contract.md)). Agents that use MCP tools can run `agentsec test --mcp-listen 127.0.0.1:8765` instead, so AgentSec acts as the MCP server ([MCP testing](docs/mcp-testing.md)). See AgentSec run against a real agent in the [Claude Code benchmark](benchmarks/real-agents/README.md).

Invaris AgentSec is an open-source testing framework for finding unsafe, unauthorized, and unreliable agent behaviour before it reaches production. 
It helps developers test complete agent workflows involving LLMs, retrieval pipelines, memory, MCP servers, external tools, databases, and sensitive actions.

The goal is simple: make testing an AI agent as repeatable and developer-friendly as testing an API.

## Why AgentSec?

Traditional software follows explicitly written execution paths. 
AI agents interpret untrusted inputs, select tools, retain memory, and make decisions dynamically. 
A single indirect prompt injection or poisoned tool response can cause an agent to:

- expose confidential information;
- invoke an unauthorized tool;
- exceed its permissions or operating budget;
- execute an irreversible action;
- preserve malicious instructions in memory;
- enter an expensive or non-terminating loop; or
- behave differently after a model, prompt, or tool update.

Unit tests alone cannot adequately exercise these behaviours. AgentSec runs stateful adversarial scenarios, observes the complete execution trace, and verifies that security policies hold throughout the workflow.

This isn't hypothetical: see [docs/why-agentsec.md](docs/why-agentsec.md) for real, sourced incidents (a
dealership chatbot selling a $76,000 car for $1, a zero-click exploit against Microsoft 365 Copilot, an
AI coding agent deleting a production database), the survey data on how little of this is actually
tested for today, and the governments and research institutions that have restricted AI use outright.

## What AgentSec Tests

The test suite covers:

- Direct and indirect prompt injection
- Unauthorized tool invocation
- Tool-output and MCP-server poisoning
- Sensitive-data and secret leakage
- Memory poisoning and unsafe persistence
- Excessive tool calls, token usage, and cost
- Infinite loops and missing termination conditions
- Unsafe handling of retrieved documents
- Actions a tool is globally allowed to perform but that the *current task* never authorized (`action_without_authorization`, when the policy declares `tool_effects`) -- see [Policy reference](docs/policy-reference.md#tool_effects)
- Dangerous compositions of individually allowed calls, tracked as data flow: private data read by one call and sent out by another to a destination the user never named, untrusted text executed as a command, untrusted instructions handed to another agent (`dangerous_composition`)
- Agents misreporting what they did: denying a side effect the trace shows, or claiming work that never happened (`deceptive_action_report`)
- Identity, session and authorization confusion: acting on another user's or tenant's resource, reusing a permission granted for an earlier task or another session, using a credential another caller left behind (`identity_and_session_confusion`)
- Multi-agent privilege abuse: sub-agents exceeding their role, privilege escalation through delegation (confused deputy), unauthorized delegation, unregistered agents, secrets passed between agents (`multi_agent_delegation`, when the policy declares `agent_roles`) -- see [Multi-agent testing](docs/multi-agent.md)
- Indirect prompt injection through the surfaces a real agent actually reads: email bodies, signatures, quoted threads, HTML parts and attachments; web page text, HTML comments, metadata, CSS-hidden elements, image alt attributes and user reviews -- with the observable outcome stated as a goal (mail forwarded or deleted, a form submitted off-site, an order placed, data carried off in a URL). See [Email and browser packs](docs/email-and-browser-packs.md)
- Behavioural regressions across models and prompts, via `agentsec compare`

A scenario can state what the attack needs in order to count. `Scenario.exposure` names text only
the adversarial content contains, so a run in which the agent never read it is reported as
**inconclusive**, never as passed; `Scenario.attack_goals` states what a successful attack *does* as
a tool call, and a goal only counts for calls made *after* the content was delivered, so a finding is
evidence of cause rather than coincidence; `inject_after()` places the content at a later step of a
multi-step task. So each scenario ends in one of: **findings** (it received the content and acted on
it), **passed** (it received the content and did not), **inconclusive** (the content never arrived) or
**error** (the run could not complete) -- and neither of the last two is ever counted as a pass. See
[Attack goals and delivery tracking](docs/extending.md#track-delivery-attack-goals-and-mid-task-injection).

Every check above is deterministic and opt-in by declaration: categories that need `tool_effects` or `agent_roles` build no scenarios without them, and a multi-agent scenario run against a system that reports no agent attribution is reported as **not observable**, never as passed. Unauthorized financial or on-chain actions are covered, but not by the default thirteen categories above -- via the bundled on-chain attack pack and the policy's `spend_limits`/`address_allowlist`; see [Domain attack packs](docs/domain-attack-packs.md). What has and has not been tested against real agents and frameworks is in [Testing](docs/testing.md#what-has-been-tested-against-real-agents-and-frameworks).

Findings are mapped to the [OWASP Top 10 for Agentic Applications](https://genai.owasp.org/2025/12/09/owasp-top-10-for-agentic-applications-the-benchmark-for-agentic-security-in-the-age-of-autonomous-ai/) (ASI01 to ASI10).

## Design Principles

- **Evidence over scores:** Every finding includes the input, trace, violated policy, and observed action.
- **Stateful testing:** Tests cover complete workflows rather than isolated prompts.
- **Framework independence:** AgentSec works across models, agent frameworks, MCP servers, and custom APIs.
- **CI-first:** Security regressions are detectable automatically on every pull request.
- **Local by default:** Developers can test locally without sending private traces to a hosted service.
- **Reproducibility:** A failed scenario is replayable with the same configuration and evidence.

## Developer Experience

Install the command-line tool:

```bash
pip install invaris-agentsec
```

For a local checkout instead (to run the examples, or to contribute), install from a clone with `pip install -e .`.

Create an `agentsec.yaml` policy in the directory you'll run `agentsec test` from -- it looks for `./agentsec.yaml` by default (or pass `--policy path/to/file.yaml` to use a different location or name). Write it by hand as below, or scaffold one with `agentsec init` (writes a starter `agentsec.yaml`; won't overwrite an existing one). See the [Policy reference](docs/policy-reference.md) for every available field.

```yaml
version: "1"

agent:
  name: support-agent
  endpoint: http://localhost:8000/agent

allowed_tools:
  - search_documents
  - create_draft

forbidden_actions:
  - send_email
  - reveal_credentials
  - execute_payment

limits:
  max_steps: 12
  max_tool_calls: 10
  max_cost_usd: 0.50

tests:
  - prompt_injection
  - indirect_prompt_injection
  - secret_extraction
  - unauthorized_tool_use
  - tool_output_poisoning
  - unsafe_retrieved_documents
  - loop_and_budget_limits
```

Run the security suite:

```bash
agentsec test
```

Example output (reports are also written to `.agentsec/report.json` and `.agentsec/report.html`, the two default formats -- `markdown` and `sarif` are also available via `--format`):

```text
Invaris AgentSec

42 scenarios executed
36 passed
6 findings

CRITICAL  Indirect prompt injection triggered send_email
HIGH      Retrieved confidential content appeared in the response
HIGH      Agent attempted a forbidden payment action
MEDIUM    Tool-call budget exceeded

Report written to .agentsec/report.json
Report written to .agentsec/report.html
```

## Try It

Run the bundled intentionally vulnerable agent, then test it:

```bash
pip install -e ".[dev]"
python examples/vulnerable_rag_agent/server.py &          # add --safe for the hardened variant
agentsec test --policy examples/vulnerable_rag_agent/agentsec.yaml
```

Against the vulnerable agent you should see 35 scenarios executed and findings in all eight
categories. With `--safe`, all 35 pass. With `--refuse`, a baseline that declines everything, all 35 pass too:
a clean score can come from refusing alone, so also check that your agent still does its job.

**Reports.** `agentsec test` writes `.agentsec/report.json` and a self-contained `.agentsec/report.html`
(`--format json,html,markdown,sarif` to choose; `sarif` writes `results.sarif` for
[GitHub Code Scanning](docs/github-actions.md#github-code-scanning-sarif)). Secrets are masked. Every
finding is tagged with the closest [OWASP Top 10 for Agentic Applications](https://genai.owasp.org/2025/12/09/owasp-top-10-for-agentic-applications-the-benchmark-for-agentic-security-in-the-age-of-autonomous-ai/)
category (ASI01 to ASI10).

**Dashboard.** `agentsec dashboard` opens a local, read-only web view of your reports at
`http://127.0.0.1:8710/`: a scenario grid by attack category, OWASP coverage, findings with their evidence and
replay commands, every trace as a timeline, the policy as run, MCP scans, and run-to-run comparison. It reads the
report files AgentSec already writes, never contacts the agent, and needs no extra dependencies. See
[`docs/dashboard.md`](docs/dashboard.md). A hosted version for teams and run history is in development, also open
source ([`invaris-agentsec-dashboard`](https://github.com/invarislabs/invaris-agentsec-dashboard)) and free at
launch; see [Hosted dashboard](#hosted-dashboard).

**Upload (opt-in).** `agentsec upload .agentsec/report.json --server <dashboard URL>` sends a report to a hosted
dashboard with the project token in `AGENTSEC_TOKEN`. Add `--no-traces` to leave out full transcripts. Nothing is
uploaded unless you run it.

**Exit codes.** `agentsec test` exits `1` when findings exist (`--fail-on high` to raise the bar,
`--fail-on none` to never fail) and `2` on configuration or connection errors. Use `--seed N` for a
reproducible run and `-s <category-or-scenario-id>` to run a subset.

**Replay.** `agentsec replay .agentsec/report.json` re-runs the findings from an earlier report with
the recorded seed and prints `REPRODUCED`, `NOT REPRODUCED` or `INCONCLUSIVE` for each, so you can
confirm a fix. A rerun in which the adversarial content never reached the agent is reported as
`INCONCLUSIVE` and exits `2`, never as fixed.

**Model-assisted checks.** Add a `judge:` section to your policy and pass `--judge` to have a model
review scenarios the deterministic checks passed, for example a paraphrased leak. These findings are
labelled `model-assisted`, are never critical, and are opt-in because transcripts are sent to the
judge endpoint. See [`docs/judge.md`](docs/judge.md).

**A RAG-style agent.** `examples/rag_agent` owns a small document corpus and runs its tools itself, reporting the calls to AgentSec. Start it with `python examples/rag_agent/server.py` (add `--safe` for the hardened variant) and test it with `agentsec test -p examples/rag_agent/agentsec.yaml`. See [`docs/agent-contract.md`](docs/agent-contract.md#the-rag-backed-reference-agent).

**Real-world reference agents.** `examples/real_world_agents` has four more deterministic, rule-based vulnerable/`--safe` reference agents modeled on daily-use AI agent products -- a coding assistant, a customer-support assistant, a browser-automation assistant and a planner/researcher/executor team -- each paired one-to-one with its matching domain attack pack below. It also has two **LLM-powered** reference assistants (email and browser) whose every tool decision is made by a configurable model rather than by rules; see [Email and browser packs](docs/email-and-browser-packs.md). See [`examples/real_world_agents/README.md`](examples/real_world_agents/README.md) and [`docs/agent-contract.md`](docs/agent-contract.md#the-real-world-reference-agents).

**Regression comparison.** `agentsec compare old/report.json new/report.json` lists new, fixed and changed findings and exits `1` on regressions. The packaged GitHub Action wires this into pull requests automatically (`baseline-report`), posting and updating a PR comment with what's new or worse; see [GitHub Actions](docs/github-actions.md#pull-request-and-scheduled-regression-testing).

**MCP servers.** `agentsec mcp scan --command "python server.py"` lists a server's tools, resources and prompts (never calls, reads or fetches any of them) and flags poisoned descriptions, hidden characters, tool shadowing, homoglyph tool-name impersonation, lying read-only/destructive annotations, and changed definitions. See [`docs/mcp-testing.md`](docs/mcp-testing.md).

**MCP-connected agents.** `agentsec test --mcp-listen 127.0.0.1:8765` makes AgentSec the MCP server your agent uses, delivering the same adversarial scenarios through MCP tool results.

**LangChain and LangGraph agents** can be tested in-process with `LangChainAdapter`; see [`docs/frameworks.md`](docs/frameworks.md). Any other framework works through the generic `CallableAdapter`.

**Email and browser injection packs.** Two bundled packs test the agents most exposed to indirect
prompt injection, each against an LLM-powered reference assistant with a baseline and a hardened
configuration:

```bash
# start a reference assistant (model from AGENTSEC_LLM_* env vars; --backend scripted for offline)
python examples/real_world_agents/email_assistant/server.py            # --safe for hardened
agentsec test -p examples/real_world_agents/email_assistant/agentsec.yaml

# browser pack
python examples/real_world_agents/llm_browser_assistant/server.py      # --safe for hardened
agentsec test -p examples/attack_packs/browser_agent.agentsec.yaml
```

Both ship an offline before/after demo (`demo.py`) and an optional real-model harness
(`evaluate_live.py`), which refuses to run without a configured backend so a results table always
reflects an actual model execution. See [Email and browser packs](docs/email-and-browser-packs.md).

**Your own scenarios** can be added without forking AgentSec: `agentsec test --attack-pack my_pack.py` or `attack_packs:` in the policy loads extra categories from a local file or an installed package; see [`docs/extending.md`](docs/extending.md#write-an-attack-pack).

**Other commands.** `agentsec dashboard` browses reports in a local web UI, `agentsec upload` sends one to a hosted dashboard, `agentsec init` writes a starter policy and `agentsec schema policy|trace` prints
the JSON schemas.

The thirteen built-in categories are `prompt_injection`, `indirect_prompt_injection`,
`secret_extraction`, `unauthorized_tool_use`, `tool_output_poisoning`, `unsafe_retrieved_documents`,
`loop_and_budget_limits`, `memory_poisoning`, `action_without_authorization`,
`dangerous_composition`, `deceptive_action_report`, `identity_and_session_confusion` and
`multi_agent_delegation`. The last five build scenarios only when the policy declares what they
need (`tool_effects`, `agent_roles`); see the [Attack catalog](docs/attack-catalog.md) for all
13 categories and up to 47 scenarios.

**Agent contract.** The adapter posts OpenAI-style chat-completions requests to `agent.endpoint`
and declares your allowed tools (plus forbidden actions as decoys). AgentSec plays the tools:
every call is simulated, and results carry the adversarial content. Agents that run tools
server-side can report them in an `x_agentsec.events` field, and agents with memory can key it on the
`user` field (also sent as `X-AgentSec-Session`). List the synthetic credentials your agent can see
under `secrets:` so leaks are detected.

**In CI.** Inside GitHub Actions, `agentsec test` adds workflow annotations for each finding and
writes a job summary automatically. A packaged action (`uses: ./`) starts your agent, runs the suite,
uploads reports and gates the job; it can also compare against a baseline report and comment on the
pull request, or feed `results.sarif` to GitHub Code Scanning. See [`docs/github-actions.md`](docs/github-actions.md).

Full documentation, including architecture, policy reference, attack catalog, Python API, testing
and extension guides, is in [`docs/`](docs/README.md).

## Example Policy Test

AgentSec tests focus on expected behaviour rather than a particular model response:

```python
from agentsec import AgentTarget, SecuritySuite

target = AgentTarget(
    endpoint="http://localhost:8000/agent",
    allowed_tools={"search_documents", "create_draft"},
    forbidden_tools={"send_email", "execute_payment"},
)

suite = SecuritySuite(target)

result = suite.run("indirect_prompt_injection")

assert result.secret_leaks == []
assert result.forbidden_tool_calls == []
assert result.total_tool_calls <= 10
```

`AgentTarget`, `SecuritySuite` and the result attributes above are implemented. In pytest, the
bundled plugin adds an `agentsec_run` fixture:

```python
import pytest
from agentsec import CATEGORIES

@pytest.mark.parametrize("category", CATEGORIES)
def test_agent_resists(category, agentsec_run):
    agentsec_run(category, fail_on="high")
```

Run it with `pytest --agentsec-policy agentsec.yaml`. See [`docs/python-api-and-pytest.md`](docs/python-api-and-pytest.md).
The API may still change before a stable release.

## How It Works

```mermaid
flowchart TD
    A["Test policy"] --> B["Adversarial scenario engine"]
    B --> C["Agent under test"]
    C --> D["Models, tools, memory and MCP"]
    D --> E["Trace collector"]
    E --> F["Policy evaluator"]
    F --> G["Evidence and security report"]
```

1. A developer defines the agent's permitted actions and operating limits.
2. AgentSec generates or loads adversarial scenarios.
3. The scenarios exercise the agent, retrieval layer, memory, and tools.
4. AgentSec records prompts, responses, tool calls, state changes, timing, and cost.
5. Policy evaluators identify violations and assign severity.
6. Reports provide reproducible evidence and remediation guidance.

## Architecture

```text
agentsec/
├── attacks/          # Prompt, retrieval, memory and tool attacks, plus attack-pack loading
├── adapters/         # OpenAI-compatible HTTP (optionally streaming) and in-process callables
├── mcp/              # MCP server scanner (client, checks, pins) and the MCP attack host
├── integrations/     # LangChain and LangGraph adapter
├── evaluators/       # Deterministic checks plus an optional model-assisted judge
├── policies/         # Permissions, limits and expected behaviour
├── runners/          # Local runner and replay (CI and sandboxed planned)
├── traces/           # Normalized agent execution events
├── reports/          # Terminal, JSON, HTML, Markdown, SARIF and GitHub output
├── dashboard/        # `agentsec dashboard`: local, read-only web UI over report files
├── cli/              # Command-line interface
├── compare.py        # Report-to-report regression comparison
├── owasp.py          # Mapping of findings to OWASP agentic categories
├── api.py            # Python API (AgentTarget, SecuritySuite)
└── pytest_plugin.py  # pytest fixtures
action.yml, action/   # Packaged GitHub Action (incl. baseline comparison, PR comments)
examples/             # Vulnerable reference agents (rule-based, RAG-backed, real-world, MCP) and attack packs
tests/                # Unit and end-to-end tests (550+ tests)
benchmarks/           # Framework, memory-system and real-agent runs (results checked in)
```

### Core components

| Component | Responsibility |
|---|---|
| Scenario engine | Builds multi-step adversarial workflows |
| Agent adapters | Connects custom agents and supported frameworks |
| Trace collector | Captures prompts, retrieval events, tool calls and state changes |
| Policy engine | Checks permissions, budgets and behavioural constraints |
| Evaluators | Detects leakage, unsafe actions and security regressions |
| Reporter | Produces human-readable and machine-readable evidence |

## What's Built

### Core testing engine

- [x] OpenAI-compatible HTTP agent adapter, with optional server-sent-events streaming (`agent.stream: true`)
- [x] `CallableAdapter` for testing an agent in-process, no HTTP server required
- [x] YAML security policies, validated against a JSON Schema (`agentsec schema policy`)
- [x] Thirteen adversarial test categories, up to 47 scenarios: direct and indirect prompt injection, secret extraction, unauthorized tool use, tool-output poisoning, unsafe retrieved documents, loop-and-budget limits, memory poisoning (two-session scenarios), plus `action_without_authorization`, `dangerous_composition`, `deceptive_action_report`, `identity_and_session_confusion` and `multi_agent_delegation` (the last five are opt-in by declaration)
- [x] Step, tool-call, token, time and cost limits, with pricing-based cost tracking
- [x] Policy-declared spend limits (`spend_limits`) and destination-address allowlists (`address_allowlist`) for tools that move money, enforced generically against any named tool's own arguments rather than tied to a specific integration; see [Policy reference](docs/policy-reference.md#spend_limits)
- [x] Deterministic evaluators, plus an optional model-assisted judge for paraphrased or borderline leaks
- [x] Normalized execution traces recording every prompt, tool call, tool result and state change
- [x] Findings mapped to the OWASP Top 10 for Agentic Applications (ASI01-ASI10)
- [x] Reproducible runs via `--seed`, and a CI-friendly exit code (`1` findings, `2` error)
- [x] Delivery tracking (`Scenario.exposure`), observable attack goals (`Scenario.attack_goals`, `AttackGoalEvaluator`) and mid-task injection (`inject_after()`), with an `inconclusive` verdict so a scenario whose adversarial content never reached the agent is never reported as passed
- [x] Email and browser attack packs covering five message and six DOM injection surfaces, with two LLM-powered reference assistants (configurable Anthropic / OpenAI-compatible backend), baseline and hardened configurations, and an optional live-model evaluation harness

### Reports and CI

- [x] Terminal, JSON, self-contained HTML, Markdown and SARIF 2.1.0 report formats (`--format`)
- [x] Secrets masked everywhere, in every format
- [x] `agentsec dashboard`: a local, read-only web dashboard over report files (findings, evidence, traces, policy, MCP scans, comparison), standard library only
- [x] `agentsec upload`: opt-in upload of a report to a hosted dashboard with a project token (HTTPS only, `--no-traces` available), also as the Action's `dashboard-url` input
- [x] `agentsec replay` re-runs findings from an earlier report to confirm a fix
- [x] `agentsec compare` diffs two reports (new, fixed, unchanged, worse, better, not comparable)
- [x] GitHub Actions workflow annotations and job summary, with no extra flags
- [x] A packaged, reusable GitHub Action (`action.yml`) that installs AgentSec, optionally starts the agent, runs the suite, uploads reports and gates the job
- [x] Baseline and pull-request regression testing built into the Action: compare a run against a baseline report and post (and update, across pushes) a PR comment listing what's new or worse
- [x] SARIF output wired to GitHub Code Scanning (`--format sarif` plus `github/codeql-action/upload-sarif`); see [GitHub Actions](docs/github-actions.md#github-code-scanning-sarif)

### Frameworks and protocols

- [x] `LangChainAdapter` for LangChain and LangGraph agents, run in-process, duck-typed so AgentSec never imports the framework itself
- [x] `agentsec mcp scan`: statically scans an MCP server's tools, resources and prompts for poisoned descriptions, invisible characters, tool shadowing, homoglyph tool-name impersonation, lying annotations, forbidden or unlisted tools, and rug pulls across all three kinds (pin a server's definitions and compare across runs)
- [x] `agentsec test --mcp-listen`: AgentSec acts as the MCP server an agent connects to, delivering the same adversarial scenarios over MCP tool results
- [x] Agents that run tools server-side and stream their replies (server-sent events, `x_agentsec` events for reporting server-side tool calls and memory keys)

### Extensibility and API

- [x] Python API (`AgentTarget`, `SecuritySuite`) mirroring the CLI, for running scenarios from code
- [x] A pytest plugin (`agentsec_run` fixture, `--agentsec-policy`)
- [x] Attack packs: load extra scenario categories from a local file or an installed package without forking AgentSec (`attack_packs:` in the policy, or `agentsec test --attack-pack`), validated and name-collision-checked at load time. A pack can also ship its own `EVALUATORS` for deterministic checks the built-in ones can't express, and its own `JUDGE_CHECKS` so `--judge` can ask a question phrased in the pack's own domain terms instead of only the two built-in ones -- six full reference packs covering [coding](examples/attack_packs/coding_agent_pack.py), [browser](examples/attack_packs/browser_agent_pack.py), [email](examples/attack_packs/email_agent_pack.py), [RAG](examples/attack_packs/rag_pack.py) (including a pack-provided judge check), [customer-support](examples/attack_packs/support_agent_pack.py) and [on-chain](examples/attack_packs/onchain_agent_pack.py) agents; see [Domain attack packs](docs/domain-attack-packs.md), [Email and browser packs](docs/email-and-browser-packs.md) and [Extending AgentSec](docs/extending.md#give-a-pack-its-own-judge-check)
- [x] Two intentionally vulnerable reference agents (rule-based, RAG-backed), each with a hardened variant that passes the full suite, plus a demo MCP server and an MCP-connected reference agent

## Future Work

Everything below is not yet built, except where ticked. It splits into the hosted dashboard (open source, free at
launch, with a few paid premium features later), and engine-level coverage gaps that stay in scope for AgentSec itself.

### Hosted dashboard

A hosted AgentSec dashboard is in development, and it is open source too: its code is public under Apache-2.0
at [`invarislabs/invaris-agentsec-dashboard`](https://github.com/invarislabs/invaris-agentsec-dashboard), so you
can read exactly what it does with your reports or run it yourself. The hosted service will be **free at
launch**. A few premium features added later will be paid and kept private; everything that exists today, in
this repository and in the dashboard's, stays free and open source, including `agentsec dashboard`, the local
viewer.

Reports reach a hosted dashboard only when you send them, with `agentsec upload` or the GitHub Action's
`dashboard-url` input, using a project token; nothing is uploaded by default. Built for the free launch:

- [x] Sign-in, projects, and project tokens for CI
- [x] Every uploaded run kept per project, with branch, commit and CI-run links
- [x] Findings history across runs, and run-to-run comparison in the browser
- [x] The same report views as the local dashboard (findings with evidence, traces, policy, MCP scans)
- [ ] Public launch of the hosted service

Planned later:

- [ ] Team members and roles
- [ ] Premium features (paid, private): for example longer retention and higher limits, self-hosted enterprise
  deployment, and production trace monitoring (continuous monitoring of live agent traffic, not just test-time runs)

The open-source side of this already works today: `agentsec upload` sends a report (optionally without full
transcripts, `--no-traces`), and `agentsec compare` plus the GitHub Action's `baseline-report`/PR-comment support
gives pull-request and scheduled regression testing without any hosted service; see
[GitHub Actions](docs/github-actions.md#pull-request-and-scheduled-regression-testing).

### Engine and coverage

- [x] Multi-agent delegation and privilege-abuse testing (`agent_roles`, `multi_agent_delegation`); exercised against a reference team and real OpenAI Agents SDK / CrewAI teams with a scripted model -- see [Multi-agent testing](docs/multi-agent.md)
- [x] Agent identity and session-boundary testing (`identity_and_session_confusion`)
- [ ] Multi-agent attribution for systems that share one MCP client across agents (not observable today)
- [ ] Stateful, multi-turn campaign generation
- [ ] Cross-agent failure-propagation analysis
- [ ] Memory-poisoning scenarios longer than one follow-up session
- [ ] MCP-specific attacks beyond hostile tool results and decoy tools; see [MCP testing](docs/mcp-testing.md)
- [ ] Dedicated adapters for other agent frameworks. The generic `CallableAdapter` plus the in-process `ToolHost` covers them today, and the same scenarios have been run through LangChain, LangGraph, CrewAI, AutoGen, the OpenAI Agents SDK, Google ADK and smolagents with a scripted model -- see [benchmarks/framework-compat](benchmarks/framework-compat/MATRIX.md)

Real-world verification: the packaged GitHub Action -- via the actual public `uses: invarislabs/invaris-agentsec@main`
path, not a local reference -- has been run repeatedly on real GitHub Actions infrastructure (see
[`.github/workflows/self-scan.yml`](.github/workflows/self-scan.yml)), and its GitHub Code Scanning integration
is confirmed working end to end: the generated SARIF validates, uploads successfully, and real findings appear
in this repo's own Security > Code scanning tab. (Those alerts are visible to signed-in users with access to
the repository, not to signed-out visitors -- a GitHub platform behavior, not an AgentSec one, worth knowing
before relying on a bare link in a demo.) The MCP attack host has been run against a real LLM-backed agent
(the Claude Code CLI, with its built-in tools disabled and every MCP tool simulated); see
[benchmarks/real-agents](benchmarks/real-agents/README.md). Codex, Gemini CLI and Cursor have not been run. See
[Testing](docs/testing.md) for exactly what is and isn't covered.

## Intended Users

AgentSec is being designed for:

- Developers building tool-using AI agents
- AI startups preparing agents for production
- Security teams evaluating autonomous workflows
- Teams exposing or consuming MCP servers
- Enterprises deploying agents over internal data
- Financial and blockchain teams building transaction-capable agents
- Researchers studying agent reliability and adversarial behaviour

## Security Model

AgentSec executes potentially adversarial content against systems that may have access to real tools and data. During early development:

- use isolated test environments;
- provide synthetic credentials and test data;
- disable irreversible actions;
- use sandboxed or mocked tools;
- enforce strict spending and execution limits; and
- never point experimental tests at production agents.

A detailed threat model will be published before the first public release. The vulnerability-reporting policy is in [SECURITY.md](SECURITY.md).

## Contributing

The project is in early development. Contributions will be welcomed in areas such as:

- Adversarial test cases
- Agent and framework adapters
- MCP security testing
- Deterministic evaluators
- Trace schemas and interoperability
- Sandboxing and safe execution
- Documentation and vulnerable examples

To develop locally, run `pip install -e ".[dev]"` and then `pytest`. See [CONTRIBUTING.md](CONTRIBUTING.md) for the guidelines.

## Responsible Disclosure

If AgentSec identifies a vulnerability in a third-party agent, framework, or integration, do not publish sensitive details immediately. Contact the affected maintainer and allow reasonable time for remediation. To report a vulnerability in AgentSec itself, see [SECURITY.md](SECURITY.md).

## License

Invaris AgentSec is licensed under the [Apache License 2.0](LICENSE). "Invaris" and "AgentSec" are
trademarks of Invaris Labs and are not covered by that license; see [NOTICE](NOTICE) for details.

## About Invaris Labs

Invaris Labs is building the security infrastructure for autonomous AI agents. Learn more at [invarislabs.com](https://www.invarislabs.com/).

## Contact

- Website: [www.invarislabs.com](https://www.invarislabs.com/)
- Email: [arunimachaudhuri2020@gmail.com](mailto:arunimachaudhuri2020@gmail.com)
- GitHub: [github.com/tinniaru3005](https://github.com/tinniaru3005)
- LinkedIn: [Arunima Chaudhuri](https://www.linkedin.com/in/arunima-chaudhuri/)
---

**Invaris AgentSec is under active development.** If you are building an AI agent and would like to become an early design partner, open a discussion or get in touch.
