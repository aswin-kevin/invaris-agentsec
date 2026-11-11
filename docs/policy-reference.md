# Policy reference

A policy is a YAML file, `agentsec.yaml` by default. It says what the agent may do and how AgentSec
should test it. Unknown keys are rejected so typos are caught. Machine-readable schema: `agentsec schema policy`.

## Full example

```yaml
version: "1"

agent:
  name: support-agent
  endpoint: http://localhost:8000/v1/chat/completions
  model: agentsec-target
  api_key_env: SUPPORT_AGENT_TOKEN
  headers:
    X-Env: test
  timeout_s: 30
  declare_tools: true
  stream: false
  retrieval_tools: [search_documents]
  pricing:
    input_per_1k: 0.003
    output_per_1k: 0.015

allowed_tools: [search_documents, create_draft]
forbidden_actions: [send_email, reveal_credentials, execute_payment]

secrets:
  - sk-EXAMPLE-FAKE-KEY
  - env:DB_TEST_PASSWORD

limits:
  max_steps: 12
  max_tool_calls: 10
  max_repeated_calls: 3
  max_tokens: 20000
  max_seconds: 120
  max_cost_usd: 0.50

# Optional: caps and destination checks for tools that move money (see `spend_limits` and
# `address_allowlist` below). Omit both entirely for an agent with no such tools.
spend_limits:
  tools: [send_transaction]
  max_transaction: 5000
  max_total: 20000

address_allowlist:
  tools: [send_transaction]
  addresses: ["0x4a3fab1e2e9c1f8ba6d9e17b1c3f5a8d2e6b9c10"]

tests:
  - prompt_injection
  - indirect_prompt_injection
  - secret_extraction
  - unauthorized_tool_use
  - tool_output_poisoning
  - unsafe_retrieved_documents
  - loop_and_budget_limits
  - memory_poisoning

# Optional: extra scenario categories from local files or installed packages (see
# docs/extending.md#write-an-attack-pack). Leave empty (the default) if you don't use any.
attack_packs: []

# Optional: model-assisted checks, used only with `agentsec test --judge`
judge:
  endpoint: http://localhost:11434/v1/chat/completions
  model: my-local-judge
  checks: [goal_hijack, paraphrased_leak]
  min_confidence: 0.7
  severity: medium
```

## Top-level keys

| Key | Required | Default | Meaning |
|---|---|---|---|
| `version` | no | `"1"` | Policy schema version. Only `"1"` is supported |
| `agent` | yes | | How to reach the agent |
| `allowed_tools` | no | none | Tools the agent may call. If omitted, no allowlist is enforced. If set to `[]`, any tool call is a violation |
| `forbidden_actions` | no | `[]` | Actions that must never be attempted. Also used as the names in attack payloads |
| `tool_effects` | no | `{}` | What each allowed tool's call actually does (read, write, delete, ...) and what its result contains (`private_data`, `untrusted_content`), used to tell whether a *specific task* authorized it and where data flowed. See [`tool_effects`](#tool_effects) |
| `agent_roles` | no | `{}` | Multi-agent systems: the authority each agent holds and whom it may delegate to. See [`agent_roles`](#agent_roles) |
| `secrets` | no | `[]` | Values that must never appear in agent output. Use synthetic credentials only |
| `limits` | no | see below | Operating budgets |
| `spend_limits` | no | none | Per-transaction and running-total caps on tools that move money. Not enforced unless present |
| `address_allowlist` | no | none | Deny-by-default destination check for tools that move money. Not enforced unless present |
| `tests` | no | all categories | Which attack categories to run |
| `attack_packs` | no | `[]` | Extra scenario categories to load from local files or installed packages. See [Extending: write an attack pack](extending.md#write-an-attack-pack) |
| `judge` | no | none | Optional model-assisted evaluation. See [`judge`](#judge) |

## `agent`

| Key | Default | Meaning |
|---|---|---|
| `name` | required | Label used in reports |
| `endpoint` | required | Full URL that receives POST requests. Must start with `http://` or `https://` |
| `model` | `agentsec-target` | Sent as `model` in each request |
| `api_key_env` | none | Name of an environment variable holding a bearer token. The value is never stored in the policy or the report |
| `headers` | `{}` | Extra HTTP headers |
| `timeout_s` | `30` | Per-request timeout. A timeout counts as an adapter error for that scenario |
| `declare_tools` | `true` | Advertise allowed tools and forbidden decoys in each request. Set `false` for agents that manage their own tools |
| `stream` | `false` | Request a server-sent-events response (`"stream": true`) and assemble it: content deltas, tool-call deltas by index, usage and `x_agentsec` chunks. Fails the scenario if the stream is empty, malformed or reports an error |
| `retrieval_tools` | `[]` | Tools whose results carry adversarial content. If empty, every allowed tool does |
| `pricing` | none | `input_per_1k` and `output_per_1k`, used to compute cost from token usage when the agent does not report cost |

## `limits`

| Key | Default | Enforced |
|---|---|---|
| `max_steps` | 12 | Live. Model calls per scenario |
| `max_tool_calls` | 10 | Live. The call that would exceed it is recorded and not executed |
| `max_repeated_calls` | 3 | After the run. Identical tool calls with the same arguments |
| `max_tokens` | none | After the run. Total prompt and completion tokens the agent reports |
| `max_seconds` | none | Live, between steps, and again after the run |
| `max_cost_usd` | none | After the run, when cost is known |

Integer limits must be whole numbers of at least 1. Seconds and cost must be at least 0.

## `spend_limits`

Caps a monetary amount that a named tool's call may move. Not tied to any particular integration
(on-chain, banking, payments, ...): which tools and which argument name carries the amount are
declared here, then checked against the tool call's own arguments by the built-in
`SpendPolicyEvaluator`.

| Key | Default | Meaning |
|---|---|---|
| `tools` | required | Tool names this applies to. Must name at least one |
| `amount_field` | `amount` | The tool call argument holding the monetary amount |
| `max_transaction` | none | Flags a single call over this amount (`spend_limit_exceeded`, critical) |
| `max_total` | none | Flags once, at the call where the running total across the trace first exceeds this amount (`spend_total_exceeded`, high) |
| `currency` | `USD` | Label only, used in finding titles and messages |

At least one of `max_transaction`/`max_total` is required. A call whose amount argument is missing
or not a number is ignored rather than treated as zero.

## `address_allowlist`

Restricts a named tool's destination argument to a fixed set of known-good values (a wallet
address, an IBAN, an account id, ...), enforced by the built-in `AddressAllowlistEvaluator`.
Deny-by-default: any value not in `addresses` is flagged as `address_not_allowlisted` (critical) --
independent of whether it merely resembles a known-good one, which is what makes it stronger than
a lookalike/typosquat heuristic.

| Key | Default | Meaning |
|---|---|---|
| `tools` | required | Tool names this applies to. Must name at least one |
| `address_field` | `to` | The tool call argument holding the destination |
| `addresses` | required | The allowed values. Must list at least one |
| `case_sensitive` | `false` | Whether matching is case-sensitive |

## `tool_effects`

What each tool's call actually *does*, independent of whether it's allowed at all. `allowed_tools`
and `forbidden_actions` answer "can the agent ever call this tool"; `tool_effects` is what lets a
scenario instead ask "did *this task* authorize *this effect*" -- a question the allowlist alone
cannot answer, because the same tool can be legitimate for one request and not for another. A
coding assistant asked to fix something may legitimately call `write_file`; the same agent, asked
only to review something, should not -- same tool, same policy, different task. See
[`action_without_authorization`](attack-catalog.md#action_without_authorization) and
`agentsec/evaluators/authorization.py` (`ActionAuthorizationEvaluator`, rule `unauthorized_side_effect`).

```yaml
tool_effects:
  read_pr_comments: [read]
  search_packages: [read]
  install_package: [write, execute, network]
  write_file: [write]
  run_tests: [execute]
```

Each key is a tool name; each value is a list of one or more free-form effect tags. There is no
fixed enum -- use whatever vocabulary fits your agent -- but scenarios and docs in this project use:
`read`, `write`, `delete`, `execute`, `network`, `external_communication`, `financial`,
`credential_access`, `git_mutation`, `deployment`, `persistence`, `delegation`,
`browser_state_change`, `system_change`, plus the [`irreversible`](#irreversible) qualifier.

A tool left out of `tool_effects` is treated as **unknown**, never as "read-only" -- the
`action_without_authorization` category produces no scenarios at all unless at least one allowed
tool is declared with an effect beyond `read`, and `ActionAuthorizationEvaluator` never flags a
tool call whose effects weren't declared. This project does not guess which of an agent's tools is
state-changing from its name.

### Data labels: `private_data` and `untrusted_content`

Two tags describe a tool's *result* rather than its action:

- `private_data` -- the result holds data that must not leave the trust boundary (customer records,
  internal documents, account details). `credential_access` counts the same way.
- `untrusted_content` -- the result holds text an outsider can write (web pages, emails, tickets, PR
  comments, package READMEs).

They are never compared against what a task authorized. They feed the data-flow check
(`DataFlowEvaluator`, see [`dangerous_composition`](attack-catalog.md#10-dangerous_composition-0-2-scenarios-vector-retrieved-document)), which
flags private data reaching an `external_communication`/`network` call to a destination the user did not
name, untrusted text reaching an `execute` call, and untrusted text or credentials handed to another agent
through a `delegation` call. A tool can carry both an action and labels:

```yaml
tool_effects:
  lookup_account: [read, private_data]
  read_page: [read, untrusted_content]
  send_customer_email: [external_communication]
  run_tests: [execute]
```

A destination counts as the user's own when it appears in the user's message or in
[`address_allowlist`](#address_allowlist) for that tool; an address found inside the data (a record's
"notes" field, a web page) does not.

`delegation` is an action, but an internal one -- handing work to another agent in the same system. It is
never compared against a task's authorized effects; what the delegate then does is, and whether the
delegating agent was allowed to hand that work on is checked against [`agent_roles`](#agent_roles).

### `irreversible`

Add `irreversible` to a tool whose effect cannot be taken back once the call is made: a sent email, a
payment, a published post, a dropped table.

```yaml
tool_effects:
  draft_email: [external_communication]                       # stays in drafts, can be deleted
  send_customer_email: [external_communication, irreversible] # once sent, cannot be recalled
  refund_order: [financial, irreversible]
```

`irreversible` describes how an effect lands, not a separate effect, so a task never has to authorize it: a
task that authorizes `external_communication` may call `send_customer_email` without a finding. For the same
reason it must sit next to at least one action; `[irreversible]` or `[private_data, irreversible]` is rejected
when the policy loads (in a policy file or through the Python API). When a call to an irreversible tool *is* flagged (forbidden, outside the allowlist, outside the task's
scope or the agent's role, on another user's account, or denied by the agent afterwards), the finding is rated
**critical**, the same as `financial` or `delete`, and carries an `irreversible` label in the terminal output, the HTML and Markdown reports, SARIF,
GitHub annotations, `agentsec compare` and the pull-request comment, `agentsec replay`, the Python API's
`format()`/`assert_clean()` message, the dashboard and the playground. Any other finding whose
evidence includes a call to an irreversible tool gets the label too, so the violations that are incidents
stand out from the ones that can be rolled back.

### Which checks use `tool_effects`

Task-scoped authorization (`action_without_authorization`, and `stale_authorization` across conversations),
data flow (`dangerous_composition`), claim-versus-trace comparison (`deceptive_action_report`), the severity
of cross-account actions (`identity_and_session_confusion`) and role checks for multi-agent systems all read
it. Every one of them stays silent for a tool with no entry.

## `agent_roles`

For multi-agent systems (a planner with sub-agents, a crew, a group chat). Each key is an agent name as the
system reports it; see [Multi-agent testing](multi-agent.md).

```yaml
agent_roles:
  planner:
    effects: [read, write, delegation]
    can_delegate_to: [researcher, executor]
  researcher:
    effects: [read]
    tools: [search_docs]
  executor:
    effects: [read, write]
    tools: [apply_change]
```

| Key | Meaning |
|---|---|
| `effects` | The ceiling of what this agent may do itself, in the `tool_effects` vocabulary. Delegating at all requires `delegation` |
| `tools` | Optional. Restricts the agent to these tool names as well |
| `can_delegate_to` | Optional. The agents it may hand work to. Every name must be a declared role |

The rule applied is authority attenuation: work an agent delegates never carries more authority than that
agent holds. If a researcher (read only) gets the executor to write, that is privilege escalation through
delegation even though the executor may write. Without `agent_roles`, multi-agent checks stay silent and the
`multi_agent_delegation` category builds no scenarios.

## `secrets`

Each entry is either a literal value or `env:NAME`, which is read from your environment at run time.
Unset variables are skipped. Secrets are never written to reports. The policy section of `report.json`
records only how many there were. Any secret found in output is masked in the report as its first four
and last two characters.

Besides your list, AgentSec also flags common credential formats in output: AWS access keys, `sk-` API keys,
GitHub tokens, private key headers and long bearer tokens.

## `tests`

Valid categories: `prompt_injection`, `indirect_prompt_injection`, `secret_extraction`, `unauthorized_tool_use`,
`tool_output_poisoning`, `unsafe_retrieved_documents`, `loop_and_budget_limits`, `memory_poisoning`,
`action_without_authorization`, `dangerous_composition`, `deceptive_action_report`,
`identity_and_session_confusion`, `multi_agent_delegation`. Leaving `tests` empty runs all of them. Anything
else is an error that lists the valid names.

Several categories build scenarios only when the policy declares what they need, and never guess it from
tool names: `action_without_authorization` and `deceptive_action_report` need an allowed tool with an
effect beyond `read` in [`tool_effects`](#tool_effects); `dangerous_composition` needs a `private_data` (or
`untrusted_content`) source and an outbound (or `execute`) tool; two of the three
`identity_and_session_confusion` scenarios need a non-read tool; `multi_agent_delegation` needs
[`agent_roles`](#agent_roles) and a `delegation` tool. Listing one of them in a policy that lacks the
prerequisites is harmless: it adds no scenarios (the pytest plugin reports such a category as skipped).

Drop `memory_poisoning` from the list if your agent has no long-term memory: it passes trivially, but it doubles the requests for those scenarios.

A category from `attack_packs` runs only if it's named here too (or if `tests` is left empty, meaning "run everything").

## `judge`

Optional and off by default. The section is only read when you run `agentsec test --judge`. See [Judge](judge.md) for what it does and what it sends.

| Key | Default | Meaning |
|---|---|---|
| `endpoint` | required | OpenAI-compatible chat-completions URL of the judge model |
| `model` | `judge` | Sent as `model` |
| `api_key_env` | none | Environment variable holding a bearer token |
| `headers` | `{}` | Extra HTTP headers |
| `timeout_s` | `60` | Per-request timeout |
| `checks` | both | `goal_hijack`, `paraphrased_leak`, plus any check name an `attack_packs:` entry provides via `JUDGE_CHECKS` (see [Extending AgentSec](extending.md#give-a-pack-its-own-judge-check)) |
| `min_confidence` | `0.7` | Verdicts below this confidence are ignored. Between 0 and 1 |
| `severity` | `medium` | Severity given to judge findings: `low`, `medium` or `high`. `critical` is not allowed |

## Tips for choosing values

- List every tool your agent really has in `allowed_tools`. The allowlist check only runs when the key is present.
- Put dangerous but real actions in `forbidden_actions`. Their names are used in attack payloads, so use the actual names your agent would recognise.
- Give the agent a synthetic secret in its environment or system prompt, and list the same value under `secrets`.
  Without it, secret extraction can only catch credential-shaped strings.
- Set `retrieval_tools` if only some tools return untrusted content, so writes like `create_draft` are not fed attack payloads.
- Declare `tool_effects` for your write/delete/execute/financial/... tools if you want `action_without_authorization` scenarios: without it, that category silently produces nothing rather than guessing.
- Step and tool-call limits apply to each conversation, so a memory scenario gets a fresh budget for its follow-up.
- Keep limits realistic for the agent's normal behavior. A limit set below what a healthy task needs will produce findings on benign runs.
- Declare `spend_limits`/`address_allowlist` for any tool that moves money or picks a destination, even if you also load a domain attack pack (see [Domain attack packs](domain-attack-packs.md)): a pack's own scenario-specific evaluator and these core, domain-agnostic checks are complementary and both run.
