# Getting started

## Requirements

Python 3.9 or newer. The only runtime dependency is PyYAML. Development adds `pytest` and `jsonschema`.

## Install

From the repository root:

```bash
pip install -e ".[dev]"
agentsec --version
```

If the `agentsec` command is not on your `PATH`, `python -m agentsec` works the same way.

## Run it against the bundled agent

The reference agent is an intentionally vulnerable stand-in for an LLM agent. It needs no API key,
network access or model. Use two terminals.

Terminal 1:

```bash
python examples/vulnerable_rag_agent/server.py
```

Terminal 2:

```bash
agentsec test --policy examples/vulnerable_rag_agent/agentsec.yaml
```

You should see 35 scenarios executed, 0 passed and 43 findings (10 critical, 25 high, 8 medium),
ending with `Report written to .agentsec/report.json` and `Report written to .agentsec/report.html`.
The command exits with code 1 because findings exist.

Now stop the server and start the hardened variant:

```bash
python examples/vulnerable_rag_agent/server.py --safe
agentsec test --policy examples/vulnerable_rag_agent/agentsec.yaml
```

This time all 35 scenarios pass and the exit code is 0. Seeing both results is the quickest way to
confirm that the engine detects real failures and does not raise false alarms.

## Reading the terminal output

```text
Invaris AgentSec

35 scenarios executed
0 passed
43 findings

CRITICAL  Indirect prompt injection triggered send_email
          indirect_prompt_injection/plain_appended  |  forbidden_actions: send_email
HIGH      Secret exposed in response
          secret_extraction/system_prompt  |  secrets must never appear in agent output (configured secret)
MEDIUM    Tool-call budget exceeded
          loop_and_budget_limits/pagination_trap  |  limits.max_tool_calls = 10

Report written to .agentsec/report.json
Report written to .agentsec/report.html
```

The summary counts scenarios, not findings, so one scenario can produce several findings. Each
finding shows its severity, a title, the scenario id, and the policy rule that was violated.
Findings are sorted most severe first. Add `-v` to also print the observed action, a remediation hint and the OWASP
categories. Findings from the optional judge carry a `[model-assisted]` tag.

Open `.agentsec/report.html` in a browser for the same information with expandable evidence and full traces.

## Try the RAG-backed example

`examples/rag_agent` is closer to a real application than the rule-based agent. It has its own documents (`examples/rag_agent/corpus/`), retrieves from them, and runs tools itself.
Because AgentSec cannot see server-side tool calls unless told, it reports them in `x_agentsec.events`. See the [agent contract](agent-contract.md#the-rag-backed-reference-agent).

```bash
python examples/rag_agent/server.py                    # vulnerable, port 8100
agentsec test -p examples/rag_agent/agentsec.yaml      # 22 scenarios, 30 findings, exit code 1
```

Restart it with `--safe` and the same command passes all 22 scenarios. While the vulnerable agent is running, `curl http://127.0.0.1:8100/outbox` shows the simulated side effects
it performed, such as a `send_email` triggered by a poisoned document.

## Test your own agent

1. Create a starter policy: `agentsec init`
2. Set `agent.endpoint` to your agent's URL, list its real tools under `allowed_tools`, the
   actions it must never take under `forbidden_actions`, and any synthetic credentials it can see under `secrets`.
3. Read the [agent contract](agent-contract.md) to confirm your agent can be driven this way.
4. Run `agentsec test`.

Only point AgentSec at test deployments with synthetic credentials and sandboxed or mocked tools.
Never point it at production. See the Security Model in the main README.

## CLI reference

### `agentsec test`

| Option | Default | Meaning |
|---|---|---|
| `-p, --policy PATH` | `agentsec.yaml` | Policy file |
| `-o, --out DIR` | `.agentsec` | Directory for the report files |
| `-f, --format LIST` | `json,html` | Comma-separated report formats: `json`, `html`, `markdown` (writes `summary.md`), `sarif` (writes `results.sarif`, for [GitHub Code Scanning](github-actions.md#github-code-scanning-sarif)) |
| `--seed N` | `0` | Seed for canaries and markers. The same seed produces the same scenarios |
| `-s, --scenario NAME` | all | Run only this category or scenario id. Repeatable |
| `--fail-on LEVEL` | `low` | Exit 1 if a finding at or above `critical`, `high`, `medium` or `low` exists. `none` never fails on findings |
| `--judge` | off | Also run the model-assisted evaluators configured under `judge:` in the policy. See [Judge](judge.md) |
| `--mcp-listen HOST:PORT` | off | Run AgentSec as the MCP server your agent connects to. See [MCP testing](mcp-testing.md#testing-an-agent-that-uses-mcp---mcp-listen) |
| `-v, --verbose` | off | Print progress and per-finding detail |

Before running any scenario, `agentsec test` checks the agent: it stops with exit code 2 and a clear error when
`agent.endpoint` is still the placeholder `agentsec init` writes, or when one preflight request to the endpoint fails
(see [Agent contract](agent-contract.md)).

Examples:

```bash
agentsec test -s prompt_injection                      # one category
agentsec test -s secret_extraction/system_prompt       # one scenario
agentsec test --fail-on high                           # only high and critical fail the build
agentsec test --seed 42                                # different canaries and markers
```

### `agentsec replay REPORT`

Re-runs the findings from an earlier `report.json` to see whether they still reproduce, for example after fixing the agent.
It rebuilds the same scenarios from the seed recorded in the report, runs them against the agent in `--policy`, and prints one line per finding.

```bash
agentsec replay .agentsec/report.json --policy agentsec.yaml
agentsec replay .agentsec/report.json --finding 'indirect_prompt_injection/plain_appended:forbidden_action:send_email'
agentsec replay .agentsec/report.json -s memory_poisoning/doc_instruction_marker
```

```text
Replaying 2 findings from .agentsec/report.json (seed 0)
REPRODUCED      critical Indirect prompt injection triggered send_email  [indirect_prompt_injection/plain_appended]
NOT REPRODUCED  high     Secret exposed in response  [secret_extraction/system_prompt]

1 reproduced, 1 not reproduced, 0 inconclusive, 0 new, 0 errored
Report written to .agentsec/replay/report.json
```

| Option | Default | Meaning |
|---|---|---|
| `-p, --policy PATH` | `agentsec.yaml` | Policy to run. Point it at the fixed agent. A note is printed if the file differs from the one used for the report |
| `-o, --out DIR` | `.agentsec/replay` | Where the replay report is written |
| `--finding ID` | all | Replay only this finding id. Repeatable |
| `-s, --scenario ID` | all | Replay only findings of this scenario. Repeatable |
| `--judge` | off | Re-check model-assisted findings too. Without it they are skipped, with a note |

`NEW` lines are findings that were not in the original report. Exit code 0 means nothing reproduced. Exit code 1 means at least one finding
reproduced or a new one appeared. Exit code 2 means a scenario could not run.
"NOT REPRODUCED" is evidence, not proof, that a fix works: an agent that samples from a model can vary between runs.

### `agentsec compare BASELINE CURRENT`

Diffs two `report.json` files by finding id and reports what is new, fixed, unchanged, or changed in
severity. Use it in CI to catch regressions: keep a report from `main` and compare each pull request against it.

```bash
agentsec compare main-report.json .agentsec/report.json --fail-on high
```

It exits 1 if a new or worsened finding is at or above `--fail-on` (default `low`), 2 if a report cannot be read.
It warns when the seeds, policies or scenario sets differ. A finding whose scenario is missing or errored in
the new run is listed as "not comparable", never as fixed.

### `agentsec mcp scan`

Connects to an MCP server, lists its tools (it never calls one) and checks the definitions for poisoning, hidden
characters, shadowing and changes since a pin. Use `--command "python server.py"` or `--url https://...`.
Options and rules are in [MCP server scanning](mcp-testing.md). It writes `mcp-report.json` and uses the same exit codes.

### `agentsec init [PATH]`

Writes a starter policy (default `agentsec.yaml`). It refuses to overwrite an existing file.

### `agentsec schema policy|trace`

Prints the JSON Schema for the policy file or for a trace, for editor validation and tooling.

### Exit codes

| Code | Meaning |
|---|---|
| 0 | Run completed and no finding reached the `--fail-on` threshold |
| 1 | At least one finding reached the `--fail-on` threshold |
| 2 | Configuration error (bad policy, missing or placeholder `agent.endpoint`, unknown category or scenario, unreadable report or pin file, MCP server that cannot be reached), an agent that fails the preflight request, or every scenario errored. For `replay`, also when a replayed scenario could not run, or when nothing reproduced but at least one replayed scenario was `inconclusive` (its adversarial content never reached the agent, so the rerun cannot show the finding is fixed) |

## In GitHub Actions

When `GITHUB_ACTIONS=true`, `agentsec test` also prints one workflow annotation per finding (critical and high as errors, medium as
warnings, low as notices) and appends a Markdown summary to the job summary (`GITHUB_STEP_SUMMARY`). No flags are needed.
See [GitHub Actions](github-actions.md) for the packaged action, or [Testing](testing.md#run-agentsec-in-ci) for a hand-written workflow.

## Troubleshooting

**`agent.endpoint is not set` or `agent.endpoint is still the placeholder`**: set `agent.endpoint` in your
policy to your agent's URL. `agentsec init` writes `https://your-agent.example/...`, which never resolves on purpose.

**`did not answer a preflight request: cannot reach agent at ...: Connection refused`**: the agent is not running or
the port is wrong. The bundled policy uses port 8000. No scenario runs and AgentSec exits with code 2.

**`unknown key(s) in policy`**: typos are rejected on purpose so a misspelled limit is not silently
ignored. The message lists the allowed keys.

**`environment variable X (agent.api_key_env) is not set`**: export the variable that holds your
agent's bearer token before running.

**0 findings against a real agent, and that feels too good**: check that the tools you expect to be
attacked appear in `allowed_tools` or `agent.retrieval_tools`, that `secrets` lists the credentials
your agent can see, and that the agent really calls tools through the API (see the
[agent contract](agent-contract.md)). A scenario that never reaches a tool cannot trigger a tool-based finding.

**`--judge needs a judge: section`**: add a `judge:` block to the policy. See [Judge](judge.md).

**`judge: N of M judge calls failed`**: the judge endpoint was unreachable or returned something that was not the expected JSON verdict. Those checks were skipped, not counted as passes.
