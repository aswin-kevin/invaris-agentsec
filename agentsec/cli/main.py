from __future__ import annotations

import argparse
import json
import os
import sys
from typing import List, Optional

from .. import __version__
from ..adapters import HTTPAgentAdapter
from ..compare import CompareError, compare, load as load_compare_report, render as render_compare
from ..evaluators import SEVERITIES, severity_rank
from ..mcp import (MCPError, build_mcp_report, compare_pins, connect_http, connect_stdio, make_pins,
                   render_mcp_terminal, scan_prompts, scan_resources, scan_tools)
from ..mcp.report import write_mcp_report
from ..policies import PolicyError, load_policy, policy_json_schema
from ..reports import (FORMATS, annotations, append_step_summary, in_github_actions,
                       render_markdown, render_terminal, write_reports)
from ..runners import load_report, replay, run_suite
from ..traces import trace_json_schema

EXIT_OK, EXIT_FINDINGS, EXIT_ERROR = 0, 1, 2

INIT_POLICY = """version: "1"

agent:
  name: my-agent
  endpoint: http://localhost:8000/v1/chat/completions

allowed_tools:
  - search_documents
  - create_draft

forbidden_actions:
  - send_email
  - reveal_credentials
  - execute_payment

# Synthetic credentials your agent can see; they must never appear in its output.
secrets: []

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
"""


def _parse_formats(text: str) -> List[str]:
    formats = [f.strip() for f in text.split(",") if f.strip()]
    bad = [f for f in formats if f not in FORMATS]
    if bad or not formats:
        raise PolicyError("--format must be a comma-separated list of: %s" % ", ".join(FORMATS))
    return formats


def _cmd_test(args: argparse.Namespace) -> int:
    policy = load_policy(args.policy)
    adapter = HTTPAgentAdapter(policy.agent)
    only = args.scenario or None
    progress = None
    if args.verbose:
        progress = lambda sc: print("running %s" % sc.id, file=sys.stderr)
    formats = _parse_formats(args.format)
    extra_packs = None
    if args.attack_pack:
        from ..attacks import CATEGORIES
        from ..attacks.packs import load_packs
        extra_packs = load_packs(args.attack_pack, CATEGORIES)

    host = None
    if args.mcp_listen:
        from ..mcp import MCPAttackHost
        hostname, _, port = args.mcp_listen.rpartition(":")
        if not port.isdigit():
            raise PolicyError("--mcp-listen must look like HOST:PORT or :PORT, e.g. 127.0.0.1:8765")
        if hostname not in ("", "127.0.0.1", "localhost", "::1"):
            print("warning: the MCP attack host is listening on %s. It serves adversarial content and "
                  "accepts any client; only do this on an isolated network." % hostname, file=sys.stderr)
        try:
            host = MCPAttackHost(policy, hostname or "127.0.0.1", int(port)).start()
        except OSError as exc:
            raise PolicyError("cannot listen on %s: %s" % (args.mcp_listen, exc))
        print("AgentSec MCP host listening at %s (point your agent's MCP client here)" % host.url,
              file=sys.stderr)
    try:
        suite = run_suite(policy, adapter, seed=args.seed, only=only, progress=progress, judge=args.judge,
                          host=host, attack_packs=extra_packs)
    finally:
        if host is not None:
            host.stop()
    report, paths = write_reports(suite, args.out, formats, policy_path=args.policy)
    print(render_terminal(suite, report_path=paths, color=sys.stdout.isatty(), verbose=args.verbose))
    if in_github_actions():
        for line in annotations(report):
            print(line)
        append_step_summary(render_markdown(report))

    if suite.results and all(r.status == "error" for r in suite.results):
        print("\nEvery scenario errored; is the agent running at %s?" % policy.agent.endpoint,
              file=sys.stderr)
        return EXIT_ERROR
    if args.fail_on != "none":
        threshold = severity_rank(args.fail_on)
        if any(severity_rank(f.severity) >= threshold for f in suite.findings):
            return EXIT_FINDINGS
    return EXIT_OK


def _cmd_replay(args: argparse.Namespace) -> int:
    report = load_report(args.report)
    policy = load_policy(args.policy)
    result = replay(report, policy, HTTPAgentAdapter(policy.agent),
                    finding_ids=args.finding or None, scenario_ids=args.scenario or None,
                    judge=args.judge)
    if result.skipped_model_assisted:
        print("note: skipped %d model-assisted finding(s); pass --judge to re-check them"
              % result.skipped_model_assisted)
    if not result.outcomes:
        print("Nothing to replay: the report has no matching findings.")
        return EXIT_OK
    print("Replaying %d finding%s from %s (seed %d)" % (
        len(result.outcomes), "" if len(result.outcomes) == 1 else "s", args.report, result.seed))
    if result.policy_changed:
        print("note: the policy file differs from the one used for the report")
    label = {"reproduced": "REPRODUCED", "not_reproduced": "NOT REPRODUCED", "inconclusive": "INCONCLUSIVE",
             "error": "ERROR"}
    for o in result.outcomes:
        print("%-15s %-8s %s  [%s]" % (label[o.status], o.severity, o.title, o.scenario_id))
    for f in result.new_findings:
        mark = " [irreversible]" if f.irreversible else ""
        print("%-15s %-8s %s%s  [%s]" % ("NEW", f.severity, f.title, mark, f.scenario_id))
    print("\n%d reproduced, %d not reproduced, %d inconclusive, %d new, %d errored" % (
        len(result.reproduced), sum(o.status == "not_reproduced" for o in result.outcomes),
        len(result.inconclusive), len(result.new_findings), len(result.errors)))
    if result.suite is not None:
        _, paths = write_reports(result.suite, args.out, ["json"], policy_path=args.policy)
        print("Report written to %s" % paths[0])
    if result.errors:
        return EXIT_ERROR
    if result.reproduced or result.new_findings:
        return EXIT_FINDINGS
    if result.inconclusive:
        return EXIT_ERROR  # could not verify: never report an unexecuted rerun as fixed
    return EXIT_OK


def _cmd_compare(args: argparse.Namespace) -> int:
    try:
        result = compare(load_compare_report(args.baseline), load_compare_report(args.current))
    except CompareError as exc:
        print("error: %s" % exc, file=sys.stderr)
        return EXIT_ERROR
    print(render_compare(result))
    if args.fail_on == "none":
        return EXIT_OK
    return EXIT_FINDINGS if result.regressions(args.fail_on) else EXIT_OK


def _cmd_mcp_scan(args: argparse.Namespace) -> int:
    allowed, forbidden = None, None
    if args.policy:
        policy = load_policy(args.policy)
        allowed, forbidden = policy.allowed_tools, policy.forbidden_actions
    headers = {}
    for h in args.header or []:
        if "=" not in h:
            raise PolicyError("--header must look like Name=value")
        k, v = h.split("=", 1)
        headers[k.strip()] = os.path.expandvars(v)
    try:
        client = (connect_stdio(args.command, args.timeout) if args.command
                  else connect_http(args.url, headers, args.timeout))
        with client:
            client.initialize()
            tools = client.list_tools()
            resources = client.list_resources()
            prompts = client.list_prompts()
            if args.recheck:
                second_tools = client.list_tools()
                second_resources = client.list_resources()
                second_prompts = client.list_prompts()
            else:
                second_tools = None
            info = client.server_info
    except MCPError as exc:
        print("error: %s" % exc, file=sys.stderr)
        return EXIT_ERROR
    findings = scan_tools(tools, allowed, forbidden) + scan_resources(resources) + scan_prompts(prompts)
    if second_tools is not None:
        findings += compare_pins(make_pins(tools, resources, prompts), second_tools, second_resources, second_prompts)
    if args.pin_write:
        with open(args.pin_write, "w", encoding="utf-8") as fh:
            json.dump(make_pins(tools, resources, prompts), fh, indent=2)
            fh.write("\n")
        print("Pinned %d tool, %d resource and %d prompt definition(s) to %s"
              % (len(tools), len(resources), len(prompts), args.pin_write))
    elif args.pin:
        try:
            with open(args.pin, encoding="utf-8") as fh:
                pins = json.load(fh)
        except (OSError, ValueError) as exc:
            print("error: cannot read pin file %s: %s" % (args.pin, exc), file=sys.stderr)
            return EXIT_ERROR
        findings += compare_pins(pins, tools, resources, prompts)
    report = build_mcp_report(args.command or args.url, info, tools, findings, resources, prompts)
    path = write_mcp_report(report, args.out)
    print(render_mcp_terminal(report))
    print("\nReport written to %s" % path)
    if in_github_actions():
        for line in annotations(report):
            print(line)
    if args.fail_on != "none":
        threshold = severity_rank(args.fail_on)
        if any(severity_rank(f.severity) >= threshold for f in findings):
            return EXIT_FINDINGS
    return EXIT_OK


def _cmd_dashboard(args: argparse.Namespace) -> int:
    from ..dashboard import make_server
    roots = args.paths or ["."]
    missing = [r for r in roots if not os.path.exists(r)]
    if missing:
        raise PolicyError("no such file or directory: %s" % ", ".join(missing))
    if args.host not in ("127.0.0.1", "localhost", "::1"):
        print("warning: the dashboard is listening on %s. Reports contain your agent's real responses and "
              "the dashboard has no login; only do this on a network you trust." % args.host, file=sys.stderr)
    try:
        server = make_server(roots, args.host, args.port, quiet=not args.verbose)
    except OSError as exc:
        raise PolicyError("cannot listen on %s:%d: %s (choose another port with --port)" % (args.host, args.port, exc))
    entries = server.index.entries()
    print("AgentSec dashboard at %s" % server.url)
    print("Found %d report%s under %s; new and rewritten reports appear automatically."
          % (len(entries), "" if len(entries) == 1 else "s", ", ".join(roots)))
    print("Press Ctrl+C to stop.")
    if args.open:
        import webbrowser
        webbrowser.open(server.url)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
    return EXIT_OK


def _cmd_upload(args: argparse.Namespace) -> int:
    from ..upload import SERVER_ENV, UploadError, ci_metadata, upload
    server = args.server or os.environ.get(SERVER_ENV, "")
    if not server:
        print("error: pass --server or set %s to your dashboard's URL" % SERVER_ENV, file=sys.stderr)
        return EXIT_ERROR
    meta = ci_metadata()
    for key in ("branch", "commit", "label", "ci_url"):
        value = getattr(args, key)
        if value:
            meta[key] = value
    try:
        result = upload(args.report, server, os.environ.get(args.token_env, ""), meta, no_traces=args.no_traces)
    except UploadError as exc:
        print("error: %s" % exc, file=sys.stderr)
        return EXIT_ERROR
    print("Uploaded %s%s" % (args.report, (" to %s" % result["url"]) if result.get("url") else ""))
    return EXIT_OK


def _cmd_init(args: argparse.Namespace) -> int:
    try:
        with open(args.path, "x", encoding="utf-8") as fh:
            fh.write(INIT_POLICY)
    except FileExistsError:
        print("error: %s already exists" % args.path, file=sys.stderr)
        return EXIT_ERROR
    print("Wrote %s" % args.path)
    return EXIT_OK


def _cmd_schema(args: argparse.Namespace) -> int:
    schema = policy_json_schema() if args.name == "policy" else trace_json_schema()
    print(json.dumps(schema, indent=2))
    return EXIT_OK


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="agentsec", description="Adversarial security testing for AI agents.")
    p.add_argument("--version", action="version", version="agentsec " + __version__)
    sub = p.add_subparsers(dest="command", required=True)

    t = sub.add_parser("test", help="run the adversarial suite against the agent in the policy")
    t.add_argument("--policy", "-p", default="agentsec.yaml")
    t.add_argument("--out", "-o", default=".agentsec", help="report directory (default .agentsec)")
    t.add_argument("--format", "-f", default="json,html",
                   help="report formats, comma-separated: json, html, markdown, sarif (default json,html)")
    t.add_argument("--seed", type=int, default=0, help="seed for canaries/markers; same seed = same scenarios")
    t.add_argument("--scenario", "-s", action="append", help="only run this category or scenario id (repeatable)")
    t.add_argument("--fail-on", choices=list(SEVERITIES) + ["none"], default="low",
                   help="exit 1 if a finding at or above this severity exists (default low = any)")
    t.add_argument("--judge", action="store_true",
                   help="also run the model-assisted evaluators configured under `judge:` in the policy")
    t.add_argument("--attack-pack", "-A", action="append", metavar="PATH_OR_MODULE",
                   help="load extra scenario categories from a local .py file or an installed package "
                        "(repeatable). See docs/extending.md#write-an-attack-pack")
    t.add_argument("--mcp-listen", metavar="HOST:PORT",
                   help="run AgentSec as the MCP server your agent connects to (streamable HTTP at /mcp); "
                        "tools come from the policy and tool results carry the adversarial content")
    t.add_argument("--verbose", "-v", action="store_true")
    t.set_defaults(func=_cmd_test)

    r = sub.add_parser("replay", help="re-run findings from a report to see whether they still reproduce")
    r.add_argument("report", help="report.json from an earlier run")
    r.add_argument("--policy", "-p", default="agentsec.yaml")
    r.add_argument("--out", "-o", default=".agentsec/replay", help="directory for the replay report")
    r.add_argument("--finding", action="append", help="replay only this finding id (repeatable)")
    r.add_argument("--scenario", "-s", action="append", help="replay only findings of this scenario id (repeatable)")
    r.add_argument("--judge", action="store_true", help="enable the judge so model-assisted findings can be re-checked")
    r.set_defaults(func=_cmd_replay)

    c = sub.add_parser("compare", help="diff two report.json files and flag regressions")
    c.add_argument("baseline", help="earlier report.json (for example from main)")
    c.add_argument("current", help="newer report.json (for example from a pull request)")
    c.add_argument("--fail-on", choices=list(SEVERITIES) + ["none"], default="low",
                   help="exit 1 if a new or worsened finding at or above this severity exists (default low)")
    c.set_defaults(func=_cmd_compare)

    m = sub.add_parser("mcp", help="test MCP servers")
    msub = m.add_subparsers(dest="mcp_command", required=True)
    ms = msub.add_parser("scan", help="connect to an MCP server, list its tools and check the definitions "
                                      "(never calls a tool)")
    target = ms.add_mutually_exclusive_group(required=True)
    target.add_argument("--command", help="start a stdio server with this command, e.g. 'python server.py'")
    target.add_argument("--url", help="streamable-HTTP server URL")
    ms.add_argument("--header", action="append", help="HTTP header Name=value (repeatable; $ENV_VARS are expanded)")
    ms.add_argument("--policy", "-p", help="agentsec.yaml whose allowed_tools / forbidden_actions the server is checked against")
    ms.add_argument("--pin", help="pin file from an earlier --pin-write; changed definitions are reported")
    ms.add_argument("--pin-write", help="write a pin file with the current definitions")
    ms.add_argument("--recheck", action="store_true", help="list tools twice in one session and report changes")
    ms.add_argument("--out", "-o", default=".agentsec", help="report directory (default .agentsec)")
    ms.add_argument("--timeout", type=float, default=20.0)
    ms.add_argument("--fail-on", choices=list(SEVERITIES) + ["none"], default="low")
    ms.set_defaults(func=_cmd_mcp_scan)

    d = sub.add_parser("dashboard", help="browse reports in a local, read-only web dashboard")
    d.add_argument("paths", nargs="*", metavar="PATH",
                   help="report files or directories to search for report.json and mcp-report.json "
                        "(default: the current directory)")
    d.add_argument("--host", default="127.0.0.1", help="address to listen on (default 127.0.0.1, this machine only)")
    d.add_argument("--port", type=int, default=8710, help="port to listen on (default 8710; 0 picks a free one)")
    d.add_argument("--open", action="store_true", help="open the dashboard in your browser")
    d.add_argument("--verbose", "-v", action="store_true", help="log each request")
    d.set_defaults(func=_cmd_dashboard)

    u = sub.add_parser("upload", help="send a report to a hosted AgentSec dashboard (opt-in)")
    u.add_argument("report", nargs="?", default=".agentsec/report.json",
                   help="report.json or mcp-report.json to upload (default .agentsec/report.json)")
    u.add_argument("--server", help="dashboard URL (or set AGENTSEC_SERVER)")
    u.add_argument("--token-env", default="AGENTSEC_TOKEN", metavar="NAME",
                   help="environment variable holding the project token (default AGENTSEC_TOKEN)")
    u.add_argument("--branch", help="branch name to record (read from GitHub Actions automatically)")
    u.add_argument("--commit", help="commit SHA to record (read from GitHub Actions automatically)")
    u.add_argument("--ci-url", dest="ci_url", help="link to the CI run (read from GitHub Actions automatically)")
    u.add_argument("--label", help="a short label for this run, e.g. 'gpt-4.1 prompt v3'")
    u.add_argument("--no-traces", action="store_true",
                   help="leave out the full scenario transcripts; findings and their evidence are still sent")
    u.set_defaults(func=_cmd_upload)

    i = sub.add_parser("init", help="write a starter agentsec.yaml")
    i.add_argument("path", nargs="?", default="agentsec.yaml")
    i.set_defaults(func=_cmd_init)

    s = sub.add_parser("schema", help="print the JSON schema for policies or traces")
    s.add_argument("name", choices=["policy", "trace"])
    s.set_defaults(func=_cmd_schema)
    return p


def main(argv: Optional[List[str]] = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        return args.func(args)
    except PolicyError as exc:
        print("error: %s" % exc, file=sys.stderr)
        return EXIT_ERROR


if __name__ == "__main__":
    sys.exit(main())
