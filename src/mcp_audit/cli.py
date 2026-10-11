"""mcp-audit CLI: scan local MCP configs and optionally fix them."""

from __future__ import annotations

import argparse
import json
import sys

from . import __version__
from .scanners import (
    agent_guard_link,
    apply_fixes,
    discover_configs,
    load_config,
    plan_fixes,
    run_all_scans,
)

EXIT_OK = 0
EXIT_FINDINGS = 1
EXIT_ERROR = 2


def _parse_args(argv):
    parser = argparse.ArgumentParser(
        prog="mcp-audit",
        description="Local runtime security scanner for MCP servers.",
    )
    parser.add_argument("--version", action="version", version=__version__)
    sub = parser.add_subparsers(dest="command", required=True)

    scan = sub.add_parser("scan", help="scan MCP configs for security issues")
    scan.add_argument("--config", action="append", dest="configs",
                      metavar="PATH", default=[],
                      help="config file to scan (repeatable; defaults to "
                           "~/.claude.json and other known locations)")
    scan.add_argument("--format", choices=["text", "json"], default="text",
                      help="output format")
    scan.add_argument("--probe", action="store_true",
                      help="send one unauthenticated GET to each http/sse "
                           "endpoint to confirm reachability")
    scan.add_argument("--timeout", type=float, default=4.0,
                      help="probe timeout in seconds (default 4.0)")
    scan.add_argument("--link-agent-guard", action="store_true",
                      help="write critical servers into agent-guard's "
                           "blocklist when it is installed")

    fix = sub.add_parser("fix", help="print or apply one-click fixes")
    fix.add_argument("--config", action="append", dest="configs",
                     metavar="PATH", default=[],
                     help="config file to fix (repeatable)")
    fix.add_argument("--apply", action="store_true",
                     help="write the fixes to the config file (backs up "
                          "first); without it only prints the plan")
    return parser.parse_args(argv)


def _load_all(paths):
    servers, errors = [], []
    for path in paths:
        svcs, err = load_config(path)
        if err:
            errors.append(err)
        servers.extend(svcs)
    return servers, errors


def _format_text(findings, errors, n_servers, n_configs):
    lines = []
    if errors:
        for e in errors:
            lines.append("error: %s" % e)
    if not findings:
        lines.append("mcp-audit: %d server(s) in %d config(s): no findings"
                     % (n_servers, n_configs))
        return "\n".join(lines)
    sev_max = findings[0].severity
    lines.append("mcp-audit: %d finding(s) across %d server(s) "
                 "(worst: %s):" % (len(findings), n_servers, sev_max))
    for f in findings:
        cve = " [%s]" % f.cve_id if f.cve_id else ""
        lines.append("[%s]%s %s (%s): %s"
                     % (f.severity.upper(), cve, f.rule_id, f.server, f.evidence))
        lines.append("  fix: %s" % f.fix)
    return "\n".join(lines)


def cmd_scan(args):
    paths = discover_configs(args.configs)
    if not paths:
        msg = {"findings": [], "errors": ["no config files found"],
               "summary": {"servers": 0, "configs": 0}}
        if args.format == "json":
            print(json.dumps(msg, indent=2))
        else:
            print("mcp-audit: no MCP config files found "
                  "(checked ~/.claude.json, ~/.codex/config.json, "
                  "~/.config/mcp/servers.json, ~/.mcp.json); "
                  "pass --config PATH to scan a specific file")
        return EXIT_ERROR
    servers, errors = _load_all(paths)
    findings = run_all_scans(servers, probe=args.probe, timeout=args.timeout)
    if args.link_agent_guard and findings:
        linked, msg = agent_guard_link(findings)
        if args.format == "json":
            pass  # message folded into output below
        else:
            print(msg)
    if args.format == "json":
        print(json.dumps({
            "findings": [f.to_dict() for f in findings],
            "errors": errors,
            "summary": {
                "servers": len(servers),
                "configs": len(paths),
                "findings": len(findings),
                "worst": findings[0].severity if findings else None,
            },
        }, indent=2))
    else:
        print(_format_text(findings, errors, len(servers), len(paths)))
    if errors and not servers:
        return EXIT_ERROR
    return EXIT_FINDINGS if findings else EXIT_OK


def cmd_fix(args):
    paths = discover_configs(args.configs)
    if not paths:
        print("mcp-audit: no MCP config files found; pass --config PATH")
        return EXIT_ERROR
    rc = EXIT_OK
    for path in paths:
        servers, errors = _load_all([path])
        findings = run_all_scans(servers)
        plan, missing = plan_fixes(path, findings) if not errors else ([], [])
        if args.apply:
            if errors:
                print("%s: error: %s" % (path, errors[0]))
                rc = EXIT_ERROR
                continue
            if not plan:
                print("%s: nothing fixable" % path)
                continue
            backup, applied = apply_fixes(path, findings)
            print("%s: applied %d fix(es); backup at %s"
                  % (path, applied, backup))
        else:
            print("%s:" % path)
            if not plan and not missing:
                print("  nothing fixable")
            for item in plan:
                print("  - [%s] %s: %s" % (
                    item["rule_id"], item["server"], item["action"]))
            for name in missing:
                print("  - %s: server not found in config (skipped)" % name)
            if plan:
                print("  re-run with --apply to write these fixes "
                      "(config is backed up first)")
    return rc


def main(argv=None):
    args = _parse_args(argv if argv is not None else sys.argv[1:])
    if args.command == "scan":
        return cmd_scan(args)
    if args.command == "fix":
        return cmd_fix(args)
    return EXIT_ERROR


if __name__ == "__main__":
    sys.exit(main())
