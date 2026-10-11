"""Config discovery, parsing, and security scanners for mcp-audit."""

from __future__ import annotations

import json
import os
import re
import socket
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field

from .cve_db import affected_cves

# ---------------------------------------------------------------- config I/O

DEFAULT_CONFIG_PATHS = [
    os.path.expanduser("~/.claude.json"),
    os.path.expanduser("~/.codex/config.json"),
    os.path.expanduser("~/.config/mcp/servers.json"),
    os.path.expanduser("~/.mcp.json"),
]


@dataclass
class McpServer:
    """One server entry parsed from a config file."""

    name: str
    transport: str  # "stdio" | "sse" | "http" | "unknown"
    command: str = ""
    args: list = field(default_factory=list)
    env: dict = field(default_factory=dict)
    url: str = ""
    headers: dict = field(default_factory=dict)
    version: str = ""
    package: str = ""
    source_file: str = ""


@dataclass
class Finding:
    rule_id: str
    cve_id: str
    severity: str  # critical | high | medium | low | info
    server: str
    evidence: str
    fix: str
    source_file: str = ""

    def to_dict(self):
        return {
            "rule_id": self.rule_id,
            "cve_id": self.cve_id,
            "severity": self.severity,
            "server": self.server,
            "evidence": self.evidence,
            "fix": self.fix,
            "source_file": self.source_file,
        }


def _servers_from_entry(name, entry, source_file=""):
    srv = McpServer(name=name, transport="unknown", source_file=source_file)
    if not isinstance(entry, dict):
        return srv
    srv.command = str(entry.get("command", "") or "")
    args = entry.get("args", [])
    srv.args = [str(a) for a in args] if isinstance(args, list) else []
    env = entry.get("env", {})
    srv.env = dict(env) if isinstance(env, dict) else {}
    srv.url = str(entry.get("url", "") or "")
    headers = entry.get("headers", {})
    srv.headers = dict(headers) if isinstance(headers, dict) else {}
    srv.version = str(entry.get("version", "") or "")

    if srv.url:
        parsed = urllib.parse.urlparse(srv.url)
        if parsed.scheme in ("http", "https"):
            srv.transport = "sse" if parsed.path.endswith("/sse") or "sse" in parsed.path else "http"
    elif srv.command:
        srv.transport = "stdio"

    srv.package, srv.version = _infer_package(srv) or (srv.package, srv.version or "")
    return srv


_PKG_RE = re.compile(r"^([@a-zA-Z0-9_.\-/]+?)(?:@([0-9][0-9A-Za-z.\-]*))?$")


def _infer_package(srv):
    """Guess (package, version) from an npx/uvx/node invocation.

    Handles args like ["-y", "@modelcontextprotocol/inspector@0.13.0"]
    or ["mcp-server-foo@1.2.3", ...].
    """
    tokens = [srv.command] + list(srv.args)
    for tok in tokens:
        tok = tok.strip()
        if tok.startswith("-"):
            continue
        m = _PKG_RE.match(tok)
        if not m:
            continue
        name, ver = m.group(1), m.group(2)
        if "/" in name or name.startswith("@") or re.fullmatch(r"[a-zA-Z0-9_.\-]+", name):
            if ver:
                return name, ver
    return None


def _walk_mcp_servers(obj, source_file=""):
    """Extract mcpServers dicts from a parsed JSON config."""
    found = []
    if isinstance(obj, dict):
        if "mcpServers" in obj and isinstance(obj["mcpServers"], dict):
            for name, entry in obj["mcpServers"].items():
                found.append(_servers_from_entry(name, entry, source_file))
        for key in ("servers", "mcp_servers"):
            if key in obj and isinstance(obj[key], dict):
                for name, entry in obj[key].items():
                    found.append(_servers_from_entry(name, entry, source_file))
        # Recurse into nested dicts (e.g. Claude Code's per-project blocks
        # inside ~/.claude.json) to avoid missing nested mcpServers.
        for key, value in obj.items():
            if key in ("mcpServers", "servers", "mcp_servers"):
                continue
            if isinstance(value, dict):
                found.extend(_walk_mcp_servers(value, source_file))
    return found


def load_config(path):
    """Load one config file, return (servers, error_message)."""
    try:
        with open(path, encoding="utf-8") as fh:
            data = json.load(fh)
    except (OSError, json.JSONDecodeError) as exc:
        return [], "cannot read %s: %s" % (path, exc)
    return _walk_mcp_servers(data, path), ""


def discover_configs(explicit=None):
    """Return list of config paths: explicit ones, else existing defaults."""
    if explicit:
        return list(explicit)
    return [p for p in DEFAULT_CONFIG_PATHS if os.path.isfile(p)]

# ------------------------------------------------------------ rule 1: stdio

# Shell-wrapper patterns that turn a stdio config into command injection.
SHELL_PATTERNS = [
    (re.compile(r"(^|\s)bash\s+-c(\s|$)", re.I), "bash -c"),
    (re.compile(r"(^|\s)sh\s+-c(\s|$)", re.I), "sh -c"),
    (re.compile(r"(^|\s)zsh\s+-c(\s|$)", re.I), "zsh -c"),
    (re.compile(r"(^|\s)(cmd|powershell|pwsh)(\.exe)?\s+(/[cC]|-c|-Command)(\s|$)"), "cmd /c"),
    (re.compile(r"&&|\|\||;\s*(curl|wget|rm|chmod|nc|ncat)\b", re.I), "command chaining"),
]


def scan_dangerous_stdio(servers):
    """Flag stdio servers whose command/args wrap execution in a shell."""
    findings = []
    for srv in servers:
        if srv.transport != "stdio":
            continue
        invocation = " ".join([srv.command] + list(srv.args))
        for pattern, label in SHELL_PATTERNS:
            if pattern.search(invocation):
                findings.append(
                    Finding(
                        rule_id="STDIO-SHELL",
                        cve_id="CVE-2026-105697",
                        severity="high",
                        server=srv.name,
                        evidence="stdio server %r runs through shell wrapper %s: %s"
                        % (srv.name, label, invocation[:200]),
                        fix="Remove the shell wrapper: set command to the real "
                        "executable and pass each argument separately in args. "
                        "Never pass untrusted input into a shell -c string.",
                        source_file=srv.source_file,
                    )
                )
                break
    return findings

# ------------------------------------------------- rule 2: unauth endpoints


def _probe_endpoint(url, timeout=4.0):
    """Send one unauthenticated GET. Returns (reachable, status, detail).

    reachable=True means the endpoint answered *without* any credentials —
    the unauthenticated-reachability signal this scanner is built to detect.
    """
    req = urllib.request.Request(url, headers={"User-Agent": "mcp-audit/0.1.0"})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return True, resp.status, "HTTP %s" % resp.status
    except urllib.error.HTTPError as exc:
        if exc.code in (401, 403, 407):
            return False, exc.code, "HTTP %s (auth required)" % exc.code
        return True, exc.code, "HTTP %s (reachable without auth)" % exc.code
    except urllib.error.URLError as exc:
        return False, 0, "unreachable: %s" % exc.reason
    except (socket.timeout, OSError) as exc:
        return False, 0, "unreachable: %s" % exc


def scan_unauthenticated_endpoints(servers, timeout=4.0, probe=False):
    """Flag http/sse servers reachable with no authentication.

    probe=False (default): static config check — flags non-loopback URLs
    with no Authorization/Api-Key header. probe=True: also sends one
    unauthenticated GET to confirm the endpoint answers.
    """
    findings = []
    for srv in servers:
        if srv.transport not in ("sse", "http") or not srv.url:
            continue
        host = urllib.parse.urlparse(srv.url).hostname or ""
        has_auth = any(
            k.lower() in ("authorization", "x-api-key", "x-auth-token", "cookie")
            for k in srv.headers
        )
        evidence_bits = []
        if probe:
            reachable, status, detail = _probe_endpoint(srv.url, timeout=timeout)
            if reachable:
                evidence_bits.append("unauthenticated GET -> %s" % detail)
        else:
            reachable = host not in ("", "127.0.0.1", "::1", "localhost")
            evidence_bits.append("no auth header configured")
        if reachable and not has_auth:
            findings.append(
                Finding(
                    rule_id="UNAUTH-ENDPOINT",
                    cve_id="CVE-2025-49596",
                    severity="critical" if probe else "high",
                    server=srv.name,
                    evidence="server %r exposes %s: %s"
                    % (srv.name, srv.url, "; ".join(evidence_bits)),
                    fix="Require authentication: put the endpoint behind an "
                    "auth proxy or add headers={\"Authorization\": \"Bearer ${MCP_TOKEN}\"} "
                    "to the config and rotate the token.",
                    source_file=srv.source_file,
                )
            )
    return findings

# ------------------------------------------------------ rule 3: bind address

BIND_RE = re.compile(r"--?(?:bind|host|listen)(?:-address)?[= ]\s*([0-9a-zA-Z.:]+)")
PUBLIC_HOSTS = {"0.0.0.0", "::"}


def scan_bind_address(servers):
    """Flag servers bound to all interfaces (0.0.0.0 / ::)."""
    findings = []
    for srv in servers:
        hits = []
        if srv.url:
            host = urllib.parse.urlparse(srv.url).hostname or ""
            if host in PUBLIC_HOSTS:
                hits.append("url host %s" % host)
        invocation = " ".join([srv.command] + list(srv.args))
        for m in BIND_RE.finditer(invocation):
            if m.group(1) in PUBLIC_HOSTS:
                hits.append("flag %s=%s" % (m.group(0), m.group(1)))
        for value in srv.env.values():
            if str(value).strip() in PUBLIC_HOSTS:
                hits.append("env value %s" % value)
        for hit in hits:
            findings.append(
                Finding(
                    rule_id="BIND-ADDR",
                    cve_id="CVE-2025-49596",
                    severity="high",
                    server=srv.name,
                    evidence="server %r binds to all interfaces (%s); "
                    "reachable beyond localhost" % (srv.name, hit),
                    fix="Bind to 127.0.0.1 instead of 0.0.0.0: e.g. replace "
                    "--host 0.0.0.0 with --host 127.0.0.1. "
                    "mcp-audit fix --apply does this automatically.",
                    source_file=srv.source_file,
                )
            )
    return findings

# ------------------------------------------------------ rule 4: known CVEs


def scan_known_cves(servers):
    """Flag servers running package versions hit by the bundled CVE table."""
    findings = []
    for srv in servers:
        if not srv.package:
            continue
        for entry in affected_cves(srv.package, srv.version):
            findings.append(
                Finding(
                    rule_id="KNOWN-CVE",
                    cve_id=entry["id"],
                    severity=entry["severity"],
                    server=srv.name,
                    evidence="server %r runs %s@%s, affected by %s (%s, CVSS %s)"
                    % (
                        srv.name,
                        srv.package,
                        srv.version,
                        entry["id"],
                        entry["title"],
                        entry.get("cvss") or "?",
                    ),
                    fix="Upgrade to %s or later, then restart the server. "
                    "Refs: %s"
                    % (entry.get("fixed_in") or "a patched version",
                       ", ".join(entry.get("references", [])) or "see NVD"),
                    source_file=srv.source_file,
                )
            )
    return findings

# ------------------------------------------------------------ orchestration

SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


def run_all_scans(servers, probe=False, timeout=4.0):
    findings = []
    findings += scan_dangerous_stdio(servers)
    findings += scan_unauthenticated_endpoints(servers, timeout=timeout, probe=probe)
    findings += scan_bind_address(servers)
    findings += scan_known_cves(servers)
    findings.sort(key=lambda f: (SEVERITY_ORDER.get(f.severity, 5), f.server))
    return findings

# ------------------------------------------------------------ one-click fix

FIXABLE_RULES = {"BIND-ADDR", "UNAUTH-ENDPOINT"}


def _apply_bind_fix(entry):
    """Rewrite 0.0.0.0 / :: bindings to 127.0.0.1 in url, args, env."""
    changed = False
    if isinstance(entry.get("url"), str):
        url = entry["url"]
        new_url = re.sub(r"://(0\.0\.0\.0|::)(:|/)", r"://127.0.0.1\2", url)
        if new_url != url:
            entry["url"] = new_url
            changed = True
    args = entry.get("args")
    if isinstance(args, list):
        i = 0
        while i < len(args):
            arg = args[i]
            if isinstance(arg, str):
                if re.fullmatch(r"--?(?:host|bind|listen)(?:-address)?", arg):
                    nxt = args[i + 1] if i + 1 < len(args) else None
                    if nxt in ("0.0.0.0", "::"):
                        args[i + 1] = "127.0.0.1"
                        changed = True
                else:
                    fixed = re.sub(
                        r"^(--?(?:host|bind|listen)(?:-address)?)=(0\.0\.0\.0|::)$",
                        r"\1=127.0.0.1",
                        arg,
                    )
                    if fixed != arg:
                        args[i] = fixed
                        changed = True
            i += 1
    env = entry.get("env")
    if isinstance(env, dict):
        for k, v in env.items():
            if str(v).strip() in PUBLIC_HOSTS:
                env[k] = "127.0.0.1"
                changed = True
    return changed


def _apply_auth_fix(entry):
    if not isinstance(entry.get("headers"), dict):
        entry["headers"] = {}
    if not any(
        k.lower() in ("authorization", "x-api-key", "x-auth-token", "cookie")
        for k in entry["headers"]
    ):
        entry["headers"]["Authorization"] = "Bearer ${MCP_TOKEN}"
        return True
    return False


def plan_fixes(path, findings):
    """Build a fix plan for one config file. Returns (plan, missing_servers)."""
    with open(path, encoding="utf-8") as fh:
        data = json.load(fh)
    containers = []
    for key in ("mcpServers", "servers", "mcp_servers"):
        if key in data and isinstance(data[key], dict):
            containers.append((key, data[key]))

    plan = []
    done = set()
    for f in findings:
        if f.rule_id not in FIXABLE_RULES:
            continue
        for ckey, container in containers:
            if f.server in container and (f.server, f.rule_id) not in done:
                plan.append(
                    {
                        "server": f.server,
                        "rule_id": f.rule_id,
                        "container": ckey,
                        "action": (
                            "bind 0.0.0.0 -> 127.0.0.1"
                            if f.rule_id == "BIND-ADDR"
                            else 'add Authorization: Bearer ${MCP_TOKEN} placeholder header'
                        ),
                    }
                )
                done.add((f.server, f.rule_id))
    missing = [f.server for f in findings
               if f.rule_id in FIXABLE_RULES and (f.server, f.rule_id) not in done]
    return plan, missing


def apply_fixes(path, findings):
    """Apply fixes to a config file. Returns (backup_path, applied_count)."""
    with open(path, encoding="utf-8") as fh:
        data = json.load(fh)

    plan, _ = plan_fixes(path, findings)
    if not plan:
        return "", 0

    backup_path = "%s.bak-%s" % (path, time.strftime("%Y%m%d-%H%M%S"))
    with open(backup_path, "w", encoding="utf-8") as fh:
        json.dump(data, fh, indent=2)

    applied = 0
    for item in plan:
        container = data.get(item["container"], {})
        entry = container.get(item["server"])
        if not isinstance(entry, dict):
            continue
        if item["rule_id"] == "BIND-ADDR" and _apply_bind_fix(entry):
            applied += 1
        elif item["rule_id"] == "UNAUTH-ENDPOINT" and _apply_auth_fix(entry):
            applied += 1

    with open(path, "w", encoding="utf-8") as fh:
        json.dump(data, fh, indent=2)
        fh.write("\n")
    return backup_path, applied

# -------------------------------------------------- agent-guard integration

AGENT_GUARD_CONFIG_PATHS = [
    os.path.expanduser("~/.agent-guard/config.json"),
    os.path.expanduser("~/.config/agent-guard/config.json"),
    os.path.expanduser("~/.agent-guard.json"),
]


def agent_guard_link(findings):
    """Link critical findings into agent-guard's blocklist.

    Returns (linked, message): linked=True when an agent-guard config was
    found and updated; otherwise prints the manual linking instruction.
    """
    critical = sorted({f.server for f in findings if f.severity == "critical"})
    if not critical:
        return False, "no critical servers to link"
    for path in AGENT_GUARD_CONFIG_PATHS:
        if not os.path.isfile(path):
            continue
        try:
            with open(path, encoding="utf-8") as fh:
                cfg = json.load(fh)
        except (OSError, json.JSONDecodeError):
            continue
        blocked = cfg.setdefault("blocked_servers", [])
        added = 0
        for name in critical:
            if name not in blocked:
                blocked.append(name)
                added += 1
        if added:
            backup = "%s.bak-%s" % (path, time.strftime("%Y%m%d-%H%M%S"))
            os.replace(path, backup)
            with open(path, "w", encoding="utf-8") as fh:
                json.dump(cfg, fh, indent=2)
        return True, "linked %d critical server(s) to %s: %s" % (
            added, path, ", ".join(critical))
    return False, (
        "agent-guard config not found. Manual link: add %s to "
        "agent-guard's blocked_servers list (or run "
        "'agent-guard block %s')." % (", ".join(critical), critical[0])
    )
