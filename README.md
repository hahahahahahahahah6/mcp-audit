# mcp-audit

A local runtime security scanner for MCP servers. Point it at your MCP client
configs and it flags the misconfigurations and known vulnerabilities that
actually get exploited — then offers one-click fixes. Zero third-party
dependencies, Python >= 3.9.

```bash
pip install mcp-audit
mcp-audit scan
```

## Why this exists

MCP servers run with your user's privileges and are driven by an AI agent on
your behalf — which makes them a very different threat surface from a library
you import. The evidence so far is not reassuring:

- **The official tooling itself has shipped RCE.** CVE-2025-49596 hit
  Anthropic's MCP Inspector (CVSS 9.4): its local proxy accepted an
  unauthenticated `/sse` request with `transportType=stdio&command=<cmd>` and
  spawned it as a subprocess — visiting a malicious page was enough to run
  code on the developer's machine. Fixed in Inspector 0.14.1.
- **Enterprise MCP apps are not immune.** CVE-2026-76404 (Splunk MCP Server
  < 1.2.1, CVSS 9.1): unsafe deserialization in credential management let an
  admin-role user execute arbitrary OS commands (Splunk advisory
  SVD-2026-0808).
- **Anthropic treats stdio risk as "expected"** — the position is that the
  security burden sits with whoever deploys the server, not the protocol.
  That leaves every local config file as the real security boundary, and
  those files are hand-edited JSON.
- **Unpatched servers are out there in production.** Five US federal
  government MCP servers were found running unpatched, and internet-wide
  scans keep turning up thousands of exposed MCP endpoints, the vast majority
  without any authentication.

Nobody audits their own `~/.claude.json` by hand. mcp-audit does it in a
second, in CI-friendly form.

## How it differs

| Tool | Known-CVE version checks | One-click fixes | Focus |
|------|--------------------------|-----------------|-------|
| **mcp-audit** | ✅ bundled CVE table | ✅ `fix --apply` | runtime security |
| mcpscan | ❌ | ❌ | static config scanning |
| graygnatconsole mcp-audit-tool | ❌ | ❌ | config auditing |
| mcp-lint | n/a | n/a | **design quality** linting, not runtime security — no overlap |

mcpscan and graygnatconsole's mcp-audit-tool scan configs but neither maps
your installed server versions against known CVEs, and neither writes fixes
back. mcp-lint is a design-quality linter for MCP servers; mcp-audit is a
runtime security scanner for the servers you run — different layer, no
overlap.

## Quick start

```bash
pip install mcp-audit

# scan default locations (~/.claude.json, ~/.codex/config.json,
# ~/.config/mcp/servers.json, ~/.mcp.json)
mcp-audit scan

# scan a specific file, JSON output for CI
mcp-audit scan --config ~/my-claude.json --format json

# confirm unauthenticated reachability with a live probe
# (one unauthenticated GET per endpoint)
mcp-audit scan --probe

# preview fixes (dry run), then apply them (backs up first)
mcp-audit fix --config ~/.claude.json
mcp-audit fix --config ~/.claude.json --apply
```

Exit codes: `0` clean, `1` findings, `2` errors — CI-ready.

## What it checks

1. **Dangerous stdio commands (`STDIO-SHELL`, high).** A stdio entry wrapping
   execution in `bash -c` / `sh -c` / `cmd /c` is command injection by
   design — this is the Langflow CVE-2026-105697 pattern (CVSS 9.9). Flags
   the server and shows the exact invocation.
2. **Unauthenticated SSE/HTTP endpoints (`UNAUTH-ENDPOINT`,
   critical with `--probe`).** Endpoints with no `Authorization`/`X-API-Key`
   header. `--probe` sends one unauthenticated GET to confirm the endpoint
   actually answers — the CVE-2025-49596 shape.
3. **Bind addresses (`BIND-ADDR`, high).** Servers bound to `0.0.0.0` or `::`
   in URLs, `--host` flags, or env vars are reachable beyond localhost.
4. **Known-CVE version checks (`KNOWN-CVE`, per-CVE severity).** Extracts
   `package@version` from `npx`/`uvx` invocations and matches against the
   bundled CVE table below.

Every finding carries a rule id, CVE id, severity, the evidence, and the fix
command — in both text and JSON output.

### One-click fix

`mcp-audit fix` defaults to a dry-run plan. With `--apply` it:

- rewrites `0.0.0.0` → `127.0.0.1` in URLs, `--host` flags, and env values,
- adds an `Authorization: Bearer ${MCP_TOKEN}` placeholder header to
  unauthenticated endpoints (you fill in a real token),
- backs up the config to `<file>.bak-<timestamp>` before writing,
- links critical servers into agent-guard's `blocked_servers` list when an
  agent-guard config is detected (see below).

### agent-guard integration

`mcp-audit scan --link-agent-guard` writes every critical server into
agent-guard's blocklist (config backed up first). If agent-guard isn't
installed, it prints the manual linking instruction instead.

## CVE table

Bundled advisory snapshot (2026-10). Re-check NVD / vendor releases before
using these for compliance reporting.

| CVE | Product | Affected | Fix | Class |
|-----|---------|----------|-----|-------|
| CVE-2025-49596 | @modelcontextprotocol/inspector | < 0.14.1 | 0.14.1 | Unauthenticated RCE, CVSS 9.4 |
| CVE-2026-76404 | splunk-mcp-server | < 1.2.1 | 1.2.1 | Unsafe deserialization RCE, CVSS 9.1 |
| CVE-2026-58201 | lokka (M365 MCP) | < 2.1.2 | 2.1.2 | SSRF leaking ARM bearer token |
| CVE-2026-105697 | langflow / langflow-base / lfx | < 1.10.3 | 1.10.3 | MCP stdio `bash -c` RCE, CVSS 9.9 |
| CVE-2026-89039 | (product mapping pending) | — | — | See NVD |
| CVE-2026-105793 | (product mapping pending) | — | — | See NVD |
| CVE-2026-94486 | (product mapping pending) | — | — | See NVD |
| CVE-2026-19807 | (product mapping pending) | — | — | See NVD |

## CI example

```yaml
# .github/workflows/mcp-audit.yml
- uses: actions/setup-python@v5
  with: { python-version: "3.12" }
- run: pip install mcp-audit
- run: mcp-audit scan --config ./mcp-servers.json --format json
# exits 1 on findings -> fails the build
```

## Limitations

- Version detection reads `package@version` from your config's command/args
  (npx/uvx/node style). Servers installed another way, or without a pinned
  version, won't match the CVE table.
- `--probe` sends one unauthenticated GET per endpoint — no auth bypass
  attempts, no payloads, and it never mutates anything. It still touches
  the network; don't run it against hosts you don't own.
- The CVE table is a bundled snapshot, not a live feed. New CVEs need a new
  release.
- Static checks can't see what a server does after it starts (dynamic tool
  behavior, prompt injection in tool outputs). This is a config/runtime
  surface scanner, not a runtime behavior monitor.

## License

MIT.
