"""Bundled known-CVE table for MCP servers and MCP-adjacent tooling.

This is a best-effort advisory snapshot (bundled 2026-10). Affected
version ranges come from public advisories; re-check NVD / vendor
releases before using these for compliance reporting.
"""

from __future__ import annotations

CVE_DB = [
    {
        "id": "CVE-2025-49596",
        "title": "MCP Inspector proxy unauthenticated RCE",
        "cvss": 9.4,
        "severity": "critical",
        "products": ["@modelcontextprotocol/inspector", "mcp-inspector"],
        "affected": "<0.14.1",
        "fixed_in": "0.14.1",
        "description": (
            "The MCP Inspector proxy (default port 6277) accepted an "
            "unauthenticated request to /sse with transportType=stdio and "
            "arbitrary command/args, spawning the command as a local "
            "subprocess. A malicious web page could drive it cross-origin "
            "(0.0.0.0-day / DNS rebinding), so visiting a page was enough "
            "to execute code on the developer's machine."
        ),
        "references": [
            "https://nvd.nist.gov/vuln/detail/CVE-2025-49596",
            "https://github.com/modelcontextprotocol/inspector/security/advisories/GHSA-7f8r-222p-6f5g",
        ],
    },
    {
        "id": "CVE-2026-76404",
        "title": "Splunk MCP Server unsafe deserialization RCE",
        "cvss": 9.1,
        "severity": "critical",
        "products": ["splunk-mcp-server", "@splunk/mcp-server"],
        "affected": "<1.2.1",
        "fixed_in": "1.2.1",
        "description": (
            "The Splunk MCP Server app's credential-management component "
            "deserialized stored data without type validation (CWE-502). "
            "A user holding the Splunk admin role could execute arbitrary "
            "OS commands on the host. Splunk advisory SVD-2026-0808."
        ),
        "references": [
            "https://nvd.nist.gov/vuln/detail/CVE-2026-76404",
        ],
    },
    {
        "id": "CVE-2026-58201",
        "title": "Lokka Microsoft 365 MCP Server SSRF",
        "cvss": None,
        "severity": "high",
        "products": ["lokka", "lokka-microsoft"],
        "affected": "<2.1.2",
        "fixed_in": "2.1.2",
        "description": (
            "Lokka's Lokka-Microsoft tool built Azure Resource Manager "
            "request URLs by concatenating a user-supplied path onto the "
            "management.azure.com base string (CWE-918). A crafted path "
            "could redirect a valid ARM Bearer token to an "
            "attacker-controlled host."
        ),
        "references": [
            "https://nvd.nist.gov/vuln/detail/CVE-2026-58201",
        ],
    },
    {
        "id": "CVE-2026-105697",
        "title": "Langflow MCP stdio transport RCE (bash -c wrapper)",
        "cvss": 9.9,
        "severity": "critical",
        "products": ["langflow", "langflow-base", "lfx"],
        "affected": "<1.10.3",
        "fixed_in": "1.10.3",
        "description": (
            "Before 1.10.3 the MCP stdio transport launched whatever "
            "command/args a user put in an MCP server configuration with "
            "no allowlist, wrapped in `bash -c \"exec {command} ...\"` "
            "(CWE-78). With the default LANGFLOW_AUTO_LOGIN=true, an "
            "unauthenticated attacker could add a malicious MCP server and "
            "get remote code execution on the Langflow host."
        ),
        "references": [
            "https://nvd.nist.gov/vuln/detail/CVE-2026-105697",
        ],
    },
    {
        "id": "CVE-2026-89039",
        "title": "MCP server RCE (advisory, see NVD for product mapping)",
        "cvss": None,
        "severity": "high",
        "products": [],
        "affected": None,
        "fixed_in": None,
        "description": (
            "Known CVE in the MCP ecosystem. Product/version mapping not "
            "bundled in this snapshot; check the NVD entry and vendor "
            "advisories for affected versions."
        ),
        "references": ["https://nvd.nist.gov/vuln/detail/CVE-2026-89039"],
    },
    {
        "id": "CVE-2026-105793",
        "title": "MCP server vulnerability (advisory, see NVD for product mapping)",
        "cvss": None,
        "severity": "high",
        "products": [],
        "affected": None,
        "fixed_in": None,
        "description": (
            "Known CVE in the MCP ecosystem. Product/version mapping not "
            "bundled in this snapshot; check the NVD entry and vendor "
            "advisories for affected versions."
        ),
        "references": ["https://nvd.nist.gov/vuln/detail/CVE-2026-105793"],
    },
    {
        "id": "CVE-2026-94486",
        "title": "MCP server vulnerability (advisory, see NVD for product mapping)",
        "cvss": None,
        "severity": "high",
        "products": [],
        "affected": None,
        "fixed_in": None,
        "description": (
            "Known CVE in the MCP ecosystem. Product/version mapping not "
            "bundled in this snapshot; check the NVD entry and vendor "
            "advisories for affected versions."
        ),
        "references": ["https://nvd.nist.gov/vuln/detail/CVE-2026-94486"],
    },
    {
        "id": "CVE-2026-19807",
        "title": "MCP server vulnerability (advisory, see NVD for product mapping)",
        "cvss": None,
        "severity": "high",
        "products": [],
        "affected": None,
        "fixed_in": None,
        "description": (
            "Known CVE in the MCP ecosystem. Product/version mapping not "
            "bundled in this snapshot; check the NVD entry and vendor "
            "advisories for affected versions."
        ),
        "references": ["https://nvd.nist.gov/vuln/detail/CVE-2026-19807"],
    },
]


def get_cve(cve_id: str):
    """Return the CVE entry for *cve_id*, or None."""
    for entry in CVE_DB:
        if entry["id"] == cve_id:
            return entry
    return None


def _version_tuple(version: str):
    """Convert a version string to a comparable tuple of ints.

    Non-numeric parts are dropped, so "1.10.3a" -> (1, 10, 3).
    """
    parts = []
    for chunk in str(version).split("."):
        digits = "".join(c for c in chunk if c.isdigit())
        if digits:
            parts.append(int(digits))
        else:
            parts.append(0)
    return tuple(parts)


def version_matches_affected(version: str, affected: str) -> bool:
    """Evaluate a constraint like '<0.14.1' against a version string."""
    for op in ("<=", ">=", "==", "<", ">"):
        if affected.startswith(op):
            bound = affected[len(op):].strip()
            v, b = _version_tuple(version), _version_tuple(bound)
            # Pad shorter tuple so (1, 2) compares sanely with (1, 2, 1).
            width = max(len(v), len(b))
            v += (0,) * (width - len(v))
            b += (0,) * (width - len(b))
            if op == "<":
                return v < b
            if op == "<=":
                return v <= b
            if op == ">":
                return v > b
            if op == ">=":
                return v >= b
            return v == b
    raise ValueError("unsupported constraint: %r" % affected)


def affected_cves(product: str, version: str):
    """Return CVE entries whose product list contains *product* and whose
    version range covers *version*. Matching is case-insensitive."""
    hits = []
    if not product or not version:
        return hits
    name = product.strip().lower()
    for entry in CVE_DB:
        if entry["affected"] is None:
            continue
        aliases = [p.lower() for p in entry.get("products", [])]
        if name not in aliases:
            continue
        try:
            if version_matches_affected(version, entry["affected"]):
                hits.append(entry)
        except (ValueError, TypeError):
            continue
    return hits
