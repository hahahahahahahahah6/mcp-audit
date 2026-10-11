"""Tests for the mcp-audit scanners."""

import json
import os
import tempfile
import threading
import unittest
from http.server import BaseHTTPRequestHandler, HTTPServer

from mcp_audit.scanners import (
    _apply_auth_fix,
    _apply_bind_fix,
    _probe_endpoint,
    agent_guard_link,
    apply_fixes,
    load_config,
    plan_fixes,
    run_all_scans,
    scan_bind_address,
    scan_dangerous_stdio,
    scan_known_cves,
    scan_unauthenticated_endpoints,
    _servers_from_entry,
)


def make_server(name="srv", **kwargs):
    return _servers_from_entry(name, kwargs)


class TestDangerousStdio(unittest.TestCase):
    def test_bash_c_flagged(self):
        srv = make_server(command="bash", args=["-c", "node server.js"])
        findings = scan_dangerous_stdio([srv])
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].rule_id, "STDIO-SHELL")
        self.assertEqual(findings[0].cve_id, "CVE-2026-105697")
        self.assertEqual(findings[0].severity, "high")

    def test_sh_c_flagged(self):
        srv = make_server(command="sh", args=["-c", "exec node server.js"])
        self.assertEqual(len(scan_dangerous_stdio([srv])), 1)

    def test_cmd_c_flagged(self):
        srv = make_server(command="cmd.exe", args=["/c", "server.bat"])
        self.assertEqual(len(scan_dangerous_stdio([srv])), 1)

    def test_safe_stdio_not_flagged(self):
        srv = make_server(command="node", args=["server.js", "--port", "3000"])
        self.assertEqual(scan_dangerous_stdio([srv]), [])

    def test_uvx_invocation_not_flagged(self):
        srv = make_server(command="uvx", args=["mcp-server-fetch"])
        self.assertEqual(scan_dangerous_stdio([srv]), [])

    def test_non_stdio_skipped(self):
        srv = make_server(url="http://127.0.0.1:8000/sse")
        self.assertEqual(scan_dangerous_stdio([srv]), [])


class TestBindAddress(unittest.TestCase):
    def test_url_host_flagged(self):
        srv = make_server(url="http://0.0.0.0:6277/sse")
        findings = scan_bind_address([srv])
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].rule_id, "BIND-ADDR")

    def test_loopback_not_flagged(self):
        srv = make_server(url="http://127.0.0.1:6277/sse")
        self.assertEqual(scan_bind_address([srv]), [])

    def test_flag_style_args_flagged(self):
        srv = make_server(command="python", args=["-m", "srv", "--host", "0.0.0.0"])
        self.assertEqual(len(scan_bind_address([srv])), 1)

    def test_env_value_flagged(self):
        srv = make_server(command="node", args=["srv.js"],
                          env={"HOST": "0.0.0.0"})
        self.assertEqual(len(scan_bind_address([srv])), 1)


class TestUnauthEndpoints(unittest.TestCase):
    def test_static_no_auth_flagged(self):
        srv = make_server(url="http://example.com:8000/sse")
        findings = scan_unauthenticated_endpoints([srv])
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].rule_id, "UNAUTH-ENDPOINT")

    def test_static_with_auth_header_not_flagged(self):
        srv = make_server(url="http://example.com:8000/sse",
                          headers={"Authorization": "Bearer x"})
        self.assertEqual(scan_unauthenticated_endpoints([srv]), [])

    def test_static_loopback_not_flagged_without_probe(self):
        srv = make_server(url="http://127.0.0.1:8000/sse")
        self.assertEqual(scan_unauthenticated_endpoints([srv]), [])


class _OpenHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b"ok")

    def log_message(self, *args):
        pass


class _AuthHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(401)
        self.end_headers()

    def log_message(self, *args):
        pass


class TestProbe(unittest.TestCase):
    def _serve(self, handler):
        server = HTTPServer(("127.0.0.1", 0), handler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        return server, "http://127.0.0.1:%d/sse" % server.server_address[1]

    def test_open_endpoint_reachable_without_auth(self):
        server, url = self._serve(_OpenHandler)
        try:
            reachable, status, detail = _probe_endpoint(url)
        finally:
            server.shutdown()
        self.assertTrue(reachable)
        self.assertEqual(status, 200)

    def test_auth_endpoint_not_reachable_without_auth(self):
        server, url = self._serve(_AuthHandler)
        try:
            reachable, status, _ = _probe_endpoint(url)
        finally:
            server.shutdown()
        self.assertFalse(reachable)
        self.assertEqual(status, 401)

    def test_probe_scan_flags_open_local_server(self):
        server, url = self._serve(_OpenHandler)
        try:
            srv = make_server(url=url)
            findings = scan_unauthenticated_endpoints([srv], probe=True)
        finally:
            server.shutdown()
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].severity, "critical")

    def test_dead_endpoint_not_flagged(self):
        srv = make_server(url="http://127.0.0.1:1/sse")
        findings = scan_unauthenticated_endpoints([srv], probe=True, timeout=0.5)
        self.assertEqual(findings, [])


class TestKnownCves(unittest.TestCase):
    def test_vulnerable_inspector_flagged(self):
        srv = make_server(command="npx",
                          args=["-y", "@modelcontextprotocol/inspector@0.13.0"])
        findings = scan_known_cves([srv])
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].rule_id, "KNOWN-CVE")
        self.assertEqual(findings[0].cve_id, "CVE-2025-49596")

    def test_patched_inspector_not_flagged(self):
        srv = make_server(command="npx",
                          args=["-y", "@modelcontextprotocol/inspector@0.14.1"])
        self.assertEqual(scan_known_cves([srv]), [])

    def test_no_package_info_not_flagged(self):
        srv = make_server(command="node", args=["my-server.js"])
        self.assertEqual(scan_known_cves([srv]), [])


class TestConfigLoading(unittest.TestCase):
    def test_load_config(self):
        with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as fh:
            json.dump({"mcpServers": {
                "demo": {"command": "node", "args": ["srv.js"]},
            }}, fh)
            path = fh.name
        try:
            servers, err = load_config(path)
        finally:
            os.unlink(path)
        self.assertEqual(err, "")
        self.assertEqual(len(servers), 1)
        self.assertEqual(servers[0].name, "demo")
        self.assertEqual(servers[0].transport, "stdio")

    def test_load_config_nested(self):
        with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as fh:
            json.dump({"projects": {"/x": {"mcpServers": {
                "nested": {"url": "http://127.0.0.1:8000/sse"},
            }}}}, fh)
            path = fh.name
        try:
            servers, _ = load_config(path)
        finally:
            os.unlink(path)
        self.assertEqual(len(servers), 1)
        self.assertEqual(servers[0].name, "nested")

    def test_load_config_bad_json(self):
        with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as fh:
            fh.write("{not json")
            path = fh.name
        try:
            servers, err = load_config(path)
        finally:
            os.unlink(path)
        self.assertEqual(servers, [])
        self.assertTrue(err)


class TestFixes(unittest.TestCase):
    def _write_config(self, servers):
        fh = tempfile.NamedTemporaryFile("w", suffix=".json", delete=False)
        json.dump({"mcpServers": servers}, fh)
        fh.close()
        return fh.name

    def test_bind_fix_rewrites_url(self):
        path = self._write_config(
            {"web": {"url": "http://0.0.0.0:6277/sse"}})
        try:
            servers, _ = load_config(path)
            findings = run_all_scans(servers)
            backup, applied = apply_fixes(path, findings)
        finally:
            pass
        self.assertTrue(os.path.isfile(backup))
        self.assertGreaterEqual(applied, 1)
        with open(path) as fh:
            data = json.load(fh)
        self.assertIn("127.0.0.1", data["mcpServers"]["web"]["url"])
        self.assertNotIn("0.0.0.0", data["mcpServers"]["web"]["url"])
        with open(backup) as fh:
            bak = json.load(fh)
        self.assertIn("0.0.0.0", bak["mcpServers"]["web"]["url"])
        os.unlink(path)
        os.unlink(backup)

    def test_bind_fix_rewrites_args(self):
        path = self._write_config(
            {"local": {"command": "python",
                       "args": ["-m", "srv", "--host", "0.0.0.0"]}})
        try:
            servers, _ = load_config(path)
            findings = run_all_scans(servers)
            backup, applied = apply_fixes(path, findings)
            with open(path) as fh:
                data = json.load(fh)
        finally:
            for p in (path,):
                if os.path.isfile(p):
                    os.unlink(p)
        self.assertEqual(data["mcpServers"]["local"]["args"],
                         ["-m", "srv", "--host", "127.0.0.1"])
        if os.path.isfile(backup):
            os.unlink(backup)

    def test_auth_fix_adds_placeholder_header(self):
        entry = {"url": "http://example.com/sse"}
        self.assertTrue(_apply_auth_fix(entry))
        self.assertEqual(entry["headers"]["Authorization"],
                         "Bearer ${MCP_TOKEN}")
        self.assertFalse(_apply_auth_fix(entry))

    def test_plan_only_lists_fixable(self):
        path = self._write_config({
            "web": {"url": "http://0.0.0.0:6277/sse"},
            "shell": {"command": "bash", "args": ["-c", "node s.js"]},
        })
        try:
            servers, _ = load_config(path)
            findings = run_all_scans(servers)
            plan, _ = plan_fixes(path, findings)
        finally:
            os.unlink(path)
        rules = {p["rule_id"] for p in plan}
        self.assertIn("BIND-ADDR", rules)
        self.assertNotIn("STDIO-SHELL", rules)  # not auto-fixable


class TestAgentGuardLink(unittest.TestCase):
    def test_no_config_prints_manual_instruction(self):
        import mcp_audit.scanners as sc
        old = sc.AGENT_GUARD_CONFIG_PATHS
        sc.AGENT_GUARD_CONFIG_PATHS = ["/nonexistent/path.json"]
        try:
            # probe=False on loopback gives no finding; craft one directly.
            from mcp_audit.scanners import Finding
            linked, msg = agent_guard_link(
                [Finding("UNAUTH-ENDPOINT", "CVE-2025-49596", "critical",
                         "bad-srv", "ev", "fix")])
        finally:
            sc.AGENT_GUARD_CONFIG_PATHS = old
        self.assertFalse(linked)
        self.assertIn("blocked_servers", msg)


if __name__ == "__main__":
    unittest.main()
