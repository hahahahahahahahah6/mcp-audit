"""End-to-end tests for the mcp-audit CLI."""

import io
import json
import os
import tempfile
import unittest
from contextlib import redirect_stdout

from mcp_audit.cli import main, EXIT_OK, EXIT_FINDINGS, EXIT_ERROR


VULN_CONFIG = {
    "mcpServers": {
        "bad-shell": {"command": "bash", "args": ["-c", "node server.js"]},
        "bad-bind": {"url": "http://0.0.0.0:6277/sse"},
        "bad-cve": {"command": "npx",
                    "args": ["-y", "@modelcontextprotocol/inspector@0.13.0"]},
        "good": {"command": "node", "args": ["server.js"]},
    }
}

SAFE_CONFIG = {
    "mcpServers": {
        "good": {"command": "node", "args": ["server.js"]},
        "local": {"url": "http://127.0.0.1:8000/sse"},
    }
}


def write_config(data):
    fh = tempfile.NamedTemporaryFile("w", suffix=".json", delete=False)
    json.dump(data, fh)
    fh.close()
    return fh.name


class TestScan(unittest.TestCase):
    def test_scan_finds_issues_exit_1(self):
        path = write_config(VULN_CONFIG)
        try:
            buf = io.StringIO()
            with redirect_stdout(buf):
                rc = main(["scan", "--config", path])
        finally:
            os.unlink(path)
        self.assertEqual(rc, EXIT_FINDINGS)
        out = buf.getvalue()
        self.assertIn("STDIO-SHELL", out)
        self.assertIn("BIND-ADDR", out)
        self.assertIn("KNOWN-CVE", out)
        self.assertIn("CVE-2025-49596", out)

    def test_scan_clean_exit_0(self):
        path = write_config(SAFE_CONFIG)
        try:
            buf = io.StringIO()
            with redirect_stdout(buf):
                rc = main(["scan", "--config", path])
        finally:
            os.unlink(path)
        self.assertEqual(rc, EXIT_OK)
        self.assertIn("no findings", buf.getvalue())

    def test_scan_json_format(self):
        path = write_config(VULN_CONFIG)
        try:
            buf = io.StringIO()
            with redirect_stdout(buf):
                rc = main(["scan", "--config", path, "--format", "json"])
            doc = json.loads(buf.getvalue())
        finally:
            os.unlink(path)
        self.assertEqual(rc, EXIT_FINDINGS)
        self.assertIn("findings", doc)
        self.assertIn("summary", doc)
        rule_ids = {f["rule_id"] for f in doc["findings"]}
        self.assertIn("STDIO-SHELL", rule_ids)
        self.assertEqual(doc["summary"]["servers"], 4)

    def test_scan_missing_config_exit_2(self):
        buf = io.StringIO()
        with redirect_stdout(buf):
            rc = main(["scan", "--config", "/nonexistent/mcp-audit-xyz.json"])
        self.assertEqual(rc, EXIT_ERROR)

    def test_scan_no_configs_exit_2(self):
        # discover_configs only returns existing default paths; with no
        # explicit --config and no defaults on disk it must exit 2.
        from mcp_audit import scanners
        old = scanners.DEFAULT_CONFIG_PATHS
        scanners.DEFAULT_CONFIG_PATHS = ["/nonexistent/mcp-audit-xyz.json"]
        try:
            buf = io.StringIO()
            with redirect_stdout(buf):
                rc = main(["scan"])
        finally:
            scanners.DEFAULT_CONFIG_PATHS = old
        self.assertEqual(rc, EXIT_ERROR)


class TestFix(unittest.TestCase):
    def test_fix_dry_run_prints_plan(self):
        path = write_config(VULN_CONFIG)
        try:
            buf = io.StringIO()
            with redirect_stdout(buf):
                rc = main(["fix", "--config", path])
            with open(path) as fh:
                untouched = json.load(fh)
        finally:
            os.unlink(path)
        self.assertEqual(rc, EXIT_OK)
        self.assertIn("127.0.0.1", buf.getvalue())
        self.assertIn("0.0.0.0", untouched["mcpServers"]["bad-bind"]["url"])

    def test_fix_apply_writes_and_backs_up(self):
        path = write_config(VULN_CONFIG)
        try:
            buf = io.StringIO()
            with redirect_stdout(buf):
                rc = main(["fix", "--config", path, "--apply"])
            with open(path) as fh:
                data = json.load(fh)
            out = buf.getvalue()
        finally:
            backup = None
            for candidate in os.listdir(os.path.dirname(path)):
                if candidate.startswith(os.path.basename(path) + ".bak-"):
                    backup = os.path.join(os.path.dirname(path), candidate)
            if os.path.isfile(path):
                os.unlink(path)
            if backup and os.path.isfile(backup):
                os.unlink(backup)
        self.assertEqual(rc, EXIT_OK)
        self.assertIn("127.0.0.1", data["mcpServers"]["bad-bind"]["url"])
        self.assertIn("backup", out)

    def test_fix_apply_nothing_fixable(self):
        path = write_config(SAFE_CONFIG)
        try:
            buf = io.StringIO()
            with redirect_stdout(buf):
                rc = main(["fix", "--config", path, "--apply"])
        finally:
            os.unlink(path)
        self.assertEqual(rc, EXIT_OK)
        self.assertIn("nothing fixable", buf.getvalue())


if __name__ == "__main__":
    unittest.main()
