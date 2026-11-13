import json
import tempfile
import unittest
from pathlib import Path
from urllib.parse import urlparse

from rift.audit import AuditLog
from rift.policy import PolicyDenied
from rift.range import LabServer
from rift.recon import http
from rift.recon.engine import Runner
from rift.report import build as build_report
from rift.report import verify as verify_report
from rift.scope import new_scope, save_scope


class RangeScanTests(unittest.TestCase):
    def setUp(self):
        self.lab = LabServer(port=0).start()
        self.tmp = tempfile.TemporaryDirectory()
        self.workspace = Path(self.tmp.name)
        self.scope = new_scope(
            "lab",
            ["127.0.0.1"],
            ports=str(self.lab.port),
            actions=["http", "crawl", "content", "probe"],
            authorized=True,
            attestation="Prueba local autorizada",
            rate_limit=1000,
            probe_budget=24,
            target=self.lab.url,
        )
        save_scope(self.workspace, self.scope)

    def tearDown(self):
        self.lab.stop()
        self.tmp.cleanup()

    def scan(self, budget=24, actions=None):
        self.scope.probe_budget = budget
        if actions is not None:
            self.scope.actions = actions
        save_scope(self.workspace, self.scope)
        return Runner(self.workspace, self.scope).scan(self.lab.url)

    def test_end_to_end_findings_and_artifacts(self):
        data = self.scan()
        cwes = {item["cwe"] for item in data["findings"]}
        self.assertIn("CWE-79", cwes)
        self.assertIn("CWE-89", cwes)
        self.assertIn("CWE-601", cwes)
        self.assertIn("CWE-942", cwes)
        self.assertIn("CWE-538", cwes)
        self.assertEqual(data["summary"]["risk"], "critica")
        self.assertLessEqual(data["probes_used"], 24)
        for name in ("recon.json", "surface.json", "findings.json", "plan.json", "results.json", "audit.jsonl"):
            self.assertTrue((self.workspace / name).exists(), name)
        self.assertTrue(AuditLog(self.workspace / "audit.jsonl").verify()["ok"])
        self.assertTrue(any("GET /search" in item for item in self.lab.requests))

    def test_report_and_tamper_detection(self):
        self.scan()
        result = build_report(self.workspace)
        self.assertEqual(len(result["files"]), 3)
        verified = verify_report(self.workspace)
        self.assertTrue(verified["ok"], verified)
        report = self.workspace / "report.md"
        report.write_text(report.read_text(encoding="utf-8") + "\nmanipulado\n", encoding="utf-8")
        tampered = verify_report(self.workspace)
        self.assertFalse(tampered["ok"])
        self.assertTrue(any("report.md" in item for item in tampered["errors"]))

    def test_content_is_opt_in(self):
        self.scan(actions=["http", "crawl", "probe"])
        recon = json.loads((self.workspace / "recon.json").read_text(encoding="utf-8"))
        findings = json.loads((self.workspace / "findings.json").read_text(encoding="utf-8"))
        self.assertNotIn("content", recon)
        self.assertFalse(any("variables de entorno" in item["title"] for item in findings))
        self.assertFalse(any("/.env" in item for item in self.lab.requests))

    def test_probe_budget_is_enforced(self):
        data = self.scan(budget=3)
        self.assertLessEqual(data["probes_used"], 3)
        self.assertLessEqual(data["probes_used"], data["probe_budget"])

    def test_unauthorized_scan_is_blocked(self):
        self.scope.authorized = False
        with self.assertRaises(PolicyDenied):
            Runner(self.workspace, self.scope).scan(self.lab.url)

    def test_external_redirect_is_not_followed(self):
        result = http.fetch(
            self.lab.url + "/redirect?next=http://example.com/",
            allow_redirects=True,
            validator=lambda url: urlparse(url).hostname in ("127.0.0.1", "localhost"),
        )
        self.assertIsNotNone(result["error"])
        self.assertIn("redireccion bloqueada", result["error"])
        self.assertTrue(any("GET /redirect" in item for item in self.lab.requests))


if __name__ == "__main__":
    unittest.main()
