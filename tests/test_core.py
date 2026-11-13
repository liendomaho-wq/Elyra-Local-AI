import tempfile
import unittest
from pathlib import Path

from rift.audit import AuditLog
from rift.models import Finding, sort_findings, summarize
from rift.policy import PolicyEngine
from rift.scope import (
    format_ports,
    load_scope,
    new_scope,
    parse_ports,
    save_scope,
)


class ScopeTests(unittest.TestCase):
    def test_ports_roundtrip(self):
        ports = parse_ports("80,443,8000-8002")
        self.assertEqual(ports, {80, 443, 8000, 8001, 8002})
        self.assertEqual(format_ports(ports), "80,443,8000-8002")

    def test_scope_persistence_and_target(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp)
            scope = new_scope(
                "lab",
                ["127.0.0.1"],
                ports="8000",
                actions=["http", "crawl", "probe"],
                authorized=True,
                attestation="autorizado",
                target="http://127.0.0.1:8000",
            )
            save_scope(path, scope)
            loaded = load_scope(path)
            self.assertEqual(loaded.target, "http://127.0.0.1:8000")
            self.assertTrue(loaded.authorized)
            self.assertEqual(loaded.actions, ["http", "crawl", "probe"])

    def test_authorization_gate(self):
        scope = new_scope(
            "lab", ["127.0.0.1"], ports="8000", actions=["http"], authorized=False
        )
        allowed, reason = scope.check_target("http://127.0.0.1:8000")
        self.assertFalse(allowed)
        self.assertIn("autorizacion", reason)
        scope.authorized = True
        self.assertTrue(scope.check_target("http://127.0.0.1:8000")[0])

    def test_public_target_requires_opt_in(self):
        scope = new_scope(
            "public",
            ["example.com"],
            ports="80",
            actions=["http"],
            authorized=True,
            attestation="autorizado",
        )
        self.assertFalse(scope.check_target("http://example.com:80")[0])
        scope.allow_public = True
        self.assertTrue(scope.check_target("http://example.com:80")[0])

    def test_ip_scope_membership(self):
        scope = new_scope(
            "cidr",
            ["127.0.0.0/30"],
            ports="80",
            actions=["http"],
            authorized=True,
            attestation="autorizado",
        )
        self.assertTrue(scope.check_target("http://127.0.0.1:80")[0])


class AuditPolicyTests(unittest.TestCase):
    def test_audit_chain_and_tamper_detection(self):
        with tempfile.TemporaryDirectory() as tmp:
            log = AuditLog(Path(tmp) / "audit.jsonl")
            log.record("scan", "http://127.0.0.1", "allow", "ok")
            log.record("probe", "http://127.0.0.1", "deny", "fuera de alcance")
            self.assertTrue(log.verify()["ok"])
            lines = log.path.read_text(encoding="utf-8").splitlines()
            lines[0] = lines[0].replace('"allow"', '"deny"')
            log.path.write_text("\n".join(lines) + "\n", encoding="utf-8")
            self.assertFalse(log.verify()["ok"])

    def test_policy_requires_action_and_port(self):
        with tempfile.TemporaryDirectory() as tmp:
            scope = new_scope(
                "lab",
                ["127.0.0.1"],
                ports="8000",
                actions=["http"],
                authorized=True,
                attestation="autorizado",
            )
            audit = AuditLog(Path(tmp) / "audit.jsonl")
            policy = PolicyEngine(scope, audit)
            self.assertTrue(policy.check("http", "http://127.0.0.1:8000").allowed)
            self.assertFalse(policy.check("probe", "http://127.0.0.1:8000").allowed)
            self.assertFalse(policy.check("http", "http://127.0.0.1:8001").allowed)
            self.assertTrue(audit.verify()["ok"])

    def test_finding_sort_and_summary(self):
        items = [
            Finding("A", "low", "low", 3.1, "CWE-1", "A", "T1", "t", "d"),
            Finding("B", "high", "high", 8.0, "CWE-2", "A", "T2", "t", "d"),
        ]
        ordered = sort_findings(items)
        self.assertEqual(ordered[0].severity, "high")
        summary = summarize(ordered)
        self.assertEqual(summary["total"], 2)
        self.assertEqual(summary["counts"]["high"], 1)
        self.assertEqual(summary["risk"], "alta")


if __name__ == "__main__":
    unittest.main()
