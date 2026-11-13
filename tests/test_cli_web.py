import contextlib
import io
import json
import os
import tempfile
import threading
import unittest
import urllib.request
from pathlib import Path
from unittest.mock import patch

from rift.cli import main
from rift.range import LabServer
from rift.web import create_server


class CliWebTests(unittest.TestCase):
    def setUp(self):
        self.lab = LabServer(port=0).start()
        self.tmp = tempfile.TemporaryDirectory()
        self.env = patch.dict(os.environ, {"RIFT_HOME": self.tmp.name})
        self.env.start()

    def tearDown(self):
        self.env.stop()
        self.lab.stop()
        self.tmp.cleanup()

    def run_cli(self, args):
        output = io.StringIO()
        errors = io.StringIO()
        with contextlib.redirect_stdout(output), contextlib.redirect_stderr(errors):
            code = main(args)
        return code, output.getvalue(), errors.getvalue()

    def test_cli_workflow_and_dashboard(self):
        code, output, errors = self.run_cli(
            [
                "init",
                "--name", "lab",
                "--target", self.lab.url,
                "--ports", str(self.lab.port),
                "--actions", "http,crawl,content,probe",
                "--authorized",
                "--attestation", "Prueba local autorizada",
            ]
        )
        self.assertEqual(code, 0, errors)
        self.assertIn("Workspace creado", output)
        self.assertEqual(self.run_cli(["list"])[0], 0)
        self.assertEqual(self.run_cli(["show", "--workspace", "lab"])[0], 0)
        self.assertEqual(self.run_cli(["scan", "--workspace", "lab"])[0], 0)
        self.assertEqual(self.run_cli(["report", "--workspace", "lab"])[0], 0)
        self.assertEqual(self.run_cli(["verify", "--workspace", "lab"])[0], 0)
        workspace = Path(self.tmp.name) / "workspaces" / "lab"
        self.assertTrue((workspace / "report.html").exists())

        httpd = create_server(workspace, port=0)
        thread = threading.Thread(target=httpd.serve_forever, daemon=True)
        thread.start()
        try:
            base = f"http://127.0.0.1:{httpd.server_address[1]}"
            with urllib.request.urlopen(base + "/", timeout=5) as response:
                body = response.read().decode("utf-8")
                self.assertIn("RIFT Dashboard", body)
                self.assertEqual(response.status, 200)
            with urllib.request.urlopen(base + "/api/results", timeout=5) as response:
                results = json.loads(response.read().decode("utf-8"))
                self.assertEqual(results["tool"], "RIFT")
            with urllib.request.urlopen(base + "/report", timeout=5) as response:
                self.assertIn("Informe RIFT", response.read().decode("utf-8"))
        finally:
            httpd.shutdown()
            httpd.server_close()
            thread.join(timeout=2)

    def test_init_requires_authorization(self):
        code, _, errors = self.run_cli(
            ["init", "--name", "lab", "--target", self.lab.url]
        )
        self.assertEqual(code, 2)
        self.assertIn("autorizacion", errors.lower())


if __name__ == "__main__":
    unittest.main()
