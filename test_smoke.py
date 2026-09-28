"""CLI smoke test with mock plugin output; does not analyze a real image."""

import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


SCRIPT = Path(__file__).resolve().parents[1] / "MemTriage.py"


class SmokeTest(unittest.TestCase):
    def test_cli_and_redaction(self):
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            image = base / "dummy.raw"
            image.write_bytes(b"")
            fake_vol = base / "fake_vol.py"
            fake_vol.write_text(
                "import json, sys\n"
                "p = sys.argv[-1]\n"
                "data = {\n"
                " 'windows.pslist': [{'PID': 20, 'PPID': 4, 'ImageFileName': 'powershell.exe', 'CreateTime': '2026-01-01T00:00:00', 'ExitTime': None}],\n"
                " 'windows.psscan': [{'PID': 20, 'PPID': 4, 'ImageFileName': 'powershell.exe', 'CreateTime': '2026-01-01T00:00:00', 'ExitTime': None}],\n"
                " 'windows.cmdline': [{'PID': 20, 'Args': 'powershell.exe -enc SECRET'}],\n"
                " 'windows.malfind': [], 'windows.ldrmodules': [],\n"
                " 'windows.netscan': [], 'windows.dlllist': []}\n"
                "print(json.dumps(data[p]))\n",
                encoding="utf-8",
            )
            report = base / "report.txt"
            findings = base / "findings.json"
            result = subprocess.run(
                [sys.executable, str(SCRIPT), str(image), "--vol", str(fake_vol),
                 "--redact-cmdline", "--report", str(report), "--json", str(findings)],
                text=True, capture_output=True, check=True,
            )
            data = json.loads(findings.read_text(encoding="utf-8"))
            self.assertEqual(len(data["plugin_coverage"]), 7)
            self.assertFalse(data["incomplete"])
            self.assertEqual(data["findings"][0]["cmdline"], "[REDACTED]")
            self.assertEqual(data["findings"][0]["indicators"][0]["evidence"]["plugin"],
                             "windows.cmdline")
            self.assertNotIn("SECRET", result.stdout)
            self.assertNotIn("SECRET", report.read_text(encoding="utf-8"))


if __name__ == "__main__":
    unittest.main()
