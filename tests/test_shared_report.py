import json
import re
import tempfile
import unittest
from pathlib import Path

from fault_report import write_report


class SharedTemplateTests(unittest.TestCase):
    def test_payload_is_escaped_once_without_expanding_trace_placeholders(self):
        data = {
            "title": "__DATA__ </script>",
            "runs": [],
            "symbol": "__SCRIPT__ </script><script>bad()</script>",
        }
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "report.html"
            write_report(data, path, "/* local plotly */")
            text = path.read_text()
        payload = re.search(r"const REPORT\s*=\s*(.*?);\s*</script>", text, re.S)[1]
        self.assertEqual(data, json.loads(payload))
        self.assertNotIn("</script>", payload)
        self.assertIn("<title>__DATA__ &lt;/script&gt;</title>", text)
        self.assertNotIn("<script src=", text)

    def test_nonfinite_values_are_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaises(ValueError):
                write_report(
                    {"title": "Faults", "time": float("nan")},
                    Path(directory) / "report.html",
                    "",
                )
