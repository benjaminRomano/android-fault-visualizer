import json
import tempfile
import unittest
from pathlib import Path

from report import build_report, report_run


def capture(path, serial):
    path.mkdir()
    metadata = {
        "schema_version": 5,
        "capture_status": "collected",
        "package": "example.app",
        "page_size": 4096,
        "serial": serial,
        "results": {"all_faults": 0},
    }
    (path / "capture_metadata.json").write_text(json.dumps(metadata))
    (path / "all_faults.csv").write_text(
        "sequence,event_type,elapsed_ms,address,file_name,offset,tid\n"
    )
    return metadata


class ReportContractTests(unittest.TestCase):
    def test_comparison_requires_matching_provenance_unless_explicitly_overridden(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            capture(root / "a", "one")
            capture(root / "b", "two")
            with self.assertRaisesRegex(ValueError, "serial"):
                build_report(root / "a", root / "report.html", root / "b")
            build_report(
                root / "a", root / "report.html", root / "b", allow_incomparable=True
            )
            self.assertIn(
                "Comparison settings differ: serial", (root / "report.html").read_text()
            )

    def test_missing_processed_counts_or_csv_are_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "capture"
            metadata = capture(path, "one")
            metadata.pop("results")
            (path / "capture_metadata.json").write_text(json.dumps(metadata))
            with self.assertRaisesRegex(ValueError, "count"):
                report_run(path)
            (path / "all_faults.csv").unlink()
            with self.assertRaisesRegex(ValueError, "missing"):
                report_run(path)
