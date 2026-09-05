import json
import tempfile
import unittest
from unittest.mock import patch
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
    def test_android_preserves_kernel_frames_and_marks_file_backing(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "capture"
            metadata = capture(path, "one")
            metadata["results"]["all_faults"] = 2
            (path / "capture_metadata.json").write_text(json.dumps(metadata))
            (path / "all_faults.csv").write_text(
                "sequence,event_type,elapsed_ms,address,file_name,offset,tid,mapping_kind\n"
                "0,minor,1,4096,[anon:heap],,7,anonymous\n"
                "1,major,2,8192,/data/app/example.app-x/base.apk,0,7,file\n"
            )
            (path / "resolved_fault_callchains.csv").write_text(
                "sequence,frame_index,frame_kind,label,file_name\n"
                "1,0,kernel,[kernel]+0x123,\n"
                "1,1,user,caller,/system/lib64/libc.so\n"
            )
            result = report_run(path)
            self.assertTrue(result["fileBackedOnly"])
            self.assertEqual([False, True], [e["fileBacked"] for e in result["events"]])
            self.assertEqual(
                ["kernel", "user"], [f["kind"] for f in result["events"][1]["stack"]]
            )
            with patch(
                "android_fault_visualizer.simpleperf.exact_dwarf_matches",
                return_value={
                    "matches": {
                        1: {
                            "stack": [
                                {
                                    "label": "managed caller",
                                    "kind": "user",
                                    "file": "app",
                                }
                            ],
                            "provenance": {"match": "exact identity"},
                        }
                    },
                    "coverage": {},
                    "warnings": [],
                },
            ):
                enriched = report_run(path)
            self.assertEqual(
                ["[kernel]+0x123", "managed caller"],
                [f["label"] for f in enriched["events"][1]["stack"]],
            )
            self.assertEqual(
                result["events"][1]["address"], enriched["events"][1]["address"]
            )
            self.assertIn(
                "exact identity", enriched["events"][1]["detail"]["Stack evidence"]
            )

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
