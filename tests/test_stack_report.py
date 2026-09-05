import tempfile
import unittest
from pathlib import Path

from stack_report import (
    build_report,
    parse_recording_summary,
    parse_simpleperf_samples,
)


SAMPLE_TEXT = """app\t12/12 [001] 3.100000: 2 minor-faults:
\t      1000 leaf.one (/data/app/base.vdex)
\t      2000 common.caller (/system/framework/boot.oat)

app\t12/13 [002] 3.200000: 3 major-faults:
\t      3000 art::Invoke(void (*)(int)) (.llvm.12345) (/system/lib64/libx.so)
\t      2000 common.caller (/system/framework/boot.oat)
"""


class StackReportTests(unittest.TestCase):
    def test_parser_preserves_leaf_first_frames_and_fault_type(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "samples.txt"
            path.write_text(SAMPLE_TEXT)

            samples = parse_simpleperf_samples(path)

            self.assertEqual(len(samples), 2)
            self.assertEqual(samples[0].frames[0].symbol, "leaf.one")
            self.assertEqual(samples[1].event_type, "major")
            self.assertEqual(samples[1].tid, 13)
            self.assertEqual(samples[1].period, 3)
            self.assertEqual(
                samples[1].frames[0].symbol,
                "art::Invoke(void (*)(int)) (.llvm.12345)",
            )
            self.assertEqual(samples[1].frames[0].dso, "/system/lib64/libx.so")

    def test_recording_summary_parses_counts(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "record.log"
            path.write_text("Samples recorded: 4,561. Samples lost: 0.\n")

            self.assertEqual(parse_recording_summary(path), (4561, 0))

    def test_report_is_self_contained_and_has_fault_type_control(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "samples.txt"
            output = root / "stack-report.html"
            source.write_text(
                SAMPLE_TEXT.replace(": 2 ", ": 1 ").replace(": 3 ", ": 1 ")
            )

            build_report(
                parse_simpleperf_samples(source),
                source,
                output,
                samples_recorded=2,
                samples_lost=0,
            )
            document = output.read_text()

            self.assertIn("Android page-fault call stacks", document)
            self.assertIn('id="kind"', document)
            self.assertTrue(
                "Stack chart" in document, "Missing chronological stack tab"
            )
            self.assertTrue("Flame graph" in document, "Missing aggregate stack tab")
            self.assertIn("Cache state is unverified", document)
            self.assertIn("2 recorded, 0 lost", document)
            self.assertIn("app (12)", document)
            self.assertIn("app (13)", document)
            self.assertNotIn("<script src=", document)

    def test_report_rejects_weighted_samples_in_fault_order(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "samples.txt"
            source.write_text(SAMPLE_TEXT)
            with self.assertRaisesRegex(ValueError, "period 1"):
                build_report(
                    parse_simpleperf_samples(source), source, root / "report.html"
                )


if __name__ == "__main__":
    unittest.main()
