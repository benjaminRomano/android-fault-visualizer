import tempfile
import unittest
from pathlib import Path

from stack_report import (
    build_report,
    hotspot_rows,
    parse_recording_summary,
    parse_simpleperf_samples,
    stack_tree,
    temporal_stack_figure,
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

    def test_stack_tree_counts_common_callers(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "samples.txt"
            path.write_text(SAMPLE_TEXT)
            samples = parse_simpleperf_samples(path)

            tree = stack_tree(samples, "All faults")

            common_index = tree["labels"].index("common.caller")
            self.assertEqual(tree["values"][0], 5)
            self.assertEqual(tree["values"][common_index], 5)

    def test_temporal_chart_preserves_time_order_and_frame_depth(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "samples.txt"
            path.write_text(SAMPLE_TEXT)
            samples = parse_simpleperf_samples(path)

            figure, frames, metadata = temporal_stack_figure(samples, max_frames=4)

            self.assertEqual(figure.data[0].x[0], 0.0)
            self.assertAlmostEqual(figure.data[0].x[1], 100.0)
            self.assertEqual(metadata[0][1]["tid"], 13)
            self.assertEqual(metadata[0][1]["period"], 3)
            self.assertEqual(len(figure.data[0].z), 4)
            self.assertTrue(
                any(
                    frame["symbol"] == "art::Invoke(void (*)(int)) (.llvm.12345)"
                    for frame in frames
                )
            )

    def test_hotspots_use_perf_sample_period(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "samples.txt"
            path.write_text(SAMPLE_TEXT)
            rows = hotspot_rows(parse_simpleperf_samples(path))

            self.assertEqual(
                rows[0]["frame"], "art::Invoke(void (*)(int)) (.llvm.12345)"
            )
            self.assertEqual(rows[0]["total"], 3)

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
            source.write_text(SAMPLE_TEXT)

            build_report(
                parse_simpleperf_samples(source),
                source,
                output,
                samples_recorded=2,
                samples_lost=0,
            )
            document = output.read_text()

            self.assertIn("Android page-fault call stacks", document)
            self.assertIn('id="page-fault-stacks-scope"', document)
            self.assertIn('id="page-fault-stack-time-scope"', document)
            self.assertIn("Stack chart over time", document)
            self.assertIn("Cache state is unverified", document)
            self.assertIn("2 recorded, 0 lost", document)
            self.assertNotIn("<script src=", document)


if __name__ == "__main__":
    unittest.main()
