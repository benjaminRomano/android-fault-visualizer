"""Exact cross-stream identity checks; never infer an address from a stack."""

import csv
import hashlib
import json
import struct
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from android_fault_visualizer import simpleperf


BOOT_ID = "12345678-1234-1234-1234-123456789abc"


def perf_data(samples):
    records = b"".join(
        struct.pack(
            "<IHHQIIQQIIQQQ",
            9,
            2,
            72,
            sample.get("ip", 4096),
            sample.get("pid", 10),
            sample.get("tid", 11),
            sample.get("time", 150),
            42,
            sample.get("cpu", 2),
            0,
            1,
            1,
            sample.get("ip", 4096),
        )
        for sample in samples
    )
    header = struct.pack(
        "<13Q",
        int.from_bytes(b"PERFILE2", "little"),
        104,
        152,
        112,
        152,
        264,
        len(records),
        0,
        0,
        0,
        0,
        0,
        0,
    )
    attr = bytearray(152)
    struct.pack_into("<IIQQQQQ", attr, 0, 1, 136, 6, 1, 0x1E7, 0, (1 << 25) | (1 << 5))
    struct.pack_into("<i", attr, 92, 7)
    struct.pack_into("<QQ", attr, 136, 104, 8)
    return header + struct.pack("<Q", 42) + attr + records


def sample_text(samples):
    return "\n".join(
        f"""sample:
  event_type: major-faults:u
  time: {sample.get('time', 150)}
  event_count: 1
  thread_id: {sample.get('tid', 11)}
  vaddr_in_file: 1000
  file: /data/app/com.example.app-xyz/base.apk
  symbol: Example.start
"""
        for sample in samples
    )


class ExactDwarfTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.path = Path(self.directory.name)
        self.metadata = {
            "boot_id": BOOT_ID,
            "serial": "emulator-test",
            "pid": 10,
            "package": "com.example.app",
            "collector_start_ns": 1,
            "collector_clock": "boottime",
            "collector": "perf-software-page-fault-events",
            "capture_status": "collected",
            "simpleperf_status": "complete",
            "startup": {"ts": 100, "ts_end": 200},
        }
        self.write_capture()

    def write_capture(self, raw=None, native=None, symbols=None):
        raw = [{}] if raw is None else raw
        native = [{}] if native is None else native
        symbols = raw if symbols is None else symbols
        (self.path / "simpleperf.data").write_bytes(perf_data(raw))
        (self.path / "simpleperf-stacks.txt").write_text(sample_text(symbols))
        rows = [
            {
                "timestamp_ns": sample.get("time", 150),
                "event_type": sample.get("event_type", "major"),
                "pid": sample.get("pid", 10),
                "tid": sample.get("tid", 11),
                "ip": hex(sample.get("ip", 4096)),
                "address": "0xabcdef",
                "cpu": sample.get("cpu", 2),
            }
            for sample in native
        ]
        with (self.path / "fault_events.csv").open("w") as file:
            writer = csv.DictWriter(
                file,
                fieldnames=(
                    "timestamp_ns",
                    "event_type",
                    "pid",
                    "tid",
                    "ip",
                    "address",
                    "cpu",
                ),
            )
            writer.writeheader()
            writer.writerows(rows)
        with (self.path / "all_faults.csv").open("w") as file:
            writer = csv.DictWriter(
                file,
                fieldnames=("sequence", "ts", "event_type", "tid", "ip", "address"),
            )
            writer.writeheader()
            selected = [
                row
                for row in rows
                if row["pid"] == 10 and 100 <= row["timestamp_ns"] < 200
            ]
            for index, row in enumerate(selected):
                writer.writerow(
                    {
                        "sequence": index,
                        "ts": row["timestamp_ns"],
                        "event_type": row["event_type"],
                        "tid": row["tid"],
                        "ip": int(row["ip"], 0),
                        "address": int(row["address"], 0),
                    }
                )
        companion = {
            "target_pid": 10,
            "clock": "boottime",
            "integrity_passed": True,
            "return_code": 0,
            "samples_lost": 0,
            "samples_recorded": len(raw),
            "joiner": False,
            "gap_removal": False,
            "capture_binding": {
                "boot_id_start": BOOT_ID,
                "boot_id_end": BOOT_ID,
                "collector_start_ns": 1,
                "serial": "emulator-test",
                "artifacts_sha256": {},
            },
        }
        self.write_companion(companion)

    def write_companion(self, companion, refresh_hashes=True):
        if refresh_hashes and "capture_binding" in companion:
            companion["capture_binding"]["artifacts_sha256"] = {
                name: hashlib.sha256((self.path / name).read_bytes()).hexdigest()
                for name in ("simpleperf.data", "simpleperf-stacks.txt")
            }
        (self.path / "simpleperf-metadata.json").write_text(json.dumps(companion))

    def companion(self):
        return json.loads((self.path / "simpleperf-metadata.json").read_text())

    def match(self):
        return simpleperf.exact_dwarf_matches(self.path, self.metadata)

    def test_exact_match_preserves_address_provenance_and_user_frame_identity(self):
        result = self.match()
        self.assertEqual([], result["warnings"])
        self.assertEqual([0], list(result["matches"]))
        match = result["matches"][0]
        self.assertEqual("Example.start", match["stack"][0]["label"])
        self.assertEqual("user", match["stack"][0]["kind"])
        self.assertTrue(match["stack"][0]["app"])
        self.assertEqual("0x1000", match["provenance"]["ip"])
        self.assertNotIn("address", match)
        self.assertIn("Native fault event", match["provenance"]["address_source"])
        self.assertEqual(1, result["coverage"]["matched_startup_major_faults"])

    def test_near_timestamp_or_wrong_ip_cpu_tid_never_matches(self):
        for changed in ({"time": 151}, {"ip": 4097}, {"cpu": 3}, {"tid": 12}):
            with self.subTest(changed=changed):
                self.write_capture(raw=[changed])
                result = self.match()
                self.assertEqual({}, result["matches"])
                self.assertEqual(
                    1, result["coverage"]["unmatched_startup_major_faults"]
                )

    def test_minor_event_is_not_enriched(self):
        self.write_capture(native=[{"event_type": "minor"}])
        self.assertEqual({}, self.match()["matches"])

    def test_duplicate_keys_rejected_in_each_full_stream(self):
        for changed in ({"raw": [{}, {}]}, {"native": [{}, {}]}, {"symbols": [{}, {}]}):
            with self.subTest(changed=changed):
                self.write_capture(**changed)
                result = self.match()
                self.assertEqual({}, result["matches"])
                self.assertEqual(1, result["coverage"]["ambiguous_target_keys"])

    def test_outside_startup_duplicates_count_and_end_is_exclusive(self):
        samples = [{"time": 50}, {"time": 50}, {}, {"time": 200}]
        self.write_capture(raw=samples, native=samples)
        result = self.match()
        self.assertEqual(1, result["coverage"]["ambiguous_target_keys"])
        self.assertEqual(1, result["coverage"]["startup_major_faults"])
        self.assertEqual(2, result["coverage"]["matched_target_samples"])
        self.assertEqual([0], list(result["matches"]))

    def test_legacy_and_wrong_boot_or_capture_binding_rejected(self):
        for name, value in (
            ("boot_id_start", "other"),
            ("boot_id_end", "other"),
            ("collector_start_ns", 2),
            ("serial", "other"),
        ):
            with self.subTest(name=name):
                self.write_capture()
                companion = self.companion()
                companion["capture_binding"][name] = value
                self.write_companion(companion)
                result = self.match()
                self.assertEqual({}, result["matches"])
                self.assertIn("same-boot", result["warnings"][0])
        companion.pop("capture_binding")
        self.write_companion(companion)
        self.assertEqual({}, self.match()["matches"])

    def test_clock_integrity_and_export_modes_rejected(self):
        for name, value in (
            ("clock", "monotonic"),
            ("target_pid", 12),
            ("samples_lost", 1),
            ("integrity_passed", False),
            ("return_code", 1),
            ("joiner", True),
            ("gap_removal", True),
        ):
            with self.subTest(name=name):
                self.write_capture()
                companion = self.companion()
                companion[name] = value
                self.write_companion(companion)
                self.assertIn("integrity mismatch", self.match()["warnings"][0])
        self.write_capture()
        self.metadata["collector_clock"] = "monotonic"
        self.assertEqual({}, self.match()["matches"])

    def test_changed_raw_or_symbol_export_fails_hash_binding(self):
        for name in ("simpleperf.data", "simpleperf-stacks.txt"):
            with self.subTest(name=name):
                self.write_capture()
                (self.path / name).write_bytes((self.path / name).read_bytes() + b"\n")
                self.assertIn("hash mismatch", self.match()["warnings"][0])

    def test_processed_address_or_event_count_mismatch_rejected(self):
        processed = self.path / "all_faults.csv"
        processed.write_text(processed.read_text().replace(str(0xABCDEF), "7"))
        self.assertIn("identity differs", self.match()["warnings"][0])
        self.write_capture()
        companion = self.companion()
        companion["samples_recorded"] = 2
        self.write_companion(companion)
        self.assertIn("sample count", self.match()["warnings"][0])

    def test_malformed_or_unfamiliar_perf_layout_is_not_guessed(self):
        mutations = [
            (0, "<Q", 0),
            (8, "<Q", 105),
            (32, "<Q", 304),
            (112 + 8, "<Q", 5),
            (112 + 16, "<Q", 2),
            (112 + 24, "<Q", 0x1EF),
            (112 + 92, "<i", 1),
            (264 + 4, "<H", 1),
            (264 + 6, "<H", 65535),
            (264 + 32, "<Q", 43),
            (264 + 48, "<Q", 2),
            (264 + 56, "<Q", 100),
        ]
        for offset, fmt, value in mutations:
            with self.subTest(offset=offset, value=value):
                data = bytearray(perf_data([{}]))
                struct.pack_into(fmt, data, offset, value)
                with self.assertRaises(ValueError):
                    simpleperf.read_perf_sample_identities(data)
        for length in (0, 50, 103, 200, 335):
            with self.subTest(length=length), self.assertRaises(ValueError):
                simpleperf.read_perf_sample_identities(perf_data([{}])[:length])

    def test_finish_binds_actual_boot_and_exported_files(self):
        (self.path / "capture_metadata.json").write_text(json.dumps(self.metadata))
        process = mock.Mock(returncode=0, fault_capture_boot_id=BOOT_ID)
        adb = mock.Mock()
        adb.shell.side_effect = [
            subprocess.CompletedProcess([], 0, stdout=BOOT_ID + "\n"),
            subprocess.CompletedProcess([], 0, stdout=sample_text([{}])),
        ]
        with mock.patch.object(
            simpleperf,
            "stop_remote",
            return_value="Samples recorded: 1. Samples lost: 0.",
        ):
            simpleperf.finish(adb, process, 100, 10, self.path)
        binding = self.companion()["capture_binding"]
        self.assertEqual(BOOT_ID, binding["boot_id_start"])
        self.assertEqual(BOOT_ID, binding["boot_id_end"])
        self.assertEqual(1, binding["collector_start_ns"])
        self.assertEqual(2, len(binding["artifacts_sha256"]))

    def test_readiness_precedes_boot_binding_and_application_launch(self):
        adb = mock.Mock()
        adb.shell.side_effect = [
            subprocess.CompletedProcess([], 0, stdout=""),
            subprocess.CompletedProcess([], 0, stdout=BOOT_ID + "\n"),
        ]
        process = mock.Mock()
        process.poll.return_value = None
        with (
            mock.patch.object(simpleperf.subprocess, "Popen", return_value=process),
            mock.patch.object(simpleperf.selectors, "DefaultSelector") as selectors,
            mock.patch.object(
                simpleperf.os, "read", return_value=b"SIMPLEPERF_PID=123\nSTARTED\n"
            ),
        ):
            selectors.return_value.__enter__.return_value.select.return_value = [True]
            recorded_process, pid = simpleperf.start(adb)
        self.assertIs(process, recorded_process)
        self.assertEqual(123, pid)
        self.assertEqual(BOOT_ID, process.fault_capture_boot_id)
        self.assertEqual(
            ["cat", "/proc/sys/kernel/random/boot_id"], adb.shell.call_args.args[0]
        )

    def test_reboot_during_recording_does_not_create_binding(self):
        (self.path / "capture_metadata.json").write_text(json.dumps(self.metadata))
        process = mock.Mock(returncode=0, fault_capture_boot_id=BOOT_ID)
        adb = mock.Mock()
        adb.shell.side_effect = [
            subprocess.CompletedProcess(
                [], 0, stdout="abcdef12-1234-1234-1234-123456789abc\n"
            ),
            subprocess.CompletedProcess([], 0, stdout=sample_text([{}])),
        ]
        with mock.patch.object(
            simpleperf,
            "stop_remote",
            return_value="Samples recorded: 1. Samples lost: 0.",
        ):
            simpleperf.finish(adb, process, 100, 10, self.path)
        self.assertNotIn("capture_binding", self.companion())


if __name__ == "__main__":
    unittest.main()
