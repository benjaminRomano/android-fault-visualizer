import hashlib
import json
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from android_fault_visualizer import artifacts, device, simpleperf


class StackArtifactTests(unittest.TestCase):
    def test_anonymous_and_deleted_mappings_are_not_pulled(self):
        maps = artifacts.parse_maps_text(
            "1000-2000 rw-p 00000000 00:00 0\n"
            "3000-4000 r-xp 00000000 00:00 0 /system/lib64/deleted.so (deleted)\n"
            "5000-6000 r-xp 00000000 00:00 0 /system/bin/linker64\n"
            "6000-7000 r--p 00001000 00:00 0 /system/bin/linker64\n"
        )
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            adb = mock.Mock()
            warnings = []
            with mock.patch.object(artifacts, "parse_maps", return_value=maps):
                device.pull_stack_binaries(adb, root, warnings)
            mapping = json.loads((root / "artifacts.json").read_text())
        self.assertEqual(["/system/bin/linker64"], list(mapping))
        self.assertEqual(1, adb.pull_with_root_fallback.call_count)
        self.assertEqual([], warnings)

    def test_nonessential_symbol_pull_failures_do_not_discard_capture(self):
        for error in (
            RuntimeError("ADB pull failed"),
            OSError("file disappeared"),
            subprocess.CalledProcessError(1, ["adb", "pull"]),
        ):
            with (
                self.subTest(error=type(error).__name__),
                tempfile.TemporaryDirectory() as directory,
            ):
                root = Path(directory)
                (root / "artifacts.json").write_text(
                    '{"/data/app/base.apk":"artifacts/base.apk"}'
                )
                maps = artifacts.parse_maps_text(
                    "1000-2000 r-xp 00000000 00:00 0 /system/lib64/test.so\n"
                )
                adb = mock.Mock()
                adb.pull_with_root_fallback.side_effect = error
                warnings = []
                with mock.patch.object(artifacts, "parse_maps", return_value=maps):
                    device.pull_stack_binaries(adb, root, warnings)
                self.assertEqual(
                    {"/data/app/base.apk": "artifacts/base.apk"},
                    json.loads((root / "artifacts.json").read_text()),
                )
                self.assertEqual(1, len(warnings))
                self.assertIn("raw addresses retained", warnings[0])

    def test_native_provenance_hashes_cpu_header_as_well_as_source(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "page_fault_collector.c"
            source.write_bytes(b"source")
            header = root / "cpu_list.h"
            header.write_bytes(b"header")
            reclaim_header = root / "apk_cache_reclaim.h"
            reclaim_header.write_bytes(b"reclaim header")
            (root / "page_fault_collector").write_bytes(b"binary")
            with (
                mock.patch.object(device, "COLLECTOR_SOURCE", source),
                mock.patch.object(device, "find_ndk", return_value=root),
                mock.patch.object(device, "find_compiler", return_value=Path("clang")),
                mock.patch.object(device.subprocess, "run"),
            ):
                first = device.build_and_push_collector(
                    mock.Mock(), root, "arm64-v8a", 36
                )
                header.write_bytes(b"changed header")
                reclaim_header.write_bytes(b"changed reclaim header")
                second = device.build_and_push_collector(
                    mock.Mock(), root, "arm64-v8a", 36
                )
            self.assertEqual(
                hashlib.sha256(b"source").hexdigest(), first["collector_source_sha256"]
            )
            self.assertEqual(
                first["collector_source_sha256"], second["collector_source_sha256"]
            )
            self.assertNotEqual(
                first["collector_cpu_list_header_sha256"],
                second["collector_cpu_list_header_sha256"],
            )
            self.assertNotEqual(
                first["collector_apk_reclaim_header_sha256"],
                second["collector_apk_reclaim_header_sha256"],
            )


class SimpleperfIntegrityTests(unittest.TestCase):
    def test_period_one_dwarf_command_has_explicit_bounded_kernel_buffers(self):
        command = simpleperf.record_command()
        self.assertIn("-a -c 1 -m 1024", command)
        self.assertIn("-e major-faults:u --call-graph dwarf", command)
        self.assertIn("--no-callchain-joiner --no-cut-samples", command)
        self.assertNotIn("--app", command)
        self.assertNotIn("--include-process-name", command)

    def test_startup_failure_uses_bounded_owned_pid_cleanup(self):
        adb = mock.Mock()
        adb.shell.return_value = subprocess.CompletedProcess([], 0, stdout="")
        process = mock.Mock()
        process.poll.return_value = None
        process.communicate.return_value = ("", None)
        with (
            mock.patch.object(simpleperf.subprocess, "Popen", return_value=process),
            mock.patch.object(simpleperf.selectors, "DefaultSelector") as selectors,
            mock.patch.object(
                simpleperf.os, "read", side_effect=[b"SIMPLEPERF_PID=123\n", b""]
            ),
        ):
            selectors.return_value.__enter__.return_value.select.return_value = [True]
            with self.assertRaisesRegex(RuntimeError, "did not report readiness"):
                simpleperf.start(adb)
        adb.root_shell.assert_called_once_with("kill -TERM 123", check=False, timeout=5)
        process.terminate.assert_called_once()
        process.communicate.assert_called_once_with(timeout=5)

    def test_comma_grouped_record_count_is_accepted(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "capture_metadata.json").write_text(
                '{"page_size":16384,"online_cpus_sysfs":"0,2,8-9"}'
            )
            adb = mock.Mock()
            adb.shell.return_value = subprocess.CompletedProcess(
                [], 0, stdout="sample export"
            )
            process = mock.Mock(returncode=0)
            with mock.patch.object(
                simpleperf,
                "stop_remote",
                return_value="Samples recorded: 4,561. Samples lost: 0.\n",
            ):
                simpleperf.finish(adb, process, 100, 123, root)
            metadata = json.loads((root / "simpleperf-metadata.json").read_text())
            self.assertEqual(4561, metadata["samples_recorded"])
            self.assertEqual(0, metadata["samples_lost"])
            self.assertEqual(123, metadata["target_pid"])
            self.assertTrue(metadata["integrity_passed"])
            self.assertEqual(16777216, metadata["kernel_buffer_bytes_per_cpu"])
            self.assertEqual("0,2,8-9", metadata["online_cpus"])
            self.assertEqual(
                "sample export", (root / "simpleperf-stacks.txt").read_text()
            )

    def test_comma_grouped_loss_count_is_a_hard_failure(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            adb = mock.Mock()
            process = mock.Mock(returncode=0)
            with mock.patch.object(
                simpleperf,
                "stop_remote",
                return_value="Samples recorded: 4,561. Samples lost: 1,234.\n",
            ):
                with self.assertRaisesRegex(RuntimeError, "integrity"):
                    simpleperf.finish(adb, process, 100, 123, root)
            adb.pull_with_root_fallback.assert_not_called()
            metadata = json.loads((root / "simpleperf-metadata.json").read_text())
            self.assertFalse(metadata["integrity_passed"])
            self.assertEqual(1234, metadata["samples_lost"])

    def test_loss_breakdown_is_parsed_and_retained_on_failure(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            with mock.patch.object(
                simpleperf,
                "stop_remote",
                return_value="Samples recorded: 1,017. Samples lost: 228 (kernelspace: 228, userspace: 0).",
            ):
                with self.assertRaisesRegex(RuntimeError, "integrity"):
                    simpleperf.finish(
                        mock.Mock(), mock.Mock(returncode=0), 100, 123, root
                    )
            metadata = json.loads((root / "simpleperf-metadata.json").read_text())
            self.assertEqual(228, metadata["samples_lost"])
            self.assertFalse(metadata["integrity_passed"])
