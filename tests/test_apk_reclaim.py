import csv
import io
import json
import subprocess
import tempfile
import unittest
from contextlib import ExitStack
from pathlib import Path
from unittest import mock

import faults
from android_fault_visualizer import device


APK = "/data/app/~~token/com.example.app-install/base.apk"


def audit_text(**changes):
    row = dict(
        zip(
            device.APK_RECLAIM_FIELDS,
            (
                "100",
                "42",
                "10000",
                "14000",
                "0",
                "fe:35",
                "1000",
                "r--s",
                "16384",
                "16384",
                "0",
                APK,
            ),
        )
    )
    row.update(changes)
    output = io.StringIO()
    writer = csv.DictWriter(
        output,
        fieldnames=device.APK_RECLAIM_FIELDS,
        delimiter="\t",
        lineterminator="\n",
    )
    writer.writeheader()
    writer.writerow(row)
    return output.getvalue()


class MappedApkReclaimTests(unittest.TestCase):
    def test_advice_success_is_not_treated_as_eviction_proof(self):
        adb = mock.Mock()
        adb.root_shell.return_value = subprocess.CompletedProcess(
            [], 0, audit_text(), ""
        )
        with (
            tempfile.TemporaryDirectory() as directory,
            mock.patch.object(device, "run_collector_file_command") as evict,
        ):
            root = Path(directory)
            result = device.reclaim_mapped_apks(adb, [APK], root, "after_drop")
            self.assertEqual(audit_text(), (root / result["audit_file"]).read_text())
        self.assertEqual(1, result["ranges_attempted"])
        self.assertEqual(16384, result["advised_bytes"])
        self.assertFalse(result["eviction_verified"])
        evict.assert_called_once_with(adb, "--evict", [APK])
        self.assertEqual(15, adb.root_shell.call_args.kwargs["timeout"])
        with self.assertRaisesRegex(RuntimeError, "eviction verification failed"):
            device.verify_cache_residency(
                [
                    {
                        "phase": "after_drop",
                        "resident_pages": 1,
                        "total_pages": 2,
                        "file_name": APK,
                    }
                ],
                0,
                "after_drop",
            )

    def test_failed_and_partial_advice_keep_explicit_diagnostics(self):
        for result, error in [(-1, 1), (8192, 0)]:
            with (
                self.subTest(result=result),
                tempfile.TemporaryDirectory() as directory,
                mock.patch.object(device, "run_collector_file_command"),
            ):
                adb = mock.Mock()
                adb.root_shell.return_value = subprocess.CompletedProcess(
                    [], 0, audit_text(result=result, errno=error), ""
                )
                diagnostics = device.reclaim_mapped_apks(
                    adb, [APK], Path(directory), "before_launch"
                )
                self.assertEqual(1, diagnostics["failed_ranges"])
                self.assertIn("strict residency", diagnostics["warning"])
                self.assertEqual(max(result, 0), diagnostics["advised_bytes"])

    def test_missing_kernel_support_or_timeout_does_not_claim_eviction(self):
        for outcome in [
            subprocess.CompletedProcess([], 1, "", "pidfd_open unavailable"),
            subprocess.TimeoutExpired("adb", 15, output=b"", stderr=b"timeout"),
        ]:
            with (
                self.subTest(outcome=outcome),
                tempfile.TemporaryDirectory() as directory,
                mock.patch.object(device, "run_collector_file_command"),
            ):
                adb = mock.Mock()
                if isinstance(outcome, Exception):
                    adb.root_shell.side_effect = outcome
                else:
                    adb.root_shell.return_value = outcome
                diagnostics = device.reclaim_mapped_apks(
                    adb, [APK], Path(directory), "after_drop"
                )
                self.assertFalse(diagnostics["eviction_verified"])
                self.assertEqual(0, diagnostics["ranges_attempted"])
                self.assertIn("warning", diagnostics)

    def test_rejects_noninstalled_or_ambiguous_targets_before_adb(self):
        adb = mock.Mock()
        for paths in [
            [],
            [APK, APK],
            ["/system/app/base.apk"],
            ["/data/app/a/../base.apk"],
            [APK + "\n"],
            [APK.replace(".apk", ".vdex")],
        ]:
            with self.subTest(paths=paths), self.assertRaises(ValueError):
                device.reclaim_mapped_apks(adb, paths, Path("unused"), "after_drop")
        adb.root_shell.assert_not_called()

    def test_success_without_audit_header_is_rejected(self):
        adb = mock.Mock()
        adb.root_shell.return_value = subprocess.CompletedProcess([], 0, "", "")
        with (
            tempfile.TemporaryDirectory() as directory,
            self.assertRaisesRegex(RuntimeError, "audit header"),
        ):
            device.reclaim_mapped_apks(adb, [APK], Path(directory), "after_drop")

    def test_rejects_malformed_or_out_of_scope_native_audit(self):
        for changes in [
            {"path": APK.replace("com.example.app-", "com.example.application-")},
            {"permissions": "rw-p"},
            {"dev": "wrong"},
            {"pid": "0"},
            {"starttime": "0"},
            {"inode": "0"},
            {"end": "14001"},
            {"result": "16385"},
            {"result": "-2"},
            {"result": "-1", "errno": "0"},
            {"result": "16384", "errno": "1"},
            {"begin": "invalid"},
        ]:
            with self.subTest(changes=changes), self.assertRaises(RuntimeError):
                device.parse_apk_reclaim_output(audit_text(**changes), [APK])
        with self.assertRaisesRegex(RuntimeError, "header"):
            device.parse_apk_reclaim_output("not an audit", [APK])
        text = audit_text()
        with self.assertRaisesRegex(RuntimeError, "bounded"):
            device.parse_apk_reclaim_output(
                text + text.splitlines(True)[1] * 256, [APK]
            )


class ReclaimCaptureLifecycleTests(unittest.TestCase):
    def run_capture(self, enabled, remaining=0):
        events = []
        adb = mock.Mock(serial="emulator-test")
        adb.getprop.side_effect = lambda key: {
            "ro.build.version.sdk": "36",
            "ro.product.cpu.abi": "arm64-v8a",
        }.get(key, "test")

        def shell(args, **kwargs):
            if args[:2] == ["am", "start"]:
                events.append("launch")
                return subprocess.CompletedProcess([], 0, "Status: ok\n")
            value = {
                "getconf": "16384",
                "uname": "6.6",
                "/sys/devices/system/cpu/online": "0-3",
                "/proc/sys/kernel/random/boot_id": "boot",
                "/proc/uptime": "10 0",
            }.get(args[-1], "16384")
            return subprocess.CompletedProcess([], 0, value)

        adb.shell.side_effect = shell

        def residency(*args, **kwargs):
            events.append("mincore")
            pages = remaining if events.count("mincore") > 1 else 1
            return f"file_name,size_bytes,total_pages,resident_pages\n{APK},32768,2,{pages}\n"

        def reclaim(*args):
            events.append("reclaim:" + args[-1])
            return {"phase": args[-1], "eviction_verified": False}

        with tempfile.TemporaryDirectory() as directory, ExitStack() as stack:
            root = Path(directory)
            replacements = {
                "package_paths": mock.Mock(return_value=[APK]),
                "resolve_activity": mock.Mock(return_value="com.example.app/.Main"),
                "build_and_push_collector": mock.Mock(return_value={}),
                "stop_and_enumerate_cache_targets": mock.Mock(return_value=[APK]),
                "dump_inode_mapping": mock.Mock(),
                "drop_caches": mock.Mock(
                    side_effect=lambda *args: events.append("drop")
                ),
                "reclaim_mapped_apks": mock.Mock(side_effect=reclaim),
                "run_collector_file_command": mock.Mock(side_effect=residency),
                "start_perfetto": mock.Mock(return_value=(mock.Mock(), 41)),
                "start_fault_collector": mock.Mock(
                    return_value=(mock.Mock(), 42, 123, "0-3")
                ),
                "package_files": mock.Mock(return_value=[APK]),
                "cache_targets": mock.Mock(return_value=[APK]),
                "dump_process_state": mock.Mock(return_value=100),
                "stop_fault_collector": mock.Mock(
                    return_value=(
                        0,
                        {
                            "lost": 0,
                            "integrity_errors": 0,
                            "throttled": 0,
                            "callchain_overflow": 0,
                        },
                    )
                ),
                "stop_perfetto": mock.Mock(),
                "pull_artifacts": mock.Mock(),
                "pull_stack_binaries": mock.Mock(),
            }
            for name, replacement in replacements.items():
                stack.enter_context(mock.patch.object(faults, name, replacement))
            stack.enter_context(mock.patch.object(faults.time, "sleep"))
            if remaining:
                with self.assertRaisesRegex(
                    RuntimeError, "eviction verification failed"
                ):
                    faults.collect(
                        adb,
                        "com.example.app",
                        None,
                        root,
                        0,
                        False,
                        0,
                        False,
                        False,
                        reclaim_apk_mappings=enabled,
                    )
            else:
                faults.collect(
                    adb,
                    "com.example.app",
                    None,
                    root,
                    0,
                    False,
                    0,
                    False,
                    False,
                    reclaim_apk_mappings=enabled,
                )
            metadata = json.loads((root / "capture_metadata.json").read_text())
        return events, metadata

    def test_opt_in_runs_before_both_strict_gates_and_before_launch(self):
        events, metadata = self.run_capture(True)
        self.assertEqual(
            [
                "mincore",
                "drop",
                "reclaim:after_drop",
                "mincore",
                "reclaim:before_launch",
                "mincore",
                "launch",
                "mincore",
            ],
            events,
        )
        self.assertTrue(metadata["reclaim_mapped_apks"])
        self.assertEqual(2, len(metadata["mapped_apk_reclaim"]))

    def test_default_does_not_reclaim_other_process_mappings(self):
        events, metadata = self.run_capture(False)
        self.assertFalse(any(event.startswith("reclaim") for event in events))
        self.assertFalse(metadata["reclaim_mapped_apks"])

    def test_advice_success_does_not_bypass_strict_gate(self):
        events, metadata = self.run_capture(True, remaining=1)
        self.assertNotIn("launch", events)
        self.assertEqual("cache_verification_failed", metadata["capture_status"])

    def test_cli_forwards_opt_in_flag(self):
        with (
            tempfile.TemporaryDirectory() as directory,
            mock.patch(
                "sys.argv",
                [
                    "faults.py",
                    "--package",
                    "com.example.app",
                    "--output",
                    directory,
                    "--reclaim-mapped-apks",
                ],
            ),
            mock.patch.object(faults, "Adb"),
            mock.patch.object(faults, "collect") as collect,
            mock.patch.object(faults, "process_capture"),
            mock.patch("report.build_report"),
        ):
            faults.main()
        self.assertIs(True, collect.call_args.args[-1])


class RebootReadinessTests(unittest.TestCase):
    def test_old_boot_complete_cannot_satisfy_reboot_readiness(self):
        adb = object.__new__(device.Adb)
        adb._root_template = "old template"
        adb.run = mock.Mock()
        old = "00000000-0000-0000-0000-000000000001"
        new = "00000000-0000-0000-0000-000000000002"
        adb.shell = mock.Mock(
            side_effect=[
                subprocess.CompletedProcess([], 0, old),
                subprocess.CompletedProcess([], 0, old),
                subprocess.TimeoutExpired("adb", 5),
                subprocess.CompletedProcess([], 0, new),
                subprocess.CompletedProcess([], 0, "0"),
                subprocess.CompletedProcess([], 0, new),
                subprocess.CompletedProcess([], 0, "1"),
            ]
        )
        with mock.patch.object(device.time, "sleep"):
            adb.reboot_and_wait()
        self.assertIsNone(adb._root_template)
        commands = [call.args[0] for call in adb.shell.call_args_list]
        self.assertEqual(2, commands.count(["getprop", "sys.boot_completed"]))
        self.assertTrue(
            all(call.kwargs["timeout"] == 5 for call in adb.shell.call_args_list)
        )
        adb.run.assert_called_once_with(["reboot"], check=True, timeout=15)

    def test_missing_boot_identity_does_not_start_reboot(self):
        adb = object.__new__(device.Adb)
        adb.run = mock.Mock()
        adb.shell = mock.Mock(return_value=subprocess.CompletedProcess([], 0, ""))
        with self.assertRaisesRegex(RuntimeError, "boot identity"):
            adb.reboot_and_wait()
        adb.run.assert_not_called()
