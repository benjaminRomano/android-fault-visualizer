import subprocess
import unittest
from types import SimpleNamespace
from unittest import mock

from android_fault_visualizer import recording


class RecorderLifecycleTests(unittest.TestCase):
    def setUp(self):
        self.adb = mock.Mock()
        self.adb.base_command = ["adb", "-s", "test-device"]
        self.adb.shell.return_value = SimpleNamespace(stdout="")
        self.adb.root_shell.return_value = SimpleNamespace(stdout="1")
        self.process = mock.Mock()
        self.process.poll.return_value = None
        self.process.communicate.return_value = ("finished", None)
        self.process.stdout.fileno.return_value = 55
        self.popen = self.enterContext(
            mock.patch.object(recording.subprocess, "Popen", return_value=self.process)
        )
        selector_factory = self.enterContext(
            mock.patch.object(recording.selectors, "DefaultSelector")
        )
        selector_factory.return_value.__enter__.return_value.select.return_value = [
            True
        ]

    def test_native_failed_readiness_stops_only_announced_pid(self):
        with mock.patch.object(
            recording.os, "read", side_effect=[b"STARTING pid=123\n", b""]
        ):
            with self.assertRaisesRegex(RuntimeError, "did not become ready"):
                recording.start_fault_collector(self.adb, True)
        self.adb.root_shell.assert_called_once_with(
            "kill -TERM 123", check=False, timeout=5
        )
        self.process.terminate.assert_called_once()
        self.process.communicate.assert_called_once_with(timeout=5)

    def test_native_readiness_deadline_escalates_stuck_cleanup(self):
        self.process.communicate.side_effect = [
            subprocess.TimeoutExpired("adb", 5),
            ("", None),
        ]
        with (
            mock.patch.object(recording.os, "read", return_value=b"STARTING pid=123\n"),
            mock.patch.object(recording.time, "monotonic", side_effect=[0, 1, 2, 16]),
        ):
            with self.assertRaisesRegex(RuntimeError, "within 15 seconds"):
                recording.start_fault_collector(self.adb, True)
        self.assertEqual(
            [
                mock.call("kill -TERM 123", check=False, timeout=5),
                mock.call("kill -KILL 123", check=False, timeout=5),
            ],
            self.adb.root_shell.call_args_list,
        )
        self.process.kill.assert_called_once()

    def test_native_success_preserves_noncontiguous_cpu_ids(self):
        with mock.patch.object(
            recording.os,
            "read",
            return_value=b"STARTING pid=123\nREADY pid=123 capture_start_ns=456 online_cpus=0,2,8-9\n",
        ):
            self.assertEqual(
                (self.process, 123, 456, "0,2,8-9"),
                recording.start_fault_collector(self.adb, True),
            )
        self.process.terminate.assert_not_called()

    def test_stop_timeout_kills_remote_and_local_then_rejects_capture(self):
        self.process.communicate.side_effect = [
            subprocess.TimeoutExpired("adb", 20),
            ("", None),
        ]
        with self.assertRaisesRegex(RuntimeError, "capture rejected"):
            recording.stop_remote(self.adb, self.process, 123)
        self.assertEqual(
            [
                mock.call("kill -INT 123", check=False, timeout=5),
                mock.call("kill -KILL 123", check=False, timeout=5),
            ],
            self.adb.root_shell.call_args_list,
        )
        self.process.kill.assert_called_once()
        self.assertEqual(
            [mock.call(timeout=20), mock.call(timeout=5)],
            self.process.communicate.call_args_list,
        )

    def test_stop_adb_exception_still_kills_local_process(self):
        self.adb.root_shell.side_effect = OSError("device disconnected")
        with self.assertRaisesRegex(RuntimeError, "capture rejected") as failure:
            recording.stop_remote(self.adb, self.process, 123)
        self.process.kill.assert_called_once()
        self.assertIn("device disconnected", failure.exception.__notes__[0])

    def test_perfetto_reads_owned_pid_before_config_and_readiness(self):
        with mock.patch.object(
            recording.os, "read", return_value=b"PERFETTO_PID=123\n"
        ):
            self.assertEqual(
                (self.process, 123),
                recording.start_perfetto(self.adb, "/data/local/tmp/fault trace"),
            )
        command = self.popen.call_args.args[0]
        self.assertEqual(
            "echo PERFETTO_PID=$$; exec perfetto --txt -c - -o '/data/local/tmp/fault trace'",
            command[-1],
        )
        self.adb.shell.assert_called_once_with(
            ["pidof", "perfetto"], capture_output=True, text=True, timeout=5
        )
        self.assertIsNone(self.process.stdin)
        self.process.terminate.assert_not_called()

    def test_perfetto_adb_readiness_exception_cleans_owned_recorder(self):
        self.adb.root_shell.side_effect = [
            OSError("read failed"),
            SimpleNamespace(stdout=""),
        ]
        with mock.patch.object(
            recording.os, "read", return_value=b"PERFETTO_PID=123\n"
        ):
            with self.assertRaisesRegex(OSError, "read failed"):
                recording.start_perfetto(self.adb, "/data/local/tmp/fault.trace")
        self.assertEqual(
            mock.call("kill -TERM 123", check=False, timeout=5),
            self.adb.root_shell.call_args_list[-1],
        )
        self.process.terminate.assert_called_once()

    def test_perfetto_config_broken_pipe_cleans_owned_recorder(self):
        stdin = self.process.stdin
        stdin.write.side_effect = BrokenPipeError("config rejected")
        with mock.patch.object(
            recording.os, "read", return_value=b"PERFETTO_PID=123\n"
        ):
            with self.assertRaisesRegex(BrokenPipeError, "config rejected"):
                recording.start_perfetto(self.adb, "/data/local/tmp/fault.trace")
        self.adb.root_shell.assert_called_once_with(
            "kill -TERM 123", check=False, timeout=5
        )
        self.assertIsNone(self.process.stdin)

    def test_perfetto_timeout_cleans_owned_recorder(self):
        self.adb.root_shell.return_value = SimpleNamespace(stdout="0")
        with (
            mock.patch.object(recording.os, "read", return_value=b"PERFETTO_PID=123\n"),
            mock.patch.object(recording.time, "monotonic", side_effect=[0, 1, 2, 11]),
            mock.patch.object(recording.time, "sleep"),
        ):
            with self.assertRaisesRegex(RuntimeError, "Timed out"):
                recording.start_perfetto(self.adb, "/data/local/tmp/fault.trace")
        self.assertEqual(
            mock.call("kill -TERM 123", check=False, timeout=5),
            self.adb.root_shell.call_args_list[-1],
        )
        self.process.terminate.assert_called_once()

    def test_perfetto_refuses_existing_trace_before_starting(self):
        self.adb.shell.return_value = SimpleNamespace(stdout="999")
        with self.assertRaisesRegex(RuntimeError, "unrelated trace"):
            recording.start_perfetto(self.adb, "/data/local/tmp/fault.trace")
        self.popen.assert_not_called()
        self.adb.root_shell.assert_not_called()

    def test_native_summary_preserves_capacity_and_memory_provenance(self):
        summary = (
            "capture_start_ns=100 capture_end_ns=200 samples=42 mappings=34 "
            "lost=0 integrity_errors=0 throttled=0 callchain_entries=50 "
            "callchain_overflow=0 lost_counter_supported=1 max_samples=500000 "
            "max_mappings=100000 max_callchain_entries=4000000 "
            "record_buffer_bytes=117600000 perf_ring_bytes=33685504"
        )
        self.process.returncode = 0
        with mock.patch.object(recording, "stop_remote", return_value=summary):
            status, metadata = recording.stop_fault_collector(
                self.adb, self.process, 123
            )
        self.assertEqual(0, status)
        self.assertEqual(100000, metadata["max_mappings"])
        self.assertEqual(4000000, metadata["max_callchain_entries"])
        self.assertEqual(117600000, metadata["record_buffer_bytes"])
        self.assertEqual(33685504, metadata["perf_ring_bytes"])
