import re
import os
import selectors
import shlex
import subprocess
import time

from android_fault_visualizer.paths import (
    TRACE_CONFIG,
    REMOTE_COLLECTOR,
    REMOTE_FAULTS,
    REMOTE_MAPPINGS,
    REMOTE_CALLCHAINS,
)
from android_fault_visualizer.device import Adb


def _abort_recorder(
    adb: Adb,
    process: subprocess.Popen,
    device_pid: int | None,
    error: BaseException,
    *,
    force: bool = False,
) -> None:
    """Best-effort bounded cleanup; preserve the failure that triggered it."""

    def attempt(action):
        try:
            action()
        except (OSError, subprocess.SubprocessError) as cleanup_error:
            error.add_note(f"Recorder cleanup: {cleanup_error}")

    def signal_remote(signal):
        if device_pid is not None:
            attempt(
                lambda: adb.root_shell(
                    f"kill -{signal} {device_pid}", check=False, timeout=5
                )
            )

    signal_remote("KILL" if force else "TERM")
    attempt(process.kill if force else process.terminate)
    try:
        process.communicate(timeout=5)
    except subprocess.TimeoutExpired:
        signal_remote("KILL")
        attempt(process.kill)
        attempt(lambda: process.communicate(timeout=5))
    except OSError as cleanup_error:
        error.add_note(f"Recorder cleanup: {cleanup_error}")


def start_perfetto(adb: Adb, remote_trace: str) -> tuple[subprocess.Popen, int]:
    existing = adb.shell(
        ["pidof", "perfetto"], capture_output=True, text=True, timeout=5
    ).stdout.strip()
    if existing:
        raise RuntimeError(
            f"Another Perfetto command is already running ({existing}); "
            "refusing to stop an unrelated trace."
        )
    config = TRACE_CONFIG.read_text()
    command = (
        f"echo PERFETTO_PID=$$; exec perfetto --txt -c - -o {shlex.quote(remote_trace)}"
    )
    process = subprocess.Popen(
        adb.base_command + ["shell", command],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
    )
    device_pid = None
    output = ""
    deadline = time.monotonic() + 10
    try:
        assert process.stdout is not None
        # Read our shell's PID before supplying config, so even a failed pipe
        # write has an exact cleanup target. exec preserves the announced PID.
        with selectors.DefaultSelector() as selector:
            selector.register(process.stdout, selectors.EVENT_READ)
            while time.monotonic() < deadline and process.poll() is None:
                if not selector.select(0.1):
                    continue
                chunk = os.read(process.stdout.fileno(), 8192)
                if not chunk:
                    break
                output += chunk.decode(errors="replace")
                match = re.search(r"PERFETTO_PID=(\d+)\r?\n", output)
                if match:
                    device_pid = int(match[1])
                    break
        if device_pid is None:
            raise RuntimeError("Perfetto did not announce its PID: " + output.strip())
        assert process.stdin is not None
        process.stdin.write(config)
        process.stdin.close()
        process.stdin = None
        while time.monotonic() < deadline:
            if process.poll() is not None:
                stdout = process.stdout.read() if process.stdout else ""
                raise RuntimeError("Unable to start Perfetto: " + stdout.strip())
            tracing_state = adb.root_shell(
                "cat /sys/kernel/tracing/tracing_on 2>/dev/null || "
                "cat /sys/kernel/debug/tracing/tracing_on 2>/dev/null",
                capture_output=True,
                text=True,
                timeout=2,
            ).stdout.strip()
            event_state = adb.root_shell(
                "cat /sys/kernel/tracing/events/filemap/"
                "mm_filemap_add_to_page_cache/enable 2>/dev/null || "
                "cat /sys/kernel/debug/tracing/events/filemap/"
                "mm_filemap_add_to_page_cache/enable 2>/dev/null",
                capture_output=True,
                text=True,
                timeout=2,
            ).stdout.strip()
            if tracing_state == "1" and event_state == "1":
                return process, device_pid
            time.sleep(0.05)
        raise RuntimeError("Timed out waiting for Perfetto to start")
    except BaseException as error:
        # communicate() must not try to flush an already closed/broken pipe.
        if process.stdin is not None:
            try:
                process.stdin.close()
            except OSError:
                pass
            process.stdin = None
        _abort_recorder(adb, process, device_pid, error)
        raise


def stop_perfetto(adb: Adb, process: subprocess.Popen, device_pid: int) -> None:
    stdout = stop_remote(adb, process, device_pid)
    if process.returncode not in (0, 130):
        raise RuntimeError("Unable to stop Perfetto cleanly: " + stdout.strip())


def start_fault_collector(
    adb: Adb, capture_stacks: bool
) -> tuple[subprocess.Popen, int, int, str]:
    if adb.shell(
        ["pidof", "page_fault_collector"], capture_output=True, text=True, timeout=5
    ).stdout.strip():
        raise RuntimeError(
            "Another fault collector is running; refusing to overwrite its files"
        )
    command = (
        f"{shlex.quote(REMOTE_COLLECTOR)} "
        f"--output {shlex.quote(REMOTE_FAULTS)} "
        f"--mappings-output {shlex.quote(REMOTE_MAPPINGS)} "
        + (
            f"--callchains-output {shlex.quote(REMOTE_CALLCHAINS)} "
            if capture_stacks
            else ""
        )
        + "--duration-ms 60000"
    )
    process = subprocess.Popen(
        adb.root_command(command),
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        bufsize=1,
    )
    assert process.stdout is not None
    output = ""
    deadline = time.monotonic() + 15
    try:
        with selectors.DefaultSelector() as selector:
            selector.register(process.stdout, selectors.EVENT_READ)
            while time.monotonic() < deadline and process.poll() is None:
                if not selector.select(
                    timeout=min(0.2, max(0, deadline - time.monotonic()))
                ):
                    continue
                chunk = os.read(process.stdout.fileno(), 8192)
                if not chunk:
                    break
                output += chunk.decode(errors="replace")
                match = re.search(
                    r"READY pid=(\d+) capture_start_ns=(\d+) online_cpus=([0-9,-]+)\n",
                    output,
                )
                if match:
                    return process, int(match[1]), int(match[2]), match[3]
        raise RuntimeError(
            "Fault collector did not become ready within 15 seconds:\n" + output
        )
    except BaseException as error:
        pid = re.search(r"STARTING pid=(\d+)", output)
        _abort_recorder(adb, process, int(pid[1]) if pid else None, error)
        raise


def stop_remote(adb: Adb, process: subprocess.Popen, device_pid: int) -> str:
    try:
        adb.root_shell(f"kill -INT {device_pid}", check=False, timeout=5)
        stdout, _ = process.communicate(timeout=20)
        return stdout
    except (OSError, subprocess.SubprocessError) as cause:
        error = RuntimeError(
            f"Recorder {device_pid} did not stop cleanly; capture rejected"
        )
        _abort_recorder(adb, process, device_pid, error, force=True)
        raise error from cause


def stop_fault_collector(
    adb: Adb, process: subprocess.Popen, device_pid: int
) -> tuple[int, dict[str, int]]:
    stdout = stop_remote(adb, process, device_pid)
    match = re.search(
        r"capture_start_ns=(?P<start>\d+) "
        r"capture_end_ns=(?P<end>\d+) "
        r"samples=(?P<samples>\d+) mappings=(?P<mappings>\d+) "
        r"lost=(?P<lost>\d+) integrity_errors=(?P<integrity_errors>\d+) "
        r"throttled=(?P<throttled>\d+)"
        r"(?: callchain_entries=(?P<callchain_entries>\d+))?"
        r"(?: callchain_overflow=(?P<callchain_overflow>\d+))?"
        r"(?: lost_counter_supported=(?P<lost_counter_supported>[01]))?"
        r"(?: max_samples=(?P<max_samples>\d+)"
        r" max_mappings=(?P<max_mappings>\d+)"
        r" max_callchain_entries=(?P<max_callchain_entries>\d+)"
        r" record_buffer_bytes=(?P<record_buffer_bytes>\d+)"
        r" perf_ring_bytes=(?P<perf_ring_bytes>\d+))?",
        stdout,
    )
    if not match:
        raise RuntimeError("Fault collector returned invalid metadata:\n" + stdout)
    metadata = {
        key: int(value) for key, value in match.groupdict().items() if value is not None
    }
    return process.returncode or 0, metadata
