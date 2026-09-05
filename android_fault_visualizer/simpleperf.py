"""Optional system-wide DWARF companion; never join its stacks to exact faults."""

import json
import os
import re
import selectors
import shlex
import subprocess
import time
from pathlib import Path

from .artifacts import is_app_owned_path
from .recording import _abort_recorder, stop_remote

REMOTE_DATA = "/data/local/tmp/android-fault-visualizer/dwarf.data"
MMAP_PAGES_PER_CPU = 1024


def record_command() -> str:
    return (
        f"simpleperf record -a -c 1 -m {MMAP_PAGES_PER_CPU} "
        "-e major-faults:u --call-graph dwarf --post-unwind=yes "
        "--no-callchain-joiner --no-cut-samples --clockid boottime "
        "--no-dump-kernel-symbols --start_profiling_fd 1 --duration 60 "
        f"-o {shlex.quote(REMOTE_DATA)}"
    )


def start(adb):
    if adb.shell(
        ["pidof", "simpleperf"], capture_output=True, text=True, timeout=5
    ).stdout.strip():
        raise RuntimeError("Another Simpleperf is running; refusing to interfere")
    # No --app/--pid attachment race and no process-name filter before naming.
    command = "echo SIMPLEPERF_PID=$$; exec " + record_command()
    process = subprocess.Popen(
        adb.root_command(command),
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
    )
    output = ""
    try:
        with selectors.DefaultSelector() as selector:
            selector.register(process.stdout, selectors.EVENT_READ)
            deadline = time.monotonic() + 20
            while time.monotonic() < deadline and process.poll() is None:
                if selector.select(0.1):
                    chunk = os.read(process.stdout.fileno(), 8192)
                    if not chunk:
                        break
                    output += chunk.decode(errors="replace")
                    pid = re.search(r"SIMPLEPERF_PID=(\d+)", output)
                    if pid and "STARTED" in output:
                        return process, int(pid[1])
        raise RuntimeError("Simpleperf did not report readiness: " + output)
    except BaseException as error:
        pid = re.search(r"SIMPLEPERF_PID=(\d+)", output)
        _abort_recorder(adb, process, int(pid[1]) if pid else None, error)
        raise


def finish(
    adb, process, recorder_pid: int, target_pid: int | None, output: Path
) -> None:
    log = stop_remote(adb, process, recorder_pid)
    (output / "simpleperf.log").write_text(log)
    summary = re.search(
        r"Samples recorded:\s*([\d,]+)\.\s*Samples lost:\s*([\d,]+)"
        r"(?:\s*\([^)]*\))?\.",
        log,
    )
    recorded = int(summary[1].replace(",", "")) if summary else None
    lost = int(summary[2].replace(",", "")) if summary else None
    valid = process.returncode == 0 and summary is not None and lost == 0
    capture_path = output / "capture_metadata.json"
    capture = json.loads(capture_path.read_text()) if capture_path.exists() else {}
    page_size = capture.get("page_size")
    (output / "simpleperf-metadata.json").write_text(
        json.dumps(
            {
                "target_pid": target_pid,
                "samples_recorded": recorded,
                "samples_lost": lost,
                "return_code": process.returncode,
                "integrity_passed": valid,
                "record_command": record_command(),
                "kernel_buffer_pages_per_cpu": MMAP_PAGES_PER_CPU,
                "page_size": page_size,
                "kernel_buffer_bytes_per_cpu": (
                    MMAP_PAGES_PER_CPU * page_size if page_size else None
                ),
                "online_cpus": capture.get("online_cpus_sysfs"),
                "scope": "system-wide; filtered by exact PID after capture",
                "clock": "boottime",
                "joiner": False,
                "gap_removal": False,
            },
            indent=2,
        )
    )
    if not valid:
        raise RuntimeError("Simpleperf companion failed integrity checks: " + log)
    adb.pull_with_root_fallback(REMOTE_DATA, output / "simpleperf.data")
    if target_pid is not None:
        result = adb.shell(
            [
                "simpleperf",
                "report-sample",
                "-i",
                REMOTE_DATA,
                "--show-callchain",
                "--remove-gaps",
                "0",
                "--include-pid",
                str(target_pid),
            ],
            capture_output=True,
            text=True,
            check=True,
        )
        (output / "simpleperf-stacks.txt").write_text(result.stdout)
    adb.root_shell(f"rm -f {shlex.quote(REMOTE_DATA)}", check=True)


def parse_samples(text: str) -> list[dict]:
    samples = []
    sample = None
    frame = None
    for raw in text.splitlines():
        line = raw.strip()
        if line == "sample:":
            sample = {"stack": []}
            samples.append(sample)
            frame = None
        elif sample is not None and ":" in line:
            key, value = line.split(":", 1)
            value = value.strip()
            if key == "vaddr_in_file":
                frame = {"ip": value, "file": "", "label": "Unresolved"}
                sample["stack"].append(frame)
            elif key in {"file", "symbol"} and frame is not None:
                frame["label" if key == "symbol" else "file"] = value
            elif key in {
                "event_type",
                "time",
                "event_count",
                "thread_id",
                "thread_name",
            }:
                sample[key] = value
    for s in samples:
        if (
            int(s.get("event_count", 0)) != 1
            or s.get("event_type", "").split(":")[0] != "major-faults"
        ):
            raise ValueError("DWARF companion requires period-1 major-fault samples")
        for key in ("time", "thread_id"):
            s[key] = int(s[key])
    return samples


def report_run(path: Path, metadata: dict) -> dict | None:
    sample_path = path / "simpleperf-stacks.txt"
    if not sample_path.exists():
        return None
    integrity = json.loads((path / "simpleperf-metadata.json").read_text())
    if (
        integrity["samples_lost"]
        or integrity["target_pid"] != metadata["pid"]
        or not integrity.get("integrity_passed", True)
    ):
        raise ValueError("Invalid Simpleperf companion metadata")
    startup = metadata["startup"]
    samples = [
        s
        for s in parse_samples(sample_path.read_text())
        if startup["ts"] <= s["time"] <= startup["ts_end"]
    ]
    sources, events = {}, []
    for index, s in enumerate(samples):
        stack = s["stack"]
        source = stack[0]["file"] if stack else "Unresolved stack"
        sources[source] = {
            "label": source,
            "path": source,
            "mapped": False,
            "boundaries": [],
        }
        for frame in stack:
            frame["app"] = is_app_owned_path(frame["file"], metadata["package"])
            frame["unresolved"] = frame["label"] in {"Unresolved", "[unknown]"}
        events.append(
            {
                "id": index,
                "time": (s["time"] - startup["ts"]) / 1e6,
                "major": True,
                "address": "0x0",
                "source": source,
                "offset": None,
                "page": None,
                "stack": stack,
                "thread": f"{s.get('thread_name','')} ({s['thread_id']})",
                "detail": {
                    "Read source": "Not recorded by Simpleperf",
                    "First captured app frame": next(
                        (f["label"] for f in stack if f["app"]), ""
                    ),
                },
            }
        )
    return {
        "label": path.name + " · DWARF stacks",
        "subtitle": "Android Simpleperf · independent major-fault samples · same launch window",
        "stacksOnly": True,
        "pageSize": metadata["page_size"],
        "sources": sources,
        "events": events,
        "cache": "See the exact capture for pre-launch cache verification.",
        "notes": [
            "System-wide recording starts before launch and is filtered by the launched PID after recording. DWARF/ART unwinding can recover managed method names. Stack joining and gap removal are disabled.",
            "Simpleperf does not record the faulted virtual address here. Binaries in this view are stack instruction sources, not read-file attribution. These samples are not paired to the native collector by timestamp or ordinal.",
            "Recording two collectors adds overhead. Compare timing only between equivalently instrumented runs.",
        ],
        "provenance": integrity,
    }
