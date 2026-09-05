"""System-wide DWARF companion with optional, exact-identity stack enrichment."""

import csv
import hashlib
import json
import os
import re
import selectors
import shlex
import subprocess
import struct
import time
from collections import defaultdict
from pathlib import Path

from .artifacts import is_app_owned_path
from .recording import _abort_recorder, stop_remote

REMOTE_DATA = "/data/local/tmp/android-fault-visualizer/dwarf.data"
MMAP_PAGES_PER_CPU = 1024


def _boot_id(adb) -> str:
    value = adb.shell(
        ["cat", "/proc/sys/kernel/random/boot_id"],
        capture_output=True,
        text=True,
        check=True,
        timeout=5,
    ).stdout.strip()
    if not re.fullmatch(r"[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}", value):
        raise RuntimeError("Could not verify Simpleperf capture boot identity")
    return value


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
                        process.fault_capture_boot_id = _boot_id(adb)
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
    boot_start = getattr(process, "fault_capture_boot_id", None)
    boot_end = _boot_id(adb) if isinstance(boot_start, str) else None
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
    # Bind exported stacks to the raw perf records and this recorder lifecycle.
    # Older captures without this evidence remain independent streams.
    binding_paths = [
        output / name for name in ("simpleperf.data", "simpleperf-stacks.txt")
    ]
    if (
        isinstance(boot_start, str)
        and boot_start == boot_end == capture.get("boot_id")
        and all(path.is_file() for path in binding_paths)
    ):
        metadata_path = output / "simpleperf-metadata.json"
        companion = json.loads(metadata_path.read_text())
        companion["capture_binding"] = {
            "boot_id_start": boot_start,
            "boot_id_end": boot_end,
            "collector_start_ns": capture.get("collector_start_ns"),
            "serial": capture.get("serial"),
            "artifacts_sha256": {
                path.name: hashlib.sha256(path.read_bytes()).hexdigest()
                for path in binding_paths
            },
        }
        metadata_path.write_text(json.dumps(companion, indent=2))
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


def read_perf_sample_identities(data: bytes) -> list[dict]:
    """Read only the period-one, post-unwind Simpleperf layout we record.

    PERF_SAMPLE_IP is the original runtime instruction pointer, unlike the
    file-relative addresses printed by report-sample. Reject unfamiliar layouts
    rather than guessing record offsets. Linux's perf_event.h defines this ABI.
    """

    def unpack(fmt, offset, end=None):
        limit = len(data) if end is None else end
        if offset < 0 or offset + struct.calcsize(fmt) > limit:
            raise ValueError("Truncated Simpleperf record")
        return struct.unpack_from(fmt, data, offset)

    header = unpack("<13Q", 0)
    if data[:8] != b"PERFILE2" or header[1] != 104:
        raise ValueError("Unsupported Simpleperf file header")
    attr_size, attr_offset, attrs_size, data_offset, data_size = header[2:7]
    if attr_size != attrs_size or attr_size < 112:
        raise ValueError("Exact matching requires one Simpleperf event attribute")
    if attr_offset < 104 or attr_offset + attrs_size > len(data):
        raise ValueError("Invalid Simpleperf attribute bounds")
    event_type, size, config, period, sample_type, _, flags = unpack(
        "<IIQQQQQ", attr_offset, attr_offset + attr_size
    )
    # IP | TID | TIME | CALLCHAIN | ID | CPU | PERIOD; no address field.
    if (
        event_type != 1
        or config != 6
        or period != 1
        or sample_type != 0x1E7
        or size < 96
        or size + 16 > attr_size
        or flags & ((1 << 4) | (1 << 10))  # exclude_user or frequency sampling
        or not flags & (1 << 5)  # require userspace-only event
        or not flags & (1 << 25)  # use_clockid
        or unpack("<i", attr_offset + 92)[0] != 7  # CLOCK_BOOTTIME
    ):
        raise ValueError("Unsupported event, sample layout, period, or clock")
    if data_offset < attr_offset + attrs_size or data_offset + data_size > len(data):
        raise ValueError("Invalid Simpleperf data bounds")
    ids_offset, ids_size = unpack("<QQ", attr_offset + attr_size - 16)
    if (
        ids_offset < 104
        or not ids_size
        or ids_size % 8
        or ids_offset + ids_size > len(data)
    ):
        raise ValueError("Invalid Simpleperf event ID bounds")
    event_ids = set(unpack(f"<{ids_size // 8}Q", ids_offset))
    samples = []
    position, end = data_offset, data_offset + data_size
    while position < end:
        record_type, misc, record_size = unpack("<IHH", position, end)
        record_end = position + record_size
        if record_size < 8 or record_end > end:
            raise ValueError("Invalid Simpleperf record bounds")
        if record_type in {2, 5, 13}:  # LOST, THROTTLE, LOST_SAMPLES
            raise ValueError("Simpleperf stream contains loss or throttling records")
        if record_type == 9:  # PERF_RECORD_SAMPLE
            ip, pid, tid, timestamp, event_id, cpu, _, period, frame_count = unpack(
                "<QIIQQIIQQ", position + 8, record_end
            )
            if (
                record_size != 64 + frame_count * 8
                or misc & 7 != 2  # PERF_RECORD_MISC_USER
                or period != 1
                or event_id not in event_ids
            ):
                raise ValueError("Invalid Simpleperf sample payload or mode")
            samples.append(
                {
                    "pid": pid,
                    "tid": tid,
                    "timestamp_ns": timestamp,
                    "ip": ip,
                    "cpu": cpu,
                    "frame_count": frame_count,
                }
            )
        position = record_end
    return samples


def exact_dwarf_matches(path: Path, metadata: dict) -> dict:
    """Return verified native-sequence -> DWARF stack matches, never nearest time.

    Missing evidence disables enrichment, not the independent captured streams.
    Ambiguity is checked on entire saved streams before startup filtering. Both
    the fault address and file mapping remain exclusively native-collector data.
    """
    result = {"matches": {}, "coverage": {}, "warnings": []}
    if metadata.get("simpleperf_status") != "complete":
        return result
    try:
        companion = json.loads((path / "simpleperf-metadata.json").read_text())
        binding = companion.get("capture_binding", {})
        if (
            not metadata.get("boot_id")
            or binding.get("boot_id_start") != metadata["boot_id"]
            or binding.get("boot_id_end") != metadata["boot_id"]
            or not metadata.get("collector_start_ns")
            or binding.get("collector_start_ns") != metadata["collector_start_ns"]
            or not metadata.get("serial")
            or binding.get("serial") != metadata["serial"]
        ):
            raise ValueError("No verified same-boot recorder binding")
        if (
            metadata.get("collector_clock") != "boottime"
            or companion.get("clock") != "boottime"
            or companion.get("target_pid") != metadata.get("pid")
            or companion.get("integrity_passed") is not True
            or companion.get("return_code") != 0
            or companion.get("samples_lost") != 0
            or companion.get("joiner") is not False
            or companion.get("gap_removal") is not False
            or metadata.get("collector") != "perf-software-page-fault-events"
            or metadata.get("capture_status") != "collected"
            or any(
                metadata.get("collector_" + key, 0) != 0
                for key in ("lost", "integrity_errors", "throttled", "return_code")
            )
        ):
            raise ValueError("Capture event, clock, identity, or integrity mismatch")
        artifacts = {}
        for name in ("simpleperf.data", "simpleperf-stacks.txt"):
            artifacts[name] = (path / name).read_bytes()
            if hashlib.sha256(artifacts[name]).hexdigest() != binding.get(
                "artifacts_sha256", {}
            ).get(name):
                raise ValueError(f"Capture binding hash mismatch: {name}")
        raw_samples = read_perf_sample_identities(artifacts["simpleperf.data"])
        if len(raw_samples) != companion.get("samples_recorded"):
            raise ValueError("Raw Simpleperf sample count differs from recorder")
        symbolized = parse_samples(artifacts["simpleperf-stacks.txt"].decode())
        with (path / "fault_events.csv").open() as file:
            native = [
                {
                    **row,
                    **{
                        key: int(row[key], 0)
                        for key in (
                            "timestamp_ns",
                            "pid",
                            "tid",
                            "ip",
                            "address",
                            "cpu",
                        )
                    },
                }
                for row in csv.DictReader(file)
            ]
        pid = metadata["pid"]
        native_by_key, raw_by_key, symbols_by_key = (
            defaultdict(list) for _ in range(3)
        )
        for row in native:
            native_by_key[(row["pid"], row["tid"], row["timestamp_ns"])].append(row)
        for row in raw_samples:
            raw_by_key[(row["pid"], row["tid"], row["timestamp_ns"])].append(row)
        for row in symbolized:
            symbols_by_key[(pid, row["thread_id"], row["time"])].append(row)

        start, end = metadata["startup"]["ts"], metadata["startup"]["ts_end"]
        selected = [
            row
            for row in native
            if row["pid"] == pid and start <= row["timestamp_ns"] < end
        ]
        with (path / "all_faults.csv").open() as file:
            processed = list(csv.DictReader(file))
        if len(selected) != len(processed):
            raise ValueError("Processed faults differ from native startup stream")
        for sequence, (row, processed_row) in enumerate(zip(selected, processed)):
            if (
                int(processed_row["sequence"]) != sequence
                or int(processed_row["ts"]) != row["timestamp_ns"]
                or processed_row["event_type"] != row["event_type"]
                or any(
                    int(processed_row[key]) != row[key]
                    for key in ("tid", "ip", "address")
                )
            ):
                raise ValueError("Processed fault identity differs from native record")

        verified = {}
        ambiguous = 0
        for key, raw_rows in raw_by_key.items():
            if key[0] != pid:
                continue
            native_rows, symbols = native_by_key[key], symbols_by_key[key]
            if len(raw_rows) > 1 or len(native_rows) > 1 or len(symbols) > 1:
                ambiguous += 1
                continue
            if len(native_rows) != 1 or len(symbols) != 1:
                continue
            raw, row, sample = raw_rows[0], native_rows[0], symbols[0]
            if (
                row["event_type"] == "major"
                and raw["ip"] == row["ip"]
                and raw["cpu"] == row["cpu"]
                and raw["frame_count"]
                and sample["stack"]
            ):
                verified[key] = (raw, sample)
        for sequence, row in enumerate(selected):
            key = (row["pid"], row["tid"], row["timestamp_ns"])
            if key not in verified:
                continue
            raw, sample = verified[key]
            result["matches"][sequence] = {
                "stack": [
                    {
                        **frame,
                        "kind": "user",
                        "app": is_app_owned_path(frame["file"], metadata["package"]),
                        "unresolved": frame["label"] in {"Unresolved", "[unknown]"},
                    }
                    for frame in sample["stack"]
                ],
                "provenance": {
                    "stream": "Simpleperf DWARF",
                    "match": "Exact PID, TID, CLOCK_BOOTTIME timestamp, runtime IP, CPU; period 1 major event",
                    "timestamp_ns": raw["timestamp_ns"],
                    "ip": hex(raw["ip"]),
                    "cpu": raw["cpu"],
                    "boot_id": metadata["boot_id"],
                    "address_source": "Native fault event; not recorded by Simpleperf",
                },
            }
        startup_majors = sum(row["event_type"] == "major" for row in selected)
        raw_target = sum(row["pid"] == pid for row in raw_samples)
        result["coverage"] = {
            "startup_major_faults": startup_majors,
            "matched_startup_major_faults": len(result["matches"]),
            "unmatched_startup_major_faults": startup_majors - len(result["matches"]),
            "raw_target_samples": raw_target,
            "matched_target_samples": len(verified),
            "unmatched_target_samples": raw_target - len(verified),
            "ambiguous_target_keys": ambiguous,
        }
    except (OSError, ValueError, KeyError, TypeError, struct.error) as error:
        result["matches"] = {}
        result["warnings"].append(f"DWARF enrichment unavailable: {error}.")
    return result


def report_run(path: Path, metadata: dict) -> dict | None:
    """Keep the original DWARF stream visible, including unmatched samples."""
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
        if startup["ts"] <= s["time"] < startup["ts_end"]
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
            "Simpleperf does not record the faulted address here. Binaries in this view are stack instruction sources, not read-file attribution. The exact-fault view uses these stacks only when raw event identity and capture provenance match uniquely; never by nearest timestamp or ordinal.",
            "Recording two collectors adds overhead. Compare timing only between equivalently instrumented runs.",
        ],
        "provenance": integrity,
    }
