import csv
import io
import json
import re
import subprocess
from collections import defaultdict, deque
from pathlib import Path
from typing import Optional

from android_fault_visualizer.paths import (
    TRACE_PROCESSOR,
)
from android_fault_visualizer.artifacts import (
    MapEntry,
    ZipEntry,
    MappingEvent,
    VdexAnalysis,
    sql_string,
    parse_maps,
    parse_mapping_events,
    find_map_entry_at,
    read_zip_entries,
    read_vdex,
    read_apk_dex_identities,
    find_zip_entry,
)


def run_trace_query(trace: Path, query: str) -> list[dict[str, str]]:
    result = subprocess.run(
        [str(TRACE_PROCESSOR), "-Q", query, str(trace)],
        capture_output=True,
        text=True,
        check=True,
    )
    return list(csv.DictReader(io.StringIO(result.stdout.lstrip())))


def query_startup(trace: Path, package: str) -> dict[str, str]:
    rows = run_trace_query(
        trace,
        f"""
        INCLUDE PERFETTO MODULE android.startup.startups;
        SELECT startup_id, ts, ts_end, dur, package, startup_type
        FROM android_startups
        WHERE package = {sql_string(package)}
        ORDER BY ts;
        """,
    )
    if len(rows) != 1:
        raise RuntimeError(
            f"Expected exactly one startup for {package}, found {len(rows)}. "
            "Collect one cold launch per output directory."
        )
    return rows[0]


def query_trace_integrity(trace: Path) -> list[dict[str, str]]:
    return run_trace_query(
        trace,
        """
        SELECT name, severity, source, value
        FROM stats
        WHERE severity IN ('error', 'data_loss')
          AND value != 0
        ORDER BY name, source;
        """,
    )


def query_thread_names(trace: Path, pid: int) -> dict[int, str]:
    rows = run_trace_query(
        trace,
        f"""
        SELECT thread.tid, COALESCE(thread.name, '') AS thread_name
        FROM thread
        JOIN process USING (upid)
        WHERE process.pid = {pid}
        GROUP BY thread.tid
        ORDER BY thread.tid;
        """,
    )
    return {int(row["tid"]): row["thread_name"] for row in rows if row["tid"]}


def query_page_cache_events(
    trace: Path,
    pid: int,
    startup_start: int,
    startup_end: int,
    app_inode_keys: set[tuple[int, int]],
) -> list[dict[str, str]]:
    inode_values = ",\n".join(
        f"({device}, {inode})" for device, inode in sorted(app_inode_keys)
    )
    if not inode_values:
        inode_values = "(-1, -1)"
    return run_trace_query(
        trace,
        f"""
        WITH
          app_inodes(sdev, inode) AS (
            VALUES {inode_values}
          ),
          cache_events AS (
            SELECT
              ftrace_event.ts,
              ftrace_event.utid,
              EXTRACT_ARG(ftrace_event.arg_set_id, 's_dev') AS sdev,
              EXTRACT_ARG(ftrace_event.arg_set_id, 'i_ino') AS inode,
              EXTRACT_ARG(ftrace_event.arg_set_id, 'index') AS page_index,
              COALESCE(EXTRACT_ARG(ftrace_event.arg_set_id, 'order'), 0)
                AS page_order
            FROM ftrace_event
            WHERE ftrace_event.name = 'mm_filemap_add_to_page_cache'
              AND ftrace_event.ts >= {startup_start}
              AND ftrace_event.ts < {startup_end}
          )
        SELECT
          cache_events.ts,
          COALESCE(process.name, '[kernel worker]') AS process_name,
          CASE
            WHEN thread.name IS NOT NULL THEN thread.name
            WHEN process.pid IS NULL THEN '[kernel worker]'
            ELSE '[unnamed thread]'
          END AS thread_name,
          COALESCE(thread.tid, 0) AS tid,
          cache_events.sdev,
          cache_events.inode,
          cache_events.page_index,
          cache_events.page_order
        FROM cache_events
        LEFT JOIN thread USING (utid)
        LEFT JOIN process USING (upid)
        WHERE process.pid = {pid}
           OR EXISTS (
             SELECT 1
             FROM app_inodes
             WHERE app_inodes.sdev = cache_events.sdev
               AND app_inodes.inode = cache_events.inode
           )
        ORDER BY cache_events.ts;
        """,
    )


def parse_inode_mapping(output_dir: Path, map_entries: list[MapEntry]) -> tuple[
    dict[tuple[int, int], str],
    dict[str, int],
    set[tuple[int, int]],
]:
    inode_paths: dict[tuple[int, int], str] = {}
    file_sizes: dict[str, int] = {}
    app_inode_keys: set[tuple[int, int]] = set()
    for entry in map_entries:
        if entry.inode and entry.file_name and not entry.file_name.startswith("["):
            inode_paths[(entry.device, entry.inode)] = entry.file_name
            file_sizes[entry.file_name] = max(
                file_sizes.get(entry.file_name, 0),
                entry.file_offset + (entry.end_address - entry.begin_address),
            )

    inode_path = output_dir / "inodes.txt"
    if inode_path.exists():
        for line in inode_path.read_text().splitlines():
            columns = line.split("|", 3)
            if len(columns) != 4:
                continue
            device, inode, size, file_name = columns
            key = (int(device), int(inode))
            inode_paths.setdefault(key, file_name)
            file_sizes[file_name] = int(size)
            app_inode_keys.add(key)
    return inode_paths, file_sizes, app_inode_keys


def load_artifacts(output_dir: Path) -> dict[str, Path]:
    path = output_dir / "artifacts.json"
    if not path.exists():
        return {}
    return {
        remote: output_dir / local
        for remote, local in json.loads(path.read_text()).items()
    }


IMAGE_SUFFIXES = (
    ".avif",
    ".gif",
    ".heic",
    ".jpeg",
    ".jpg",
    ".png",
    ".svg",
    ".webp",
)


def classify_source(file_name: Optional[str], zip_entry: Optional[str]) -> str:
    target = (zip_entry or file_name or "").lower()
    if zip_entry:
        if target.endswith(IMAGE_SUFFIXES):
            return "image"
        if re.search(r"(?:^|[/ ·])classes\d*\.dex(?:\s|$)", target) or (
            "compactdex data" in target
        ):
            return "dex"
        if target.endswith(".so"):
            return "native_code"
        if target == "resources.arsc" or target.startswith("res/"):
            return "resources"
        if target.startswith("assets/"):
            return "asset"
        if target.startswith("meta-inf/"):
            return "metadata"
        return "apk_other"
    if target.endswith((".odex", ".oat")):
        return "compiled_code"
    if target.endswith(".art"):
        return "art_image"
    if target.endswith((".vdex", ".dex")):
        return "dex"
    if target.endswith(".so"):
        return "native_code"
    if target.endswith(IMAGE_SUFFIXES):
        return "image"
    if target.endswith(".apk"):
        return "apk_container"
    if not file_name or file_name.startswith("["):
        return "anonymous"
    if file_name.startswith(("/system/", "/apex/", "/vendor/", "/product/")):
        return "system"
    return "other_file"


def write_fault_csvs(
    output_dir: Path,
    metadata: dict[str, object],
    startup: dict[str, str],
    map_entries: list[MapEntry],
    mapping_events: list[MappingEvent],
    zip_entries: dict[str, list[ZipEntry]],
    thread_names: dict[int, str],
) -> tuple[list[dict[str, object]], list[dict[str, object]]]:
    pid = int(metadata["pid"])
    page_size = int(metadata["page_size"])
    startup_start = int(startup["ts"])
    startup_end = int(startup["ts_end"])
    raw_rows = []
    with (output_dir / "fault_events.csv").open() as file:
        for row in csv.DictReader(file):
            if int(row["pid"]) != pid:
                continue
            timestamp = int(row["timestamp_ns"])
            if not startup_start <= timestamp < startup_end:
                continue
            raw_rows.append(row)

    all_faults = []
    mapped_faults = []
    for sequence, row in enumerate(raw_rows):
        timestamp = int(row["timestamp_ns"])
        tid = int(row["tid"])
        address = int(row["address"], 16)
        ip = int(row["ip"], 16)
        map_entry = find_map_entry_at(map_entries, mapping_events, address, timestamp)
        file_name = None
        file_offset = None
        mapping_kind = "unmapped"
        zip_entry = None
        zip_offset = None
        if map_entry is not None:
            if (
                map_entry.inode
                and map_entry.file_name
                and not map_entry.file_name.startswith(("[", "/dev/", "/memfd:"))
            ):
                mapping_kind = "file"
                file_name = map_entry.file_name.removesuffix(" (deleted)")
                file_offset = map_entry.file_offset + address - map_entry.begin_address
                if file_name in zip_entries:
                    zip_entry = find_zip_entry(zip_entries[file_name], file_offset)
                    if zip_entry:
                        zip_offset = file_offset - zip_entry.data_offset
            else:
                mapping_kind = "anonymous"
                file_name = map_entry.file_name

        fault = {
            "ts": timestamp,
            "elapsed_ms": (timestamp - startup_start) / 1_000_000,
            "sequence": sequence,
            "process_name": metadata["package"],
            "thread_name": thread_names.get(tid, ""),
            "tid": tid,
            "address": address,
            "ip": ip,
            "event_type": row["event_type"],
            "is_major": row["event_type"] == "major",
            "mapping_kind": mapping_kind,
            "file_name": file_name,
            "zip_entry_name": zip_entry.file_name if zip_entry else None,
            "offset": file_offset,
            "page_index": (
                file_offset // page_size if file_offset is not None else None
            ),
            "zip_entry_offset": zip_offset,
            "category": classify_source(
                file_name, zip_entry.file_name if zip_entry else None
            ),
        }
        all_faults.append(fault)
        if mapping_kind == "file":
            mapped_faults.append(fault)

    raw_fields = [
        "ts",
        "process_name",
        "thread_name",
        "address",
        "ip",
        "event_type",
        "tid",
        "is_major",
    ]
    with (output_dir / "faults.csv").open("w", newline="") as file:
        writer = csv.DictWriter(file, fieldnames=raw_fields)
        writer.writeheader()
        for row in all_faults:
            writer.writerow({field: row[field] for field in raw_fields})

    fields = [
        "ts",
        "process_name",
        "thread_name",
        "file_name",
        "zip_entry_name",
        "offset",
        "is_major",
        "event_type",
        "elapsed_ms",
        "sequence",
        "tid",
        "address",
        "ip",
        "mapping_kind",
        "page_index",
        "zip_entry_offset",
        "category",
    ]
    for name, rows in [
        ("all_faults.csv", all_faults),
        ("mapped_faults.csv", mapped_faults),
    ]:
        with (output_dir / name).open("w", newline="") as file:
            writer = csv.DictWriter(file, fieldnames=fields)
            writer.writeheader()
            writer.writerows(rows)
    return all_faults, mapped_faults


PERF_CONTEXT_NAMES = {
    0xFFFFFFFFFFFFFFE0: "hypervisor",
    0xFFFFFFFFFFFFFF80: "kernel",
    0xFFFFFFFFFFFFFE00: "user",
    0xFFFFFFFFFFFFF800: "guest",
    0xFFFFFFFFFFFFF780: "guest_kernel",
    0xFFFFFFFFFFFFF600: "guest_user",
}


def write_fault_callchains(
    output_dir: Path,
    pid: int,
    abi: str,
    all_faults: list[dict[str, object]],
    map_entries: list[MapEntry],
    mapping_events: list[MappingEvent],
) -> dict[str, int]:
    source = output_dir / "fault_callchains.csv"
    output = output_dir / "resolved_fault_callchains.csv"
    fields = [
        "sequence",
        "ts",
        "elapsed_ms",
        "event_type",
        "is_major",
        "tid",
        "fault_address",
        "fault_file_name",
        "fault_offset",
        "frame_index",
        "frame_kind",
        "raw_ip",
        "ip",
        "file_name",
        "file_offset",
        "label",
    ]
    if not source.exists():
        output.unlink(missing_ok=True)
        return {
            "faults_with_callchains": 0,
            "callchain_frames": 0,
            "resolved_user_frames": 0,
            "unresolved_user_frames": 0,
        }

    raw_chains: dict[int, list[int]] = defaultdict(list)
    raw_fault_keys: dict[int, tuple[int, int, int, int, str]] = {}
    with source.open() as file:
        for row in csv.DictReader(file):
            row_pid = int(row["pid"])
            if row_pid != pid:
                continue
            raw_index = int(row["fault_index"])
            raw_chains.setdefault(raw_index, [])
            ip = int(row["ip"], 16)
            if ip != 0:
                raw_chains[raw_index].append(ip)
            raw_fault_keys[raw_index] = (
                row_pid,
                int(row["timestamp_ns"]),
                int(row["tid"]),
                int(row["address"], 16),
                row["event_type"],
            )

    chains_by_key: dict[tuple[int, int, int, int, str], deque[list[int]]] = defaultdict(
        deque
    )
    for raw_index, chain in raw_chains.items():
        chains_by_key[raw_fault_keys[raw_index]].append(chain)

    rows: list[dict[str, object]] = []
    faults_with_callchains = 0
    resolved_user_frames = 0
    unresolved_user_frames = 0
    for fault in all_faults:
        key = (
            pid,
            int(fault["ts"]),
            int(fault["tid"]),
            int(fault["address"]),
            str(fault["event_type"]),
        )
        candidates = chains_by_key.get(key)
        if not candidates:
            raise RuntimeError(
                "Missing exact native callchain for startup fault "
                f"sequence={fault['sequence']} ts={fault['ts']} tid={fault['tid']} "
                f"address=0x{int(fault['address']):x} event={fault['event_type']}"
            )
        chain = candidates.popleft()
        if any(ip not in PERF_CONTEXT_NAMES for ip in chain):
            faults_with_callchains += 1
        context = "unknown"
        context_frame_index = 0
        for frame_index, raw_ip in enumerate(chain):
            context_name = PERF_CONTEXT_NAMES.get(raw_ip)
            if context_name is not None:
                context = context_name
                context_frame_index = 0
                continue
            adjustment = 0
            if context_frame_index > 0:
                adjustment = 2 if abi in {"arm64-v8a", "armeabi-v7a"} else 1
            normalized_ip = (
                raw_ip & 0x00FFFFFFFFFFFFFF
                if abi == "arm64-v8a" and context == "user"
                else raw_ip
            )
            ip = max(0, normalized_ip - adjustment)
            context_frame_index += 1
            file_name = None
            file_offset = None
            if context == "user":
                mapping = find_map_entry_at(
                    map_entries,
                    mapping_events,
                    ip,
                    int(fault["ts"]),
                )
                if mapping is not None:
                    file_name = (
                        mapping.file_name.removesuffix(" (deleted)")
                        if mapping.file_name
                        else None
                    )
                    if file_name is not None:
                        file_offset = mapping.file_offset + ip - mapping.begin_address
                        resolved_user_frames += 1
                    else:
                        unresolved_user_frames += 1
                else:
                    unresolved_user_frames += 1
            label = (
                f"{Path(file_name).name}+0x{file_offset:x}"
                if file_name and file_offset is not None
                else (f"[kernel]+0x{ip:x}" if context == "kernel" else f"0x{ip:x}")
            )
            rows.append(
                {
                    "sequence": fault["sequence"],
                    "ts": fault["ts"],
                    "elapsed_ms": fault["elapsed_ms"],
                    "event_type": fault["event_type"],
                    "is_major": fault["is_major"],
                    "tid": fault["tid"],
                    "fault_address": fault["address"],
                    "fault_file_name": fault["file_name"],
                    "fault_offset": fault["offset"],
                    "frame_index": frame_index,
                    "frame_kind": context,
                    "raw_ip": raw_ip,
                    "ip": ip,
                    "file_name": file_name,
                    "file_offset": file_offset,
                    "label": label,
                }
            )

    with output.open("w", newline="") as file:
        writer = csv.DictWriter(file, fieldnames=fields)
        writer.writeheader()
        writer.writerows(rows)
    return {
        "faults_with_callchains": faults_with_callchains,
        "faults_without_callchains": len(all_faults) - faults_with_callchains,
        "callchain_frames": len(rows),
        "resolved_user_frames": resolved_user_frames,
        "unresolved_user_frames": unresolved_user_frames,
    }


def write_page_cache_events(
    output_dir: Path,
    trace: Path,
    metadata: dict[str, object],
    startup: dict[str, str],
    inode_paths: dict[tuple[int, int], str],
    app_inode_keys: set[tuple[int, int]],
    zip_entries: dict[str, list[ZipEntry]],
) -> list[dict[str, object]]:
    page_size = int(metadata["page_size"])
    rows = query_page_cache_events(
        trace,
        int(metadata["pid"]),
        int(startup["ts"]),
        int(startup["ts_end"]),
        app_inode_keys,
    )
    events = []
    for row in rows:
        key = (int(row["sdev"]), int(row["inode"]))
        file_name = inode_paths.get(key)
        page_index = int(row["page_index"])
        file_offset = page_index * page_size
        zip_entry = (
            find_zip_entry(zip_entries.get(file_name, []), file_offset)
            if file_name
            else None
        )
        events.append(
            {
                "ts": int(row["ts"]),
                "elapsed_ms": (int(row["ts"]) - int(startup["ts"])) / 1_000_000,
                "process_name": row["process_name"],
                "thread_name": row["thread_name"],
                "tid": int(row["tid"]),
                "device": key[0],
                "inode": key[1],
                "file_name": file_name,
                "zip_entry_name": zip_entry.file_name if zip_entry else None,
                "offset": file_offset,
                "page_index": page_index,
                "page_order": int(row["page_order"]),
                "page_count": 1 << int(row["page_order"]),
                "category": classify_source(
                    file_name, zip_entry.file_name if zip_entry else None
                ),
            }
        )
    fields = (
        list(events[0].keys())
        if events
        else [
            "ts",
            "elapsed_ms",
            "process_name",
            "thread_name",
            "tid",
            "device",
            "inode",
            "file_name",
            "zip_entry_name",
            "offset",
            "page_index",
            "page_order",
            "page_count",
            "category",
        ]
    )
    with (output_dir / "page_cache_events.csv").open("w", newline="") as file:
        writer = csv.DictWriter(file, fieldnames=fields)
        writer.writeheader()
        writer.writerows(events)
    return events


def write_vdex_analysis(
    output_dir: Path,
    analyses: dict[str, VdexAnalysis],
    page_size: int,
) -> list[dict[str, object]]:
    fields = [
        "file_name",
        "dex_name",
        "start_offset",
        "page_index",
        "checksum",
        "format_version",
        "identity_verified",
    ]
    rows: list[dict[str, object]] = []
    for file_name, analysis in sorted(analyses.items()):
        if not analysis.identities_verified:
            continue
        for index, dex_range in enumerate(analysis.dex_ranges):
            rows.append(
                {
                    "file_name": file_name,
                    "dex_name": dex_range.file_name,
                    "start_offset": dex_range.data_offset,
                    "page_index": dex_range.data_offset // page_size,
                    "checksum": f"0x{analysis.stored_checksums[index]:08x}",
                    "format_version": analysis.format_version,
                    "identity_verified": True,
                }
            )
    with (output_dir / "vdex_dex_boundaries.csv").open("w", newline="") as file:
        writer = csv.DictWriter(file, fieldnames=fields)
        writer.writeheader()
        writer.writerows(rows)
    return rows


def write_file_sizes(
    output_dir: Path,
    file_sizes: dict[str, int],
    zip_entries: dict[str, list[ZipEntry]],
) -> None:
    fields = [
        "file_name",
        "zip_entry_name",
        "size",
        "file_offset",
        "uncompressed_size",
        "data_end",
        "compression",
    ]
    with (output_dir / "file_sizes.csv").open("w", newline="") as file:
        writer = csv.DictWriter(file, fieldnames=fields)
        writer.writeheader()
        for file_name in sorted(file_sizes):
            writer.writerow(
                {
                    "file_name": file_name,
                    "zip_entry_name": None,
                    "size": file_sizes[file_name],
                    "file_offset": 0,
                    "uncompressed_size": file_sizes[file_name],
                    "data_end": file_sizes[file_name],
                    "compression": "file",
                }
            )
            for entry in zip_entries.get(file_name, []):
                writer.writerow(
                    {
                        "file_name": file_name,
                        "zip_entry_name": entry.file_name,
                        "size": entry.compressed_size,
                        "file_offset": entry.data_offset,
                        "uncompressed_size": entry.uncompressed_size,
                        "data_end": entry.data_end,
                        "compression": entry.compression,
                    }
                )


def process_capture(output_dir: Path) -> None:
    metadata_path = output_dir / "capture_metadata.json"
    if not metadata_path.exists():
        raise RuntimeError(
            "This output predates the exact perf-event collector. Recollect it; "
            "legacy page-cache events cannot be converted into true faults."
        )
    metadata = json.loads(metadata_path.read_text())
    if metadata.get("schema_version") != 5:
        raise RuntimeError(
            "This capture predates timestamped mapping attribution. "
            "Recollect it with the current collector."
        )
    if metadata.get("capture_status") != "collected":
        raise RuntimeError(
            "Capture is incomplete and cannot be processed: "
            f"capture_status={metadata.get('capture_status')!r}"
        )
    integrity_failures = {
        key: int(metadata.get(f"collector_{key}", 0))
        for key in ("lost", "integrity_errors", "throttled", "callchain_overflow")
    }
    if int(metadata.get("collector_return_code", 0)) != 0 or any(
        integrity_failures.values()
    ):
        raise RuntimeError(
            "Capture failed collector integrity checks and cannot be processed: "
            + ", ".join(f"{key}={value}" for key, value in integrity_failures.items())
        )
    trace = output_dir / "faults.pftrace"
    startup = query_startup(trace, str(metadata["package"]))
    trace_integrity = query_trace_integrity(trace)
    if trace_integrity:
        details = ", ".join(f"{row['name']}={row['value']}" for row in trace_integrity)
        raise RuntimeError(f"Perfetto reported trace integrity failures: {details}")
    metadata["trace_integrity"] = {"errors_or_data_loss": 0}
    metadata["startup"] = {
        "id": int(startup["startup_id"]),
        "ts": int(startup["ts"]),
        "ts_end": int(startup["ts_end"]),
        "duration_ns": int(startup["dur"]),
        "type": (
            None
            if startup["startup_type"] in ("", "[NULL]")
            else startup["startup_type"]
        ),
    }

    map_entries = parse_maps(output_dir)
    mapping_events = parse_mapping_events(output_dir, int(metadata["pid"]))
    inode_paths, file_sizes, app_inode_keys = parse_inode_mapping(
        output_dir, map_entries
    )
    artifacts = load_artifacts(output_dir)
    file_sections = {
        remote_path: read_zip_entries(local_path)
        for remote_path, local_path in artifacts.items()
        if remote_path.endswith((".apk", ".jar", ".zip"))
    }
    apk_dex_identities: dict[str, list[tuple[str, int]]] = {
        remote_path: read_apk_dex_identities(artifacts[remote_path])
        for remote_path in file_sections
        if remote_path.endswith(".apk")
    }
    vdex_analyses: dict[str, VdexAnalysis] = {}
    for remote_path, local_path in artifacts.items():
        if not remote_path.endswith(".vdex"):
            continue
        parents = Path(remote_path).parents
        artifact_root = str(parents[2]) if len(parents) > 2 else ""
        apk_path = next(
            (
                candidate
                for candidate in apk_dex_identities
                if str(Path(candidate).parent) == artifact_root
                and Path(candidate).stem == Path(remote_path).stem
            ),
            None,
        )
        analysis = read_vdex(local_path, apk_dex_identities.get(apk_path))
        if analysis is not None:
            vdex_analyses[remote_path] = analysis
    metadata["vdex_files"] = [
        {
            "file_name": remote_path,
            "format_version": analysis.format_version,
            "stored_dex_checksums": [
                f"0x{checksum:08x}" for checksum in analysis.stored_checksums
            ],
            "embedded_dex_files": len(analysis.dex_ranges),
            "dex_identities_verified": analysis.identities_verified,
            "verification_note": analysis.verification_note,
        }
        for remote_path, analysis in sorted(vdex_analyses.items())
    ]
    write_vdex_analysis(output_dir, vdex_analyses, int(metadata["page_size"]))
    thread_names = query_thread_names(trace, int(metadata["pid"]))
    all_faults, mapped_faults = write_fault_csvs(
        output_dir,
        metadata,
        startup,
        map_entries,
        mapping_events,
        file_sections,
        thread_names,
    )
    callchain_results = write_fault_callchains(
        output_dir,
        int(metadata["pid"]),
        str(metadata["abi"]),
        all_faults,
        map_entries,
        mapping_events,
    )
    page_cache_events = write_page_cache_events(
        output_dir,
        trace,
        metadata,
        startup,
        inode_paths,
        app_inode_keys,
        file_sections,
    )
    write_file_sizes(output_dir, file_sizes, file_sections)

    from .binary import enrich_capture, symbolize_callchains
    from .device import find_ndk

    enrich_capture(output_dir, artifacts, int(metadata["page_size"]))
    try:
        symbolizer = next(
            (find_ndk() / "toolchains/llvm/prebuilt").glob("*/bin/llvm-symbolizer")
        )
        symbolize_callchains(output_dir, artifacts, symbolizer)
    except (RuntimeError, StopIteration, subprocess.SubprocessError) as error:
        metadata.setdefault("warnings", []).append(
            f"Native symbolization unavailable; raw frame offsets retained: {error}"
        )

    residency = list(csv.DictReader((output_dir / "cache_residency.csv").open()))
    before_launch = [row for row in residency if row["phase"] == "before_launch"]
    metadata["cache_verification"] = {
        "files_checked": len(before_launch),
        "resident_pages": sum(int(row["resident_pages"]) for row in before_launch),
        "total_pages": sum(int(row["total_pages"]) for row in before_launch),
        "fully_evicted_files": sum(
            int(row["resident_pages"]) == 0 for row in before_launch
        ),
    }
    metadata["results"] = {
        "all_faults": len(all_faults),
        "file_backed_faults": len(mapped_faults),
        "major_file_backed_faults": sum(bool(row["is_major"]) for row in mapped_faults),
        "minor_file_backed_faults": sum(
            not bool(row["is_major"]) for row in mapped_faults
        ),
        "page_cache_insertions": len(page_cache_events),
        **callchain_results,
    }
    metadata_path.write_text(json.dumps(metadata, indent=2, sort_keys=True) + "\n")
