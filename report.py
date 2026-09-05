"""Build an offline Android fault report from verified capture artifacts."""

import argparse
import csv
import json
from collections import defaultdict
from pathlib import Path

from plotly.offline import get_plotlyjs

from android_fault_visualizer.artifacts import is_app_owned_path
from fault_report import write_report


def read_csv(path: Path) -> list[dict[str, str]]:
    if not path.exists():
        return []
    with path.open() as file:
        return list(csv.DictReader(file))


def app_relative_path(path: str, package: str) -> str:
    marker = f"/{package}-"
    if path.startswith("/data/app/") and marker in path:
        return path.split(marker, 1)[1].split("/", 1)[-1]
    return path


def validate_metadata(metadata: dict) -> None:
    if (
        metadata.get("schema_version") != 5
        or metadata.get("capture_status") != "collected"
    ):
        raise ValueError("Report requires a completed exact capture (schema 5)")
    for name in (
        "lost",
        "integrity_errors",
        "throttled",
        "callchain_overflow",
        "return_code",
    ):
        if int(metadata.get("collector_" + name, 0)):
            raise ValueError(f"Collector integrity check failed: {name}")
    if int(metadata.get("page_size", 0)) <= 0:
        raise ValueError("Capture page size is missing")


def report_run(path: Path, label: str | None = None) -> dict:
    metadata = json.loads((path / "capture_metadata.json").read_text())
    validate_metadata(metadata)
    package, page_size = metadata["package"], int(metadata["page_size"])
    if not (path / "all_faults.csv").is_file():
        raise ValueError(
            "Processed all_faults.csv is missing; reprocess the capture first"
        )
    raw = read_csv(path / "all_faults.csv")
    expected = metadata.get("results", {}).get("all_faults")
    if not isinstance(expected, int) or len(raw) != expected:
        raise ValueError("Fault CSV count differs from capture metadata")
    chains = defaultdict(list)
    for row in read_csv(path / "resolved_fault_callchains.csv"):
        if row["frame_kind"] != "user":
            continue
        chains[int(row["sequence"])].append(
            (
                int(row["frame_index"]),
                {
                    "label": row["label"],
                    "file": row["file_name"],
                    "app": is_app_owned_path(row["file_name"], package),
                    "unresolved": not row["file_name"] or row["label"].startswith("0x"),
                },
            )
        )
    detail_path = path / "fault_details.json"
    details = (
        {int(r["sequence"]): r for r in json.loads(detail_path.read_text())}
        if detail_path.exists()
        else {}
    )
    sources, events = {}, []
    for row in raw:
        if row["event_type"] not in {"major", "minor"}:
            raise ValueError("Unknown fault type in all_faults.csv")
        seq = int(row["sequence"])
        file_name = row["file_name"] or "Unattributed memory"
        source = file_name  # VDEX is always a whole file, including shared data.
        sources.setdefault(
            source,
            {
                "path": file_name,
                "label": app_relative_path(file_name, package),
                "app": is_app_owned_path(file_name, package),
                "mapped": bool(row["file_name"] and row["offset"]),
                "boundaries": [],
            },
        )
        offset = int(row["offset"]) if row["offset"] else None
        detail = details.get(seq, {})
        events.append(
            {
                "id": seq,
                "time": float(row["elapsed_ms"]),
                "major": row["event_type"] == "major",
                "address": hex(int(row["address"])),
                "source": source,
                "page": offset // page_size if offset is not None else None,
                "offset": offset,
                "thread": f"{row.get('thread_name') or 'unnamed'} ({row['tid']})",
                "stack": [f for _, f in sorted(chains[seq], key=lambda pair: pair[0])],
                "detail": {
                    "section": detail.get("section", ""),
                    "dex": detail.get("dex") or row.get("zip_entry_name", ""),
                    "DEX methods on this page (content, not callers)": "; ".join(
                        detail.get("page_methods", [])
                    ),
                },
            }
        )
    for b in read_csv(path / "vdex_dex_boundaries.csv"):
        if (
            b["file_name"] in sources
            and b.get("identity_verified", "").lower() == "true"
        ):
            sources[b["file_name"]]["boundaries"].append(
                {"page": int(b["start_offset"]) / page_size, "label": b["dex_name"]}
            )
    if len({e["id"] for e in events}) != len(events):
        raise ValueError("Duplicate fault sequence identifiers")
    events.sort(key=lambda e: (e["time"], e["id"]))
    cache = metadata.get("cache_verification", {})
    count, files = cache.get("resident_pages"), cache.get("files_checked", 0)
    cache_text = (
        f"Pre-launch cache: {count} resident pages across {files} checked app files."
        if count is not None and files
        else "Pre-launch cache: not verified in this capture."
    )
    if count:
        cache_text += " Partially warm; not a fully cold capture."
    notes = [
        "Major/minor are emitted Linux perf software fault events, not syscall events. Some kernel-accounted faults do not emit userspace perf samples; process counters can differ.",
        "Minor faults do not necessarily mean a file-cache hit: anonymous allocation and copy-on-write also fault minor.",
        "The read source is mapped from the fault address at the event timestamp. Native stacks are captured in that same event. Monitoring starts before app launch; unwinding can stop at ART or omitted frame pointers.",
        "DEX method labels describe instructions stored on the faulted file page, not proof those methods executed or triggered the fault. Compressed DEX and CompactDex method ranges are not decoded.",
        "VDEX identity is named only after the complete ART location-checksum list matches the APK DEX entries. VDEX files without embedded DEX cannot expose DEX payload boundaries.",
        "Cache insertions include app threads and workers touching exact app-owned device/inode pairs. They correlate with reads/readahead; they do not establish which fault caused an insertion.",
        "Code-layout changes need repeated, equally prepared captures of the same startup. R8 DEX order and ART-compiled OAT layout are different layers.",
        *metadata.get("warnings", []),
    ]
    return {
        "label": label or path.name,
        "subtitle": f"Android {metadata.get('release','')} · {package} · PID {metadata.get('pid')} · startup {metadata.get('startup',{}).get('duration_ns',0)/1e6:.1f} ms",
        "pageSize": page_size,
        "events": events,
        "sources": sources,
        "cache": cache_text,
        "notes": notes,
        "provenance": metadata,
    }


def build_report(
    path: Path,
    output: Path,
    compare: Path | None = None,
    *,
    label: str | None = None,
    compare_label: str | None = None,
    allow_incomparable: bool = False,
) -> None:
    runs = [report_run(path, label)]
    if compare:
        runs.append(report_run(compare, compare_label))
        a, b = (r["provenance"] for r in runs)
        if a["package"] != b["package"] or a["page_size"] != b["page_size"]:
            raise ValueError("Compare captures of the same package and page size")
        changed = [
            k
            for k in (
                "activity",
                "serial",
                "build_fingerprint",
                "abi",
                "kernel",
                "collector_source_sha256",
                "collector_binary_sha256",
                "trace_config_sha256",
                "ndk",
                "compiler",
                "cache_procedure",
                "cache_max_resident_pages",
                "reboot_before_collect",
                "capture_native_callchains",
                "simpleperf_status",
            )
            if a.get(k) != b.get(k)
        ]
        if changed and not allow_incomparable:
            raise ValueError(
                "Comparison settings differ: "
                + ", ".join(changed)
                + ". Use --allow-incomparable only for exploratory comparisons."
            )
        for r in runs:
            r["notes"].append(
                "Comparison runs are separately selectable. Changed capture settings: "
                + (", ".join(changed) or "none")
                + "."
            )
            if changed:
                r["cache"] += " Comparison settings differ: " + ", ".join(changed) + "."
    from android_fault_visualizer.simpleperf import report_run as dwarf_run

    for capture_path, exact_run in [(path, runs[0])] + (
        [(compare, runs[1])] if compare else []
    ):
        if exact_run["provenance"].get("simpleperf_status") == "complete":
            companion = dwarf_run(capture_path, exact_run["provenance"])
            if companion is not None:
                runs.append(companion)
    write_report(
        {"title": runs[0]["provenance"]["package"] + " · startup faults", "runs": runs},
        output,
        get_plotlyjs(),
    )


def main() -> None:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("capture", type=Path)
    p.add_argument("--output", type=Path)
    p.add_argument("--compare", type=Path)
    p.add_argument("--label")
    p.add_argument("--compare-label")
    p.add_argument("--allow-incomparable", action="store_true")
    a = p.parse_args()
    output = a.output or a.capture / "report.html"
    build_report(
        a.capture,
        output,
        a.compare,
        label=a.label,
        compare_label=a.compare_label,
        allow_incomparable=a.allow_incomparable,
    )
    print(output.resolve())


if __name__ == "__main__":
    main()
