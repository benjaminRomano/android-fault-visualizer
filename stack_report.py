#!/usr/bin/env python3
"""Build an interactive page-fault stack report from Simpleperf samples."""

import argparse
import re
from dataclasses import dataclass
from pathlib import Path


HEADER_PATTERN = re.compile(
    r"^(?P<thread>.*)\t(?P<pid>\d+)/(?P<tid>\d+) "
    r"\[(?P<cpu>\d+)\] (?P<time>\d+\.\d+): "
    r"(?P<period>\d+) (?P<event>minor|major)-faults:$"
)
FRAME_PATTERN = re.compile(r"^\s*(?P<ip>[0-9a-f]+) (?P<symbol>.+) \((?P<dso>.+)\)$")

RECORDING_SUMMARY_PATTERN = re.compile(
    r"Samples recorded:\s*(?P<recorded>[\d,]+)\.\s*"
    r"Samples lost:\s*(?P<lost>[\d,]+)\."
)


@dataclass(frozen=True)
class Frame:
    ip: int
    symbol: str
    dso: str


@dataclass(frozen=True)
class FaultStack:
    thread: str
    pid: int
    tid: int
    cpu: int
    timestamp_s: float
    period: int
    event_type: str
    frames: tuple[Frame, ...]  # Leaf first, then callers.


def parse_simpleperf_samples(path: Path) -> list[FaultStack]:
    samples: list[FaultStack] = []
    header: re.Match[str] | None = None
    frames: list[Frame] = []

    def finish_sample() -> None:
        nonlocal header, frames
        if header is None:
            return
        samples.append(
            FaultStack(
                thread=header.group("thread"),
                pid=int(header.group("pid")),
                tid=int(header.group("tid")),
                cpu=int(header.group("cpu")),
                timestamp_s=float(header.group("time")),
                period=int(header.group("period")),
                event_type=header.group("event"),
                frames=tuple(frames),
            )
        )
        header = None
        frames = []

    for line_number, raw_line in enumerate(
        path.read_text(errors="replace").splitlines(), start=1
    ):
        header_match = HEADER_PATTERN.match(raw_line)
        if header_match:
            finish_sample()
            header = header_match
            continue
        if not raw_line.strip():
            finish_sample()
            continue
        if header is None:
            raise ValueError(f"Unexpected line {line_number}: {raw_line!r}")
        frame_match = FRAME_PATTERN.match(raw_line)
        if not frame_match:
            raise ValueError(f"Invalid frame on line {line_number}: {raw_line!r}")
        frames.append(
            Frame(
                ip=int(frame_match.group("ip"), 16),
                symbol=frame_match.group("symbol"),
                dso=frame_match.group("dso"),
            )
        )
    finish_sample()
    return samples


def parse_recording_summary(path: Path) -> tuple[int, int]:
    match = RECORDING_SUMMARY_PATTERN.search(path.read_text(errors="replace"))
    if match is None:
        raise ValueError(f"No Simpleperf recording summary found in {path}")
    return (
        int(match.group("recorded").replace(",", "")),
        int(match.group("lost").replace(",", "")),
    )


def build_report(
    samples,
    source: Path,
    output: Path,
    samples_recorded=None,
    samples_lost=None,
    package="",
):
    """Use the same reader as exact captures, without inventing read addresses."""
    from fault_report import write_report
    from plotly.offline import get_plotlyjs
    from android_fault_visualizer.artifacts import is_app_owned_path

    if any(sample.period != 1 for sample in samples):
        raise ValueError(
            "Fault-order reports require period 1 (-c 1), not weighted samples"
        )
    samples = sorted(samples, key=lambda s: s.timestamp_s)
    start = samples[0].timestamp_s if samples else 0
    sources, events = {}, []
    for index, sample in enumerate(samples):
        source_name = sample.frames[0].dso if sample.frames else "Unresolved stack"
        sources[source_name] = {
            "label": source_name,
            "path": source_name,
            "mapped": False,
            "boundaries": [],
        }
        events.append(
            {
                "id": index,
                "time": (sample.timestamp_s - start) * 1000,
                "major": sample.event_type == "major",
                "address": "0x0",
                "source": source_name,
                "offset": None,
                "page": None,
                "thread": f"{sample.thread} ({sample.tid})",
                "stack": [
                    {
                        "label": f.symbol,
                        "file": f.dso,
                        "app": bool(package) and is_app_owned_path(f.dso, package),
                        "unresolved": not f.symbol,
                    }
                    for f in sample.frames
                ],
                "detail": {"Read source": "Not recorded in this stack export"},
            }
        )
    quality = (
        f"{samples_recorded} recorded, {samples_lost} lost"
        if samples_recorded is not None
        else "Recording loss status unverified"
    )
    run = {
        "label": source.name,
        "subtitle": "Android Simpleperf stack export",
        "stacksOnly": True,
        "pageSize": 4096,
        "sources": sources,
        "events": events,
        "cache": "Cache state is unverified. " + quality,
        "notes": [
            "These are stack-only samples, not read-file attribution. Capture timing and early-startup coverage depend on how Simpleperf was launched.",
            "Lost samples or non-period-1 sampling cannot establish complete fault order. No stack joining is performed by this reader.",
        ],
        "provenance": {
            "input": str(source),
            "recorded": samples_recorded,
            "lost": samples_lost,
        },
    }
    write_report(
        {"title": "Android page-fault call stacks", "runs": [run]},
        output,
        get_plotlyjs(),
    )


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Generate an interactive page-fault stack report"
    )
    parser.add_argument("samples", type=Path, help="Simpleperf report_sample.py text")
    parser.add_argument("--output", type=Path, default=Path("stack-report.html"))
    parser.add_argument(
        "--recording-log",
        type=Path,
        help="Simpleperf record output containing recorded/lost sample counts",
    )
    parser.add_argument(
        "--allow-loss",
        action="store_true",
        help="Generate a visibly warned report even when Simpleperf lost samples",
    )
    args = parser.parse_args()
    samples = parse_simpleperf_samples(args.samples)
    recorded: int | None = None
    lost: int | None = None
    if args.recording_log is not None:
        recorded, lost = parse_recording_summary(args.recording_log)
        if lost and not args.allow_loss:
            raise RuntimeError(
                f"Simpleperf lost {lost:,} samples; rerun or pass --allow-loss"
            )
    build_report(samples, args.samples, args.output, recorded, lost)
    print(f"Report written: {args.output.resolve()}")


if __name__ == "__main__":
    main()
