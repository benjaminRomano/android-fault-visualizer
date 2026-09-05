# Android Fault Visualizer

Capture Android startup page faults, identify their backing files, and inspect
page order and call stacks in a self-contained HTML report.

## Requirements

Python 3.13, [uv](https://docs.astral.sh/uv/), Android SDK `adb`, an Android NDK,
and a rooted target permitting system-wide perf, tracefs, process maps, and
app-file access. Use an AOSP/Google APIs userdebug emulator, not a Play Store
production image. Rooted physical devices are kernel/SELinux-dependent; this
iteration was verified on an Android 16 arm64 emulator, not physical hardware.

## Capture and open

```bash
uv sync
uv run faults.py --package com.example.app --serial emulator-5554 --output output/run-01
open output/run-01/report.html
```

The command resolves the launcher activity, verifies cache eviction, records
before launch, processes the trace, and writes the report. Use `--activity` to
select another entry point. Existing captures are protected against accidental
overwrite.

Default capture records exact Linux major/minor perf events, virtual fault
addresses, mapping events, and native callchains. Native unwinding may stop at
ART or code without frame pointers. Missing callchains remain missing; the
fault itself is retained. Lost, throttled, overflowing, or corrupt capture
streams are rejected.

For managed/DWARF stacks, add the optional companion:

```bash
uv run faults.py --package com.example.app --serial emulator-5554 \
  --dwarf-stacks --reboot-before-collect --output output/run-02
```

This starts system-wide Simpleperf **before** launch and waits for its recording
notification. It exports only the launched PID and startup window, with stack
joining and timestamp-gap removal disabled. Choose the “DWARF stacks” run in
the HTML. It is a separate stream: the tested Simpleperf does not sample the
faulted address, so its stacks are never guessed onto exact events by timestamp
or ordinal. Running two profilers adds substantial overhead and can reduce
native stack coverage; compare only equivalently instrumented captures.

## Cache verification

Every iteration force-stops the app and waits for its processes to exit,
enumerates installed APK and package-data files, runs `sync` and a global cache
drop, then applies file-scoped `POSIX_FADV_DONTNEED`. `mincore()` checks residency
after eviction and immediately before launch.

The default requires **zero resident pages** in every checked app file.
A successful `drop_caches` command is not proof of eviction. Missing installed
APK mappings or residual pages fail the pre-launch gate and preserve diagnostics.
Changing optional files are handled with warnings and fresh eviction checks.
System/framework file residency is outside this app-file check.

Use `--reboot-before-collect` for isolated iterations if other processes retain
APK pages. Rebooting does not bypass the residency gate.
`--max-resident-pages N` explicitly allows a partially warm experiment.
A post-launch residency failure preserves the usable capture with a warning.

## Reading the report

The report defaults to **major faults**, ordered by major count.

- The source sidebar shows filtered counts, major-first; hover retains full paths.
  Click a source to filter the analysis panes.
- File lanes, whole-file page indices, and virtual-address plots share filters.
- VDEX remains one file, including shared/verification data. Verified DEX starts
  are red lines. Android 10 VDEX 021/002 and modern VDEX 027 are supported.
- DEX names require the complete ART location-checksum list to match APK ZIP
  entry checksums. Unsupported or mismatched identities remain unnamed.
- Standard DEX instruction ranges can identify methods **stored on a page**.
  That is not proof those classes executed or triggered a fault. CompactDex and
  compressed DEX method ranges are not decoded.
- Native ELF sections and verified DEX identity are retained in point details.
- Stack roots are at the top, faulting frames below. One chronological column
  is one fault, not a duration. Click a column for the exact event and stack.
- Stack chart and Flame graph are separate tabs: the former preserves time
  order, the latter aggregates complete call paths by fault count. Click a
  flame frame to focus it; reset restores the full graph. Neither width is time.
- Address plots support elapsed time or original recorded fault index. Hiding
  minor faults does not renumber major points. Signed virtual-page and file-page
  delta views compare consecutive filtered faults; file deltas omit cross-file
  and unknown-offset transitions. Zoom can become a shared analysis range.
- The DWARF view ranks instruction binaries, not files read.
- Empty filters show no data. SVG scatter is used when WebGL is unavailable.

For locality, select one file and switch to fault order. A tight progression
through pages can motivate an ordering experiment; a scattered pattern is not
a prediction of time saved. R8 DEX order and ART-compiled OAT layout are
different layers. Repeat captures with the same compilation state and cache
procedure before drawing conclusions.

## Reprocessing and comparison

```bash
# Saved metadata supplies the package; no device or local app config is needed.
uv run faults.py --skip-collect --output output/run-01

# HTML only:
uv run report.py output/run-01

uv run report.py output/run-01 --label Baseline \
  --compare output/run-02 --compare-label Reordered --output output/comparison.html
```

Comparison runs are separately selectable with identical controls. Package and
page size must match. Device/build, activity, kernel, collector/config hashes,
toolchain, cache preparation, and instrumentation must match unless
`--allow-incomparable` is explicitly supplied; mismatches remain visible.
Legacy heuristic captures without exact perf events are not accepted.

## What the counts mean

Major/minor are emitted Linux userspace perf fault events, not syscall events.
Some kernel-accounted faults do not emit those samples, so process-level fault
counters can differ. Minor faults include anonymous allocation and copy-on-write,
not just file-cache hits.

Perfetto supplies the startup interval and separate page-cache insertions.
Insertions include application threads **and kernel/background workers touching
exact app-owned device/inode pairs**. They are correlated I/O/readahead evidence,
not additional faults or proof that a particular fault caused a read.

Non-root profileable apps can use a reduced Simpleperf workflow, but attachment
can miss early startup and the tested sample lacks read addresses. That does not
replace this tool's exact file attribution or strict app-file cache gate.
See [the capture design](docs/how-it-works.md) for why the small C collector is
retained instead of replacing it with Simpleperf commands.

## Outputs and development

`all_faults.csv` contains every captured app fault in the startup interval;
`mapped_faults.csv` contains file-backed faults.
`mapping_events.csv`, `resolved_fault_callchains.csv`, `fault_details.json`,
`vdex_dex_boundaries.csv`, `page_cache_events.csv`, and `cache_residency.csv`
retain attribution and evidence. `capture_metadata.json` records device,
instrumentation, loss checks, warnings, and counts. Optional DWARF captures add
`simpleperf.data`, `simpleperf-stacks.txt`, and integrity metadata.

The CLI in `faults.py` orchestrates focused modules under
`android_fault_visualizer/`: device preparation, recording, artifact parsing,
processing, binary enrichment, and Simpleperf. `report.py` only normalizes data
for `fault_report/`, the six-file reader vendored identically in the iOS repo.
Historical notebooks remain for compatibility; HTML is the supported report.

```bash
uv run python -m unittest discover -s tests -v
node --test tests/report_model.test.cjs tests/report_stacks.test.cjs
uv run ./scripts/format.sh
```

[Latest verification](docs/verification-2026-09-05.md) records emulator commands,
capture totals, failure gates, browser checks, and limitations. Raw traces can
contain app paths, device identifiers, and symbols; inspect them before sharing.
