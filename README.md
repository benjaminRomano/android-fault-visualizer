# Android Fault Visualizer

Collect exact Linux major and minor page-fault events during one Android app
startup, attribute file-backed fault addresses to mappings and APK entries, and
generate a self-contained interactive Plotly report.

The tool is intended for evaluating startup code and data locality, including R8
startup profiles and native order files. It reports demand faults separately
from page-cache insertions so readahead is useful supporting evidence without
being mislabeled as minor faults.

See [How it works](docs/how-it-works.md) for the measurement model and Android
version caveats.

## Requirements

- Python 3.13 and [uv](https://docs.astral.sh/uv/)
- Android SDK platform tools (`adb`)
- An installed Android NDK; the collector is built for the target ABI
- A userdebug/eng emulator with `adb root`, or a physical device whose root
  environment permits system-wide perf, tracefs, `/proc`, and file access
- The bundled `trace_processor` executable and a compatible `ftrace.config`

Root is required for this tool's exact capture: the collector starts before the
app exists, opens system-wide perf events with fault addresses, and inspects
process mappings and inodes. Android 12 and newer let the adb `shell` domain
request a cache drop through `perf.drop_caches`, but that alone does not make
the rest of the exact pipeline usable without root.

Android 16 is supported and has been exercised end-to-end on API 36 arm64
userdebug emulator images with both 4 KiB and 16 KiB pages. Play Store emulator
images are production `user` builds, so `adb root` correctly fails on them. A
production physical device may work with Magisk/KernelSU or equivalent, but UID
0 is not enough by itself: the vendor kernel and SELinux policy must also permit
the operations above. See
[Android and device compatibility](#android-and-device-compatibility).

## Capture

```bash
uv sync

uv run faults.py \
  --package com.example.app \
  --output output/run-01
```

The launcher activity is resolved automatically. Use `--activity` when a package
has multiple relevant entry points and `--serial` when more than one adb target
is connected.

Each capture force-stops the app, waits for its processes to exit, then discovers
the app-owned file set. It calls `sync`, requests a global page-cache drop,
applies `POSIX_FADV_DONTNEED` to those files, and records
`mincore()` residency after the drop and again immediately before launch. The
default is strict: collection stops before launching the app if even one checked
page remains resident. This prevents an iteration from being silently labeled
cache-cold when eviction was incomplete.

The checked set is every regular file found under the installed APK directories
and the package's credential/device-encrypted data directories—not only APK,
DEX, or ART suffixes. This includes startup databases, secondary code, models,
and other app-owned files. System/framework files are affected by the global
drop but are outside this app-owned `mincore()` coverage.
The tool re-enumerates the file set immediately before launch and aborts if a
file appeared or disappeared, so an exact residency check cannot silently use a
stale snapshot.

Some Android processes or recently terminated app mappings can keep APK pages
unevictable. For isolated iterations, reboot the target first:

```bash
uv run faults.py \
  --package com.example.app \
  --output output/run-02 \
  --reboot-before-collect
```

`--max-resident-pages N` is an explicit opt-out for intentionally partially
warm experiments. The chosen threshold is stored in capture provenance and must
match for ordinary comparisons. Whether the iteration requested a reboot is
also comparison provenance; boot ID and uptime are retained for audit.
`cache_residency.csv` retains `before_drop`,
`after_drop`, `before_launch`, and `after_launch` evidence.
If a strict gate fails, `capture_metadata.json` is still written with the
threshold, reboot policy, device/boot provenance, failure status, and message.

To reprocess an existing exact capture:

```bash
uv run faults.py \
  --package com.example.app \
  --output output/run-01 \
  --skip-collect
```

Legacy captures produced by the old tracepoint/readahead heuristic are rejected
because they do not contain exact perf fault events.

## Interactive HTML report

Generate a standalone report with embedded Plotly JavaScript:

```bash
uv run report.py output/run-01 \
  --label "Baseline" \
  --output output/baseline.html
```

Compare two captures:

```bash
uv run report.py output/run-01 \
  --label "Baseline" \
  --compare output/run-02 \
  --compare-label "R8 reordered" \
  --output output/comparison.html
```

Comparisons require matching package/activity, device image and serial, ABI,
page size, kernel, collector source/binary, Perfetto config, cache procedure,
allowed cache-residency threshold, NDK, and compiler provenance.
`--allow-incomparable` is an explicit escape
hatch for exploratory cross-device views; the generated report prominently
lists every mismatch.

The report provides:

- an all-fault virtual-address timeline with minor/major markers and
  all/regular-file/anonymous/unmapped filters;
- major/minor rankings by mapped file and APK section;
- a fault timeline with a distinct lane for every mapped source;
- selectable per-file sequence plots and locality metrics;
- whole-file VDEX views on every supported Android version, plus Android 10
  VDEX 021/002 payload attribution by multidex order;
- an overall section/category view;
- page-cache insertion evidence shown separately from demand faults;
- side-by-side capture metrics and selectable sequence comparisons.

For an R8 experiment, keep Android image, app compilation mode, ABI, device,
activity, and cache procedure fixed. Run enough iterations to report a
distribution rather than treating one startup-duration pair as causal evidence.

## Optional page-fault stack capture

Simpleperf can record DWARF call stacks for the same kernel minor/major fault
events. Keep this as a separate diagnostic run: collecting an 8 KiB stack for
every fault adds substantial overhead, and Simpleperf can attach only after the
new app process appears.

**The standalone command below does not run this project's strict cache-eviction
and residency gate. Its cache state is unverified. Do not compare its
major/minor mix directly with cache-cold exact runs.** A production stack pass
should run the same gate immediately before launch.

Start recording before launch. On a production build the app must be
`profileableFromShell` or debuggable; `adb root` is not required for this
reduced-fidelity Simpleperf pass:

```bash
mkdir -p output
adb shell am force-stop com.example.app
adb shell simpleperf record \
  --app com.example.app \
  -e minor-faults,major-faults \
  -c 1 \
  --call-graph dwarf,8192 \
  --clockid boottime \
  -m 64 \
  --duration 30 \
  -o /data/local/tmp/page-fault-stacks.data \
  2>&1 | tee output/page-fault-stacks-record.log
```

Launch the activity from another terminal while Simpleperf is waiting. Stop the
recorder as soon as `am start -W` completes, then pull, symbolize, and render the
result:

```bash
adb shell 'pid="$(pidof simpleperf)"; [ -n "$pid" ] && kill -INT "$pid"'
adb pull /data/local/tmp/page-fault-stacks.data output/page-fault-stacks.data

"$ANDROID_NDK_HOME/simpleperf/report_sample.py" \
  -i output/page-fault-stacks.data \
  -o output/page-fault-stacks.txt \
  --show-art-frames

uv run stack_report.py output/page-fault-stacks.txt \
  --recording-log output/page-fault-stacks-record.log \
  --output output/page-fault-stacks.html
```

The self-contained report has a Firefox-Profiler-style sampled stack chart with
time on the x-axis and stack depth on the y-axis, plus an aggregated call-path
view. It rejects a recording with lost samples by default; `--allow-loss`
produces a visibly warned report when a lossy result is still useful. Perf
sample periods are preserved and used as weights. The exact collector remains
authoritative for fault counts, faulted addresses/files, and startup timing.
The stack run is qualitative unless a future collector records the fault
address and raw unwind state in one event.

## Android and device compatibility

| Target | Exact file/page attribution | Cache verification | Status |
| --- | --- | --- | --- |
| Android 16 `userdebug` emulator (4 KiB or 16 KiB pages) | Yes | Global drop plus app-file `mincore()` gate | Both tested end-to-end |
| Android 10 rooted emulator | Yes | Same gate | Tested; useful for VDEX 021/002 details |
| Rooted physical device | Conditional | Same gate when policy permits | Supported, kernel/SELinux dependent |
| Production non-rooted emulator/device | No | Cache drop can be requested on API 31+, but exact capture is still unavailable | Simpleperf stacks/counts only |

On an Android 16 production `user` image, non-root Simpleperf successfully
recorded minor/major fault samples for a profileable app. That audited recording
did not request stacks, and its sample type did not include `PERF_SAMPLE_ADDR`,
so an individual fault cannot be joined to a virtual mapping, file, or file
page. AOSP supports a separate DWARF call-stack mode for profileable apps, but
it still attaches only after the app process appears and does not supply the
fault address required here. That mode is useful for qualitative stack
diagnostics but cannot answer this project's file attribution or page-ordering
questions.

The Android 16 run produced VDEX version 027. The report shows that VDEX as one
complete file, which is the default view. Per-DEX payload labels are currently
limited to the validated Android 10 VDEX 021/002 parser; an unknown VDEX version
is never guessed or mislabeled.

## Capture outputs

`all_faults.csv` contains every app-process fault in the Perfetto startup
interval. `mapped_faults.csv` contains regular-file-attributed faults.
`mapping_events.csv` contains the timestamped perf MMAP2 timeline used for
attribution, with the post-launch `maps.txt` snapshot covering inherited maps.
`page_cache_events.csv` contains cache insertions and is deliberately a separate
dataset. `cache_residency.csv` records cache-state checks.
`artifacts.json` maps pulled APK and app ART artifacts (`.odex`, `.vdex`, and
`.art`) to their capture-local copies.
`capture_metadata.json` records device, page size, startup interval, collector
loss/throttle/integrity checks, Perfetto data-loss checks, and summary counts.
It also stores deterministic collector source/binary and trace-config hashes so
comparison provenance is enforced rather than assumed.

## Development

```bash
uv run black faults.py report.py stack_report.py utilities.py tests
uv run python -m unittest discover -v
```

The historical notebooks remain available for compatibility, but `report.py` is
the supported visualization path.
