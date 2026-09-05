# Verification — 2026-09-05

## Fresh Android 16 captures

Tests used owned, rooted arm64 userdebug emulators: AOSP with 4 KiB pages and
Google APIs with 16 KiB pages. No physical device was tested.

| Capture | All faults | Major faults | File-backed faults | Cache inserts |
| --- | ---: | ---: | ---: | ---: |
| Small fixture, exact + DWARF | 8,535 | 28 | 1,745 | 3,070 |
| Snapchat, AOSP compatibility screen | 15,818 | 124 | 3,553 | 25,023 |
| Snapchat, Google APIs landing screen | 7,028 | 213 | 2,933 | 6,666 |
| Snapchat, Google APIs exact + DWARF | 7,051 | 225 | 2,882 | 6,562 |

The Google APIs test used Snapchat 14.22.0.48, package `com.snapchat.android`,
target SDK 36. It reached the normal logged-out landing screen. No account was
used. The AOSP-only image lacked Google Play services and reached a compatibility
dialog; that capture does not represent normal Snapchat startup.

The fixture passed the strict cache gate: **0 / 3,105 app-file pages resident**.
Snapchat did not: the strict Google APIs attempt found 504 resident APK pages
and correctly stopped before launch. A separate, explicitly partially warm
capture allowed `--max-resident-pages 5000`; its immediately pre-launch result
was **487 / 23,597 pages resident**, across 25 checked files. This is not a cold
Snapchat benchmark. Rebooting the AOSP image also failed to establish zero
residency; the implementation did not silently waive that requirement.

The Google APIs native capture had stacks for all 213 major faults, zero sample
loss, zero integrity errors, and ten checksum-verified DEX payloads in one VDEX
027 source. Of those majors, 187 had file attribution; unknown mappings remain
unknown. The report preserves the whole VDEX and marks verified DEX boundaries.

The fixture's optional companion had 28 major stacks. Its native stream had 28
explicitly empty major callchains; the events were preserved without invented
frames. Equal counts are not used to pair these independent streams.

The final Snapchat companion retry also succeeded: 426 system-wide samples
recorded, zero lost, and **225 in-window major stacks**, 125 containing app-bundle
frames. Managed names include `io.reactivex.Single.subscribe` and obfuscated
application methods. All 225 native major callchains were explicitly empty with
concurrent DWARF collection; the separate native-only run had full coverage.
The streams are never joined by ordinal or timestamp. This final run had 483
resident app-file pages out of 24,282 and one post-launch changing-file warning.
Its screenshot again showed the normal logged-out landing screen.

Commands (substitute the target serial and output directory):

```bash
uv run faults.py --package com.bromano.mperf.fixture --serial emulator-5560 \
  --dwarf-stacks --output output/e2e-api36-final
uv run faults.py --package com.snapchat.android --serial emulator-5562 \
  --max-resident-pages 5000 --output output/e2e-snapchat-google16k-partially-warm
uv run report.py output/e2e-snapchat-google16k-partially-warm
uv run faults.py --package com.snapchat.android --serial emulator-5562 \
  --dwarf-stacks --max-resident-pages 5000 \
  --output output/e2e-snapchat-google16k-dwarf-final
```

## Failure paths exercised

- Nonzero pre-launch residency rejected, including after reboot.
- A large capture exceeded the previous 50,000 mapping-record capacity and was
  rejected instead of publishing an incomplete exact trace.
- Bounded capacities now allow 100,000 mappings and 4,000,000 callchain entries.
  The tested collector records 117,600,000 bytes of record-buffer capacity and
  33,685,504 bytes of perf-ring capacity on the four-CPU, 16 KiB target. This is
  instrumentation overhead, not application memory, and is saved in metadata.
- A Snapchat DWARF run lost 228 of 1,245 samples. The companion was rejected;
  the loss-free exact capture remained available. Loss checks were not relaxed.
  The final retry explicitly requested 1,024 buffer pages per CPU (16 MiB per CPU
  on this target) and passed. Simpleperf's automatic setting may already have
  selected that size, so this does not prove the flag caused the improvement.
- Snapchat queue files disappeared during post-launch residency checks. The
  trace survived with explicit warnings and exit statuses.

## Automated and visual checks

```bash
uv run python -m unittest discover -s tests -v
node --test tests/report_model.test.cjs tests/report_stacks.test.cjs
uv run ./scripts/format.sh
```

Regression tests cover modern/legacy VDEX bounds and checksums, whole-file
reporting, DEX method bounds, worker cache attribution, package delimiters,
disappearing files, missing processes, recorder readiness/cleanup, comma-formatted
Simpleperf counts, empty callchains, and comparison compatibility.
Final results: 69 Python tests and 16 shared JavaScript tests passed. NDK
compilation, Ruff's undefined/unused-import checks, compileall, and diff checks
also passed.

Shared reader tests cover exact BigInt page arithmetic, signed deltas that do
not bridge files, recursive/full-path flame aggregation, missing-stack
denominators, exact hit testing, zoom, and 150,000-event input. The browser check
in `scripts/check_report_ui.js` compares rendered counts to the embedded capture,
checks stable indices across the minor toggle, validates adjacent address deltas,
clicks an exact stack event, and checks empty filters and flame denominators.
Chrome checks also exercised shared zoom filtering, SVG fallback with WebGL
disabled, and 390-pixel layouts. The ten-DEX VDEX plot had 593 events and ten
boundary lines; `classes2.dex` search narrowed it to 119 events. The search-field
overflow found at narrow width was fixed. Desktop address, VDEX, chronological
stack, and flame views were visually inspected.

An independent adversarial review found optional-file handling, sample-count
parsing, and stack-only labeling issues; these were corrected and covered by
regression tests before publication.

## Report design and interpretation

The compact source sidebar, separate chronological stack/flame views, local
scrolling, measured label truncation, and full hover details were informed by
[Firefox Profiler](https://github.com/firefox-devtools/profiler/tree/cb07a1a678748de3d8adc816de54378f5bd7927f).
No upstream source code was copied. Here, each chronological column represents
one fault, and aggregate width is fault count—not stack changes or elapsed time.

Raw traces, installed APKs, pulled binaries, and generated HTML are intentionally
excluded from Git. They can contain application paths, symbols, and device IDs.
Rooted physical-device support remains conditional on kernel and SELinux policy;
non-root collection does not satisfy this tool's exact-address and cache gates.
