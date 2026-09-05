# Verification — 2026-09-05

## Follow-up: strict Firefox and ChatGPT captures

Supplied APKM archives were installed using their arm64/xxhdpi splits (and
English for ChatGPT) on the rooted Android 16 Google APIs, 16 KiB emulator.
Both reached their normal logged-out welcome screens; no accounts were used.

| Capture | Recorded faults | File-backed faults | File-backed major | Pre-launch app-file residency |
| --- | ---: | ---: | ---: | --- |
| `e2e-firefox-strict-pageout` | 9,266 | 4,190 | 660 | 0 / 16,361 pages, 5 files |
| `e2e-chatgpt-strict-pageout` | 7,191 | 2,702 | 270 | 0 / 5,497 pages, 6 files |

Both used the zero-residency threshold and reported zero collector loss. Every
file-backed major had a captured native stack. These initial experiments used
scoped APK mapping reclaim before the normal CLI's strict cache gates. They are
not measurements of physical-device storage or of an empty host disk cache.

The integrated Firefox retry (`e2e-firefox-strict-integrated-settled`) also passed:
13,558 recorded faults, 1,173 majors, 4,728 file-backed faults (903 major), and
0 / 17,375 pages resident across 168 checked files. This was another launch
state, not a before/after code-layout comparison.

The fresh bound DWARF fixture (`e2e-fixture-bound-dwarf`) passed both strict
cache gates with 0 / 3,105 pages across 3 files. All 26 startup major faults
matched DWARF samples exactly, with zero ambiguous or unmatched identities;
native and Simpleperf loss were both zero. Chains contained 7–47 user frames.
Six faults read app artifacts (four ODEX, two VDEX), but no captured caller
was app-owned in this fixture. The report does not claim app classes triggered
these loader/ART faults.

The final Snapchat attempt (`e2e-snapchat-strict-bound`) established strict
zero residency (0 / 24,290 pages, 81 files) and reached the normal landing screen.
It was nevertheless rejected: the native collector lost 164 samples and
Simpleperf lost 663 of 3,492 recorded samples. No report or enrichment was
published from that incomplete run. A ChatGPT dual-profiler run likewise lost
samples, and a later attempt failed the second cache gate. The loss-free native
reports above remain usable; reliable large-app dual recording remains a limit.

Read-only mapping inspection explained why `sync` plus `drop_caches` alone had
left APK pages resident: other Android processes retained resource mappings even
when the target app was force-stopped. The bounded experiment applied
`process_madvise(MADV_PAGEOUT)` only to exact installed APK device/inode pairs
and read-only ranges, then checked residency again. Advice returning success
does not establish eviction: multiply mapped pages initially remained resident
for Firefox. Core services were not stopped; GMS later released its mappings
naturally. Strict verification, not the advice return status, decides success.

### The Snapchat screenshots

In the older AOSP capture, `resources.arsc` occupies APK bytes
140,654,180–200,615,736 (4 KiB pages 34,339–48,978). The 393.590–397.593 ms
burst contains 98 faults, all minor in both the raw collector and mapped CSV.
No earlier cache-insertion event in the saved trace matches those 98 pages.
The APK still had 1,730 resident pages before launch. Residency snapshots saved
counts rather than individual page indices, so those exact pages' prior
residency cannot be proved from this capture. It does not establish a classifier
bug, a fully cold start, or readahead causality.

SystemUI inserted 102 resource pages earlier in the trace, but none overlaps
that initial burst. Four later minor faults do overlap those fills. Resource
major faults also have fills shortly before their emitted samples: Linux emits
the major/minor perf event after fault handling, so timestamp precedence alone
is not proof that a page was prefetched before the fault began.

The two `libclient.so` virtual-address bands reflect different mappings of the
same inode. Five small upper mappings serve loader metadata (3 major, 2 minor);
four lower runtime segment mappings account for 73 major and 742 minor faults.
All 820 faults match a preceding MMAP2 mapping and its file-offset calculation,
with zero mismatches. Upper major offsets identify section-header, `.dynamic`,
and `.dynstr` reads; stacks include the dynamic loader. The temporary mappings
are absent from final `maps.txt`, demonstrating why timestamped mappings matter.

### Reader changes

- Android hides anonymous and unknown mappings, retaining raw capture counts
  and original indices. Real file mappings can still occupy distant virtual
  ranges (for example ART boot files); hiding anonymous pages does not remove
  those legitimate gaps. The Files axis is useful for that case.
- File-page coordinates require one selected file. All-source mode uses
  virtual addresses or file lanes, never overlapping unrelated file offsets.
- Stack charts start fully zoomed out. Paging and wheel-zoom controls are gone;
  W/S scroll vertically, A/D select adjacent faults, and Escape clears flame
  focus. Captured kernel frames are retained at the trigger end of the stack.
- Fault list rows are chronological individual events, not symbol aggregates.
  Their displayed index matches plots; raw capture sequence is retained in
  selected-event details.

The earlier capture history and its deliberately partially warm runs follow.

Final follow-up checks: 95 Python tests and 17 shared JavaScript tests passed.
The same shared reader passed 50 iOS Python tests and its 17 JavaScript tests;
all six reader assets are byte-identical between repositories. Browser checks
passed on Firefox, ChatGPT, the bound Android fixture, and the saved iOS
Simulator capture, including all-source filtering, stable fault indices,
per-event list selection, fully zoomed-out stacks and 390-pixel layouts.
Desktop reports were visually inspected; numeric list wrapping and excess
file-lane padding found during inspection were fixed. The independent review
found no remaining P0/P1/P2 issues. No fresh iOS recording was needed for these
shared-reader-only changes; the earlier Simulator E2E data was reprocessed.

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
