# Capture design

## What changed

The original filemap/readahead approach confused page-cache insertions with
faults and used a fixed nearby-page window to infer major/minor classification.
Neither is valid: a worker can fill many pages, one later demand can fault minor,
and read-ahead pages may never be demanded.

The current pipeline keeps three independent kinds of evidence:

1. Linux perf software fault samples: emitted major/minor, address, PID/TID,
   timestamp, native callchain.
2. Mapping events and pulled binaries: file offsets, verified DEX identities,
   ELF sections, and names of instructions stored on the demanded page.
3. Perfetto startup slices and page-cache insertions: the analysis window and
   correlated cache activity, including background workers.

Process-level kernel fault counters are a fourth, different measurement. Some
kernel-accounted faults do not emit the userspace perf samples collected here.
A mismatch is not automatically trace loss; explicit perf/Perfetto loss checks
remain mandatory.

## Why retain C instead of only perf commands?

Page faults are CPU exceptions, not a “major-page-fault syscall”.
Linux perf can record software fault events with callchains and, using
`perf record -d --data-mmap`, data addresses and mappings. A compatible perf
binary plus an audited decoder could replace the native collector in principle.

The tested Android 16 emulator ships Simpleperf, not a general `perf` command.
Its fault sample type was `0x1e7`: callchain, CPU, ID, IP, period, TID, time,
but **not PERF_SAMPLE_ADDR**. The instruction address is not the page-fault
address. Simpleperf therefore cannot directly replace exact read-file mapping
on this target.

The small C program handles the part that needs the Linux ABI directly:
per-online-CPU `perf_event_open`, sample decoding, MMAP2 records, loss checks,
and app-file eviction/residency. CPU identifiers come from
`/sys/devices/system/cpu/online`, including noncontiguous sets. Collection
records and validates that topology. C source, CPU header, built binary,
toolchain, and trace configuration are captured as provenance.
Record arrays and per-CPU rings are bounded, with their capacities recorded in
metadata. Increasing capacity does not relax overflow or loss rejection; both
the native recorder and a DWARF companion add measurable memory/runtime overhead.

Python owns orchestration and analysis. The modules separate device/file
preparation, recorder lifecycle, metadata parsing, event processing, binary
enrichment, and report adaptation; they do not add a backend framework.

## Startup and stack capture

Perfetto and the exact native collector start before the app is launched.
Readiness is bounded and explicit; failures stop the owned recorder. Events
are filtered to the launched PID and Perfetto's startup interval, in the
`CLOCK_BOOTTIME` domain.

Native callchains belong to their exact fault event, joined using sequence and
the complete PID/TID/timestamp/address/type identity. Repeated recursive frames
are retained. An explicitly empty kernel callchain preserves the event with no
stack. Missing records, overflowing chains, sample loss, throttling, and corrupt
streams fail integrity checks.

Optional `--dwarf-stacks` starts system-wide Simpleperf before launch, avoiding
the `--app` attachment race. Its readiness notification precedes app launch.
Offline unwinding can recover managed methods. Export uses the exact launched
PID, preserves timestamp gaps, and disables callchain joining. Period must be
one, and recording loss must be zero.

The DWARF stream is not joined to the native stream. Its binaries are
instruction sources, not read sources. Concurrent profiling perturbs startup
and can affect native callchain coverage. In the verified dual run, all 27
major faults lacked native user frames while the companion had 27 major stacks;
the native-only run had full fault-stack coverage. These are observations, not
a proof of why individual chains were empty.

## File and binary attribution

Timestamped MMAP2 records include executable and data mappings. For a
regular-file mapping, the demanded byte is:

```text
file offset = mapping offset + fault address - mapping start
```

A final `/proc/PID/maps` snapshot covers inherited Zygote mappings when no
contradictory later mapping overlaps the sampled address. Anonymous/special
mappings stay unattributed. Snapshot fallback cannot reconstruct arbitrary
unmap/remap history; attribution is deliberately limited to available evidence.

APK entry bounds come from ZIP local headers and payload sizes. Gaps and
headers stay attributed to the container. Compressed payload locations are not
decompressed instruction locations.

VDEX 021/002 and 027 layouts are bounds-checked. Individual `classes*.dex`
identity is exposed only when the **complete ordered ART location-checksum
list** matches APK DEX ZIP checksums. The entire VDEX remains one analytical
source; verified payload starts are red plot boundaries, not separate sources.
Unknown formats and mismatches never get guessed DEX names.

Standard DEX instruction ranges produce “methods on this page” hints.
They describe file content, not callers. CompactDex/DEX 041 instruction decoding
and per-method OAT-to-DEX attribution are not implemented. ELF PT_LOAD and
allocated file-backed sections support native offsets/symbolization; unavailable
symbol files leave raw addresses without discarding the capture.

## Cache and background work

Before every launch the tool force-stops the package, waits for all package
processes to exit, inventories app-owned files, calls `sync` and
`drop_caches`, applies `POSIX_FADV_DONTNEED`, and checks `mincore()` after
eviction and immediately before launch. Zero resident app-file pages is the
default gate; reboot never bypasses it.

Installed APK mappings are essential and must all resolve. Optional temporary
files can disappear with warnings; newly discovered files are evicted and
checked. Post-launch residency failures are diagnostics, not grounds to discard
an otherwise valid startup capture. System-file residency is not measured by
the app-file gate.

Perfetto cache inserts include app-process events and events targeting exact
app-owned `(device,inode)` pairs. A left join retains kernel workers without
userspace process records. Package matching is delimiter-aware, so
`com.example.app` does not claim `com.example.application`.
Folio order is preserved as page count. Inserts remain separate CSV evidence,
not major/minor faults or proof of causal I/O.

## Platform limits

Rooted physical Android can work if kernel and SELinux policy permit the same
operations; it has not been verified in this iteration. Non-root profileable
Simpleperf can provide a reduced stack/count view, but app attachment can miss
early startup and the tested format lacks demand addresses. A permitted
`perf.drop_caches` property alone does not enable exact non-root collection.

Page size, compilation mode, Android release, readahead, and system services
change the observed pattern. Match those conditions and instrumentation across
repeated runs. R8 input DEX locality is not synonymous with ART OAT layout.

## Primary references

- [Linux perf-record options](https://man7.org/linux/man-pages/man1/perf-record.1.html)
- [AOSP Simpleperf record implementation](https://android.googlesource.com/platform/system/extras/+/refs/heads/main/simpleperf/cmd_record.cpp)
- [Linux perf callchain handling](https://github.com/torvalds/linux/blob/master/kernel/events/callchain.c)
- [Linux drop_caches documentation](https://www.kernel.org/doc/html/latest/admin-guide/sysctl/vm.html)
- [AOSP arm64 fault accounting](https://android.googlesource.com/kernel/arm64/+/f5269100977385d1fd4a5ef68e49631892cf4fe4/arch/arm64/mm/fault.c)
- [Android 16 ART VDEX definitions](https://android.googlesource.com/platform/art/+/refs/heads/android16-release/runtime/vdex_file.h)
