# How it works

## Measurement model

The native collector opens the Linux perf software events
`PERF_COUNT_SW_PAGE_FAULTS_MAJ` and `PERF_COUNT_SW_PAGE_FAULTS_MIN` on every CPU
before the app process exists. Each sample contains the faulting process/thread,
timestamp, instruction pointer, fault address, and CPU. After collection, the
events are filtered to the launched PID and Perfetto's one Android startup
interval.

This is architecture-independent and follows the kernel's post-resolution
major/minor accounting. It replaces two inaccurate behaviors in the original
implementation:

- `mm_filemap_add_to_page_cache` means a page or folio was inserted into a
  file's page cache. It can represent synchronous I/O or readahead, but is not a
  page-fault event.
- A fixed 128 KiB readahead window cannot determine whether a fault was major or
  minor. The kernel's classification is recorded directly instead.

The collector fails the capture if its perf ring buffers report lost samples.
Major remains a Linux VM classification (`VM_FAULT_MAJOR`), not a direct
measurement at the storage controller.

## File attribution

The perf collector records timestamped `PERF_RECORD_MMAP2` events, including data
mappings, from before the app process exists. A sampled fault is resolved using
the most recent mapping record active at that timestamp. The tool also captures
`/proc/<pid>/maps` after launch as a fallback for mappings inherited from Zygote
that predate collection. A sampled address is attributed only when it lies in a
half-open mapping range `[start, end)` with a nonzero inode and a regular-file
path. The file offset is:

```text
mapping file offset + (fault address - mapping start)
```

Device numbers use Linux's encoded `dev_t`, so `(device, inode)` from mappings,
ftrace, and `stat` can be joined correctly. Anonymous mappings and special
`/dev/*` mappings remain unattributed.

If a later MMAP2 record overlaps an address, the final snapshot is not applied
backward in time. This avoids silently assigning an early fault to a mapping
created later.

For APKs, ZIP local headers are parsed to locate the start and end of each
entry's compressed payload. A fault is assigned to an entry only inside that
payload range. Local headers, data descriptors, alignment gaps, and the central
directory remain attributed to the APK container; they are not assigned to the
nearest preceding entry.

The page size comes from `getconf PAGESIZE` on the target, so 4 KiB and 16 KiB
devices use the correct page index.

## Page-cache control and verification

For each iteration the tool:

1. force-stops the package;
2. waits until all package processes have exited;
3. enumerates every regular file in the installed APK and package data
   directories;
4. runs `sync` so dirty pages are eligible for eviction;
5. requests `echo 3 > /proc/sys/vm/drop_caches`, or Android's
   `perf.drop_caches` init property from the adb `shell` domain where direct
   sysctl access is unavailable;
6. applies file-scoped `POSIX_FADV_DONTNEED` to every regular file discovered
   under the installed APK and package data directories;
7. re-enumerates the file set and rejects any additions or removals; and
8. uses `mincore()` after eviction and immediately before launch.

Linux documents `drop_caches` as dropping clean caches only; it does not
guarantee that every page remains absent. Android system processes can retain or
repopulate package files between the drop and launch. Consequently the default
`--max-resident-pages=0` policy aborts collection before app launch if any
checked page remains resident. The per-file evidence is still written to
`cache_residency.csv`. A nonzero threshold is an explicit partially warm policy,
not a successful cache flush, and becomes comparison provenance.
Strict failures also retain `capture_metadata.json` with the cache policy,
device/boot provenance, failure status, and diagnostic message.

`--reboot-before-collect` is useful when a prior launch left APK pages
unevictable. Rebooting is not itself accepted as proof of a cold cache: the same
post-drop and pre-launch `mincore()` gates still have to pass.
The reboot policy is comparison-gated provenance, while boot ID and device
uptime remain audit metadata.

The property fallback intentionally uses plain adb shell rather than explicitly
routing through `su`. Android's SELinux policy grants `perf.drop_caches` to the
shell domain; third-party root domains are not necessarily permitted to set it.
This lets a non-root API 31+ shell request the global drop. It does **not** make
the complete verified procedure non-root: file-scoped eviction, `mincore()`
coverage, system-wide address-bearing events, and mapping access still require
the exact collector's root environment.

On a root-adbd userdebug image, plain `adb shell` may itself retain a root
SELinux domain. Such images normally use the direct sysctl path; if both paths
are denied, collection fails rather than accepting an unverified cache state.

## Perfetto's role

Perfetto supplies the Android startup boundary and page-cache insertion evidence.
The trace records Android startup slices plus
`mm_filemap_add_to_page_cache`. Cache insertions are written to
`page_cache_events.csv` with folio order preserved as `page_count`; they never
enter `faults.csv` or the major/minor counts.

The perf collector uses `CLOCK_BOOTTIME`, which is the same time domain used by
the trace timestamps, so the two streams can be filtered without a wall-clock
conversion.

Perfetto runs in the foreground with in-memory ring buffers during the measured
interval. It is interrupted only after startup collection, at which point the
trace is written. Periodic trace-file streaming is intentionally disabled so
the instrumentation does not add storage writes to a cold-I/O experiment.

## Optional call stacks

Linux perf can attach either a kernel-produced call chain
(`PERF_SAMPLE_CALLCHAIN`) or the user registers and stack bytes needed for
offline unwinding (`PERF_SAMPLE_REGS_USER` and `PERF_SAMPLE_STACK_USER`) to a
software fault sample. Android Simpleperf's DWARF mode uses the latter and can
resolve Java, ART, framework, and native frames on Android 9 and later.

Stack capture is intentionally a separate diagnostic pass:

- an 8 KiB user-stack snapshot per fault materially increases recording work;
- Simpleperf attaches after the package process appears, so the earliest faults
  can be absent;
- Simpleperf's standard page-fault sample does not retain the fault address used
  by this project's exact file-attribution pipeline; and
- running Simpleperf and the exact system-wide collector together can perturb
  launch and overflow Simpleperf's buffers.

The standalone stack command does not execute the exact collector's strict
cache-eviction and residency gate. Its cache state is therefore unverified and
its major/minor mix must not be compared directly with a verified cold run.
`stack_report.py` accepts the Simpleperf recording log, rejects nonzero sample
loss by default, and retains perf sample periods as weights.

Consequently `stack_report.py` visualizes captured fault call paths, but those
samples are not silently joined to files or used for authoritative counts and
timing. Frame-pointer mode is smaller, but optimized ART and native code often
produce incomplete managed stacks. DWARF mode is the default recommendation for
the qualitative stack pass.

## Android-version behavior

The event source works across CPU architectures, subject to kernel perf support
and security policy. The interpretation of a startup still depends on the
Android release:

- Android 10/11 images are useful for explicitly cold code-loading experiments.
- Android 16/API 36 has been exercised end-to-end on arm64 userdebug emulator
  images with both 4 KiB and 16 KiB pages. One 4 KiB capture initially failed
  its strict gate when 182 of 684 APK pages remained resident; a rebooted
  iteration reached zero and completed. A 16 KiB post-boot attempt likewise
  rejected 36 of 171 resident APK pages; a subsequent strictly verified
  iteration reached zero and completed. This is why cache-drop command success
  is not treated as proof.
- ART and platform startup components on newer releases may issue
  `madvise(MADV_WILLNEED)` or other readahead before demand access. That work can
  convert later demand faults to minor faults or eliminate demand faults
  altogether.
- Compilation state changes whether code demand targets ODEX/OAT, VDEX, or APK
  DEX. Compare builds only after matching compilation mode. On Android 10
  VDEX 021/002, the report labels each unambiguous CompactDex payload by
  multidex order. Android 16 currently produces VDEX 027; the report presents
  the entire VDEX file and deliberately does not guess per-DEX boundaries for
  that unvalidated format. ODEX byte offsets are not assigned to a dex without
  method-level OAT metadata.
- 16 KiB page devices change page counts and locality metrics even when byte
  layout is unchanged; compare like with like.

### Emulator and physical-device capability boundary

- **AOSP/Google APIs userdebug/eng emulator:** exact mode works when `adb root`
  succeeds and the kernel exposes perf plus the required filemap tracepoint.
  The API 36 AOSP `default` 4 KiB and Google APIs 16 KiB images satisfy those
  requirements. Play Store AVD images are production `user` builds and do not
  permit `adb root`.
- **Rooted physical device:** exact mode can work and is preferable when real
  storage behavior matters. Root must be usable from adb and its SELinux domain
  must be allowed to open per-CPU system-wide perf events, read tracefs and
  `/proc/<pid>`, and inspect app/system files. Magisk/KernelSU does not guarantee
  those permissions, and some vendor kernels omit or restrict perf.
- **Non-rooted production device:** Android 12+ shell can request
  `perf.drop_caches`, and Simpleperf can profile an app marked
  `profileableFromShell`. In an API 36 production-image audit, Simpleperf
  captured fault samples, but the audited pass did not request stacks and its
  sample type omitted `PERF_SAMPLE_ADDR`. AOSP's separate DWARF mode supports
  call stacks for profileable apps, but without the fault address a sample
  cannot be mapped to a file or page, and attaching after process creation
  misses the earliest startup. This is a useful qualitative diagnostic mode,
  not a replacement for exact capture.

The tool reports a root or capability failure rather than falling back to the
old tracepoint/readahead heuristic.

## Reading the report

The address-space overview plots every recorded startup fault at its process
virtual address. Minor faults use circles and major faults use diamonds; the
scope control switches between all, regular-file, anonymous/non-regular, and
unmapped addresses. Hover preserves named anonymous mappings such as stacks and
JIT caches; regular-file points additionally retain the exact file or APK
section, file page/offset, thread, category, and capture sequence. Because ASLR
can move mappings between launches, use this view for within-capture temporal
patterns and the logical-file comparison views for cross-capture ordering
comparisons.

Minor faults are useful: they show demanded pages that resolved without the
kernel's major-fault path, often because a page was already cached or supplied
by readahead. The selectable sequence plot is independent of major/minor
classification. Its next-page, nearby-step, and median-jump metrics describe
how tightly demanded file pages are ordered. “Nearby” is 32 pages (128 KiB on
a 4 KiB-page device), a comparison window rather than a readahead assumption.

For R8 ordering experiments, focus on the executable artifact actually used by
the runtime, typically app ODEX/VDEX on an AOT-compiled installation. Compare
both the file's page sequence and its exact major/minor counts across repeated
runs; total startup time alone is noisier and can include unrelated Android
runtime work.

The comparison report rejects mismatched device/build, kernel, ABI, page size,
activity, collector source/binary hash, trace-config hash, cache procedure, or
toolchain metadata. An explicit `--allow-incomparable` override retains a
prominent mismatch warning for intentional exploratory comparisons.

## Primary references

- [Linux `drop_caches` documentation](https://www.kernel.org/doc/html/latest/admin-guide/sysctl/vm.html)
- [Linux perf event ABI](https://www.kernel.org/doc/html/latest/userspace-api/perf_ring_buffer.html)
- [AOSP arm64 page-fault accounting](https://android.googlesource.com/kernel/arm64/+/f5269100977385d1fd4a5ef68e49631892cf4fe4/arch/arm64/mm/fault.c)
- [AOSP filemap fault handling](https://android.googlesource.com/kernel/common/+/refs/tags/android16-6.12-2025-06_r12/mm/filemap.c)
- [AOSP filemap tracepoint definition](https://android.googlesource.com/kernel/msm/+/android-8.1.0_r0.24/include/trace/events/filemap.h)
- [Android Simpleperf documentation](https://developer.android.com/ndk/guides/simpleperf)
- [AOSP Android 16 app profiling with Simpleperf](https://android.googlesource.com/platform/system/extras/+/android16-release/simpleperf/doc/android_application_profiling.md)
- [AOSP Android 16 `perf.drop_caches` init action](https://android.googlesource.com/platform/system/core/+/android16-qpr2-release/rootdir/init.rc)
- [AOSP shell SELinux policy for `perf.drop_caches`](https://android.googlesource.com/platform/system/sepolicy/+/android16-qpr1-release/private/shell.te)
- [AOSP ART `MADV_WILLNEED` change](https://android.googlesource.com/platform/art/+/0654153bc5ca22466697681bb6dc4bc8b379975e%5E%21/)
