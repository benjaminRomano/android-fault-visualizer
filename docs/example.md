# Example workflow

Capture at least two launches into separate directories:

```bash
uv run faults.py \
  --package com.example.app \
  --output output/baseline-01

uv run faults.py \
  --package com.example.app \
  --output output/reordered-01
```

Generate an interactive comparison:

```bash
uv run report.py output/baseline-01 \
  --label "Baseline" \
  --compare output/reordered-01 \
  --compare-label "R8 reordered" \
  --output output/comparison.html
```

Start with the cache-state metric. If checked app pages remained resident before
either launch, use `cache_residency.csv` to identify the files and avoid
interpreting the comparison as perfectly cold.

Next, check “Where startup faults came from” to identify the executable artifact
actually used by the installation. An AOT-compiled app commonly loads code from
ODEX/OAT and VDEX rather than directly from `classes.dex` in the APK. Supported
Android 10 VDEX captures split the per-dex payload from shared CompactDex data;
ODEX stays a compiled-code container unless method metadata supplies a safe
dex mapping. The selected-file sequence view then shows the page-access order.
The same logical source can be selected in the two-panel comparison.

Useful locality signals are:

- fewer major faults for the matched app artifact;
- a smaller median page jump for a similar amount of startup code;
- fewer large jumps and a higher nearby-step rate;
- stability across repeated cold launches.

Do not infer an R8 win from one startup-duration delta. Run multiple iterations
for each build with the same device image, ABI, compilation mode, activity, and
cache procedure, then compare distributions. Minor faults still belong in the
analysis: they are demanded pages that resolved without the kernel's major-fault
path and can reveal pages supplied by cache or readahead.
