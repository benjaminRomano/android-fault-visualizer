# Repository Guidelines

## Project Structure & Module Organization
Core automation lives in `faults.py`, which drives Perfetto queries and writes CSVs under `output/`. Shared pandas helpers sit in `utilities.py` for notebooks such as `visualizations.ipynb` and `compare.ipynb`. Reference material lives in `docs/`, while sample traces remain in `example/`. Support assets (`images/`, `ftrace.config`, plus executables `record_android_trace`, `trace_processor`, `scripts/format.sh`) should stay executable and aligned with the documented workflow.

## Build, Test, and Development Commands
```bash
uv sync                        # install deps into .venv
uv run faults.py --package com.example.app              # collect + process trace
uv run faults.py --package com.example.app --skip-collect --output example/output
./scripts/format.sh            # black + clear notebook outputs
uv run jupyter lab             # launch notebooks
```

## Coding Style & Naming Conventions
Target Python 3.13 with Black's defaults; run `./scripts/format.sh` before pushing. Use 4-space indentation, snake_case functions, PascalCase classes, and uppercase constants such as `PAGE_SIZE`. Keep filenames descriptive (e.g., `mapped_faults.csv`) and import shared logic from `utilities.py` instead of re-implementing it in notebooks.

## Testing Guidelines
The project has no automated test suite, so exercise changes by replaying `uv run faults.py --skip-collect --output example/output` and stepping through the notebooks. Preserve CSV schemas because the visualizations expect consistent columns. Attach screenshots or saved CSV diffs when behavior changes.

## Commit & Pull Request Guidelines
Follow the existing history: concise, imperative summaries with optional detail in the body and issue references (`Fixes #123`) when relevant. Group code, data, and documentation updates that belong together, and note any regenerated artifacts. PRs should list the commands you ran, point reviewers to updated notebooks, and flag large files excluded from the diff.

## Trace Collection Tips
Verify `adb root` succeeds before invoking `faults.py`; the script automatically falls back to `su -c` when needed. Replace the bundled `record_android_trace` and `trace_processor` binaries with upstream downloads rather than editing them, and stash raw traces in dated folders inside `output/` to keep comparisons reproducible.
