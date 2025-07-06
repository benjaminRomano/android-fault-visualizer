# Android Fault Visualizer

A collection of scripts to analyze Android startup page fault patterns for a given app.

## Background

These scripts were created to help evaluate the efficacy of code locality optimizations (e.g. R8 Startup Profile and LLVM's Order Files). For large apps, code loading can be a significant performance bottleneck, particulary on devices with cheap flash memory (eMMC) or low available RAM (~2GB devices). Optimizing code locality can have very material impact (>10%) on startup performance while also reducing the overall code memory footprint.

Check out the [example](./example/README.md) to see how these scripts can be used to analyze Snapchat's DEX locality.

## Prerequisites

- Python 3.13
- [uv](https://github.com/astral-sh/uv) - A fast Python package installer and resolver
- A rooted device (preferred) or Android emulator

## Getting Started

### Setup

1. Download perfetto scripts:

```bash
# Install scripts to record traces
curl -O https://raw.githubusercontent.com/google/perfetto/master/tools/record_android_trace
chmod u+x record_android_trace

# Install scripts to run SQL queries against traces
curl -LO https://get.perfetto.dev/trace_processor
chmod +x ./trace_processor
```

2. Setup Python environment with `uv`:

```bash
source .venv/bin/activate
uv sync
```

## Usage

```bash
$ uv run faults.py
usage: faults.py [-h] {collect,process} ...

Process page faults

positional arguments:
  {collect,process}  Choose a command
    collect          Collect fault data
    process          Process fault data

options:
  -h, --help         show this help message and exit
```

# Collect and process a startup trace

### Collect and process startup trace

```bash
# When prompted that the tracing session has started, manually open the app.
# Once startup has completed, end the tracing session with `ctrl-C` to proceed.
# Optional: use `--output` to specify custom output directory.
python ./faults.py collect --package <package_name>

# Process the page faults.
# Optional: Use `--pull-apks` to get details about the file paged in from APK
python ./faults.py process --package <package_name>
```

### Visualize

The post-processed data can be explored by running the `visualizations.ipynb` notebook.

## Diffing

Results can be diffed by using the `compare.ipynb` notebook.

## Contributing

Contributions to improve these tools are welcome! Please feel free to submit issues and pull requests for any enhancements or bug fixes.

### Development Setup

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/AmazingFeature`)
3. Commit your changes (`git commit -m 'Add some AmazingFeature'`)
4. Push to the branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request
