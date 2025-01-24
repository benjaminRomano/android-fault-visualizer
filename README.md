# Android Fault Visualizer

This repo contains scripts to perform analysis on an Android application's page fault behavior on app startup.
This is useful for understanding whether profile-guided optimizations intended to improve code locality are impactful.

Check out the [example directory](./example/README.md) to see how these scripts can be used to analyze Firefox's layout optimizations on their `.so` file.

<img src="./example/faults.png" />

## Getting Started

Install perfetto scripts:

```bash
# Install scripts to record traces
curl -O https://raw.githubusercontent.com/google/perfetto/master/tools/record_android_trace
chmod u+x record_android_trace

# Install scripts to run SQL queries against traces
curl -LO https://get.perfetto.dev/trace_processor
chmod +x ./trace_processor
```

Setup python environment:

```bash
python3 -m venv venv
source venv/bin/activate
# Note: It may be necessary to manually install additional dependencies
pip install -r requirements.in
```

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