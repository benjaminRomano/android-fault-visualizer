# Android Fault Visualizer

This repo contains scripts to perform analysis on an Android application's page fault behavior on app startup.

**Note:** These scripts only work on x86 devices (i.e. emulators). See the caveats section for more details.

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
./trace.sh <package_name>
```

### Visualize

The post-processed data can be explored using the `visualizations.ipynb` notebook.

```python
# Render graph of faulted pages for a given file
# Tip: Use the generated `mapped_faults.csv` file to see what files were faulted in.
page_fault_chart("<file_name>", None, file_sizes, mapped_faults)

# Render graph of faulted pages for a file within an APK
# This is useful for when `.so` or `.dex` files are loaded directly from the APK.
#
# Note: Only in rare circumstances are DEX files loaded from the APK directly. More likely, the DEX files
# are read from a `.vdex` file.
page_fault_chart("<apk file>", "<.so file>", file_sizes, mapped_faults)
```

### Caveats

The scripts provided currently only work on `x86` devices (i.e. emulators). This is becuase the scripts use the `exceptions:page_faults_user` ftrace event which is not available in linux kernel for `arm` arch. Presumably, this is due to differences in how virtual memory and faults are implemented in the different architectures.

It may be possible to implement equivalent functionality for `arm` by instead tracing the `filemap:mm_filemap_add_to_page_cache` ftrace event. However, this will require a different mechanism to correlate page faults to files as this event returns an `inode` instead of the raw virtual memory address. With a slightly different mapping approach, it should be feasible to post-process the event to map it to a file name and a file relative offset.
