import csv
import ipywidgets as widgets
from typing import Optional
import altair as alt
import numpy as np
import pandas as pd
import math
import os
from ipywidgets import interact

COLUMN_COUNT = 100
PAGE_SIZE = 4096


def load_mappings(output_dir: str = "output"):
    """
    Load the Fault mapping (file_name, offset) and the File Sizes (File Name, file size) from the csv files
    """
    mapped_faults = []
    with open(os.path.join(output_dir, "mapped_faults.csv")) as csv_file:
        for row in csv.DictReader(csv_file):
            row["zip_entry_name"] = (
                row["zip_entry_name"] if row["zip_entry_name"] else None
            )
            row["offset"] = int(row["offset"])
            row["ts"] = int(row["ts"])
            row["is_major"] = row["is_major"] == "True"
            mapped_faults.append(row)

    file_sizes = []
    with open(os.path.join(output_dir, "file_sizes.csv")) as csv_file:
        for row in csv.DictReader(csv_file):
            row["size"] = int(row["size"])
            row["zip_entry_name"] = (
                row["zip_entry_name"] if row["zip_entry_name"] else None
            )
            row["file_offset"] = int(row["file_offset"])
            file_sizes.append(row)

    return mapped_faults, file_sizes


def extract_faults(
    file_name: str, zip_entry_name: Optional[str], file_sizes, mapped_faults
):
    """
    Extract the faults mathcing the file name and optional zip entry name

    @returns a data frame with found faults, the size of the file, the offset of the zip entry within the file (applicably only if zip_entry_name is provided)
    """

    maybe_file = [
        file
        for file in file_sizes
        if file["file_name"] == file_name and file["zip_entry_name"] == zip_entry_name
    ]
    if not maybe_file:
        print(f"No file found: {file_name} - {zip_entry_name}")
        return pd.DataFrame([]), None, None

    file = maybe_file[0]

    file_size = file["size"]
    file_offset = file["file_offset"]

    return (
        pd.DataFrame(
            [
                entry
                for entry in mapped_faults
                if entry["file_name"] == file_name
                and (not zip_entry_name or entry["zip_entry_name"] == zip_entry_name)
            ]
        ),
        file_size,
        file_offset,
    )


def page_fault_chart(
    file_name: str, zip_entry_name: Optional[str], file_sizes, mapped_faults
):
    """
    Create graph showing page faults for a given file.

    Optionally, provide a `zip_entry_name`, to visualize a specific file within an .apk
    This is useful for applications that load native libraries directly from the APK (when `extractNativeLibs=false` is set in AndroidManifest.xml)
    or the DEX files are directly loaded from the APK (typically applicable for preloaded apps)
    """
    faults, file_size, file_offset = extract_faults(
        file_name, zip_entry_name, file_sizes, mapped_faults
    )
    if not len(faults):
        print(f"No faults found: {file_name} - {zip_entry_name}")
        return

    rows = math.ceil(math.ceil(file_size / PAGE_SIZE) / COLUMN_COUNT)
    x, y = np.meshgrid(range(0, COLUMN_COUNT), range(0, rows), indexing="ij")

    fault_offsets = faults["offset"].tolist()

    pages_accessed = set()

    for fault_offset in fault_offsets:
        offset = fault_offset - file_offset
        page = math.floor(offset / PAGE_SIZE)
        x_idx = page % COLUMN_COUNT
        y_idx = math.floor(page / COLUMN_COUNT)
        pages_accessed.add((x_idx, y_idx))

    z = np.array(x)
    for idx, _ in np.ndenumerate(x):
        z[idx] = 1 if idx in pages_accessed else 0

    source = pd.DataFrame({"x": x.ravel(), "y": y.ravel(), "z": z.ravel()})
    return (
        alt.Chart(source)
        .mark_rect()
        .transform_calculate(
            offset="(datum.x + datum.y * 50) * 4096",
        )
        .encode(
            x="x:O",
            y="y:O",
            color="z:N",
            tooltip=["offset:Q"],
        )
        .properties(title=f"Page Faults for {file_name} - {zip_entry_name}")
    )


def time_based_page_fault_chart(file_name, zip_entry_name, file_sizes, mapped_faults):
    """
    Generate an interactive chart showing page faults over time
    """

    faults, file_size, file_offset = extract_faults(
        file_name, zip_entry_name, file_sizes, mapped_faults
    )

    if not len(faults):
        print(f"No faults found: {file_name} - {zip_entry_name}")
        return

    rows = math.ceil(math.ceil(file_size / PAGE_SIZE) / COLUMN_COUNT)
    t, x, y = np.meshgrid(
        range(0, len(faults)), range(0, COLUMN_COUNT), range(0, rows), indexing="ij"
    )

    fault_offsets = faults["offset"].tolist()

    slider = alt.binding_range(min=0, max=len(faults) - 1, step=1)
    select_time = alt.selection_point(name="time", fields=["t"], bind=slider)

    pages_accessed = set()

    for t_idx in range(0, len(faults)):
        for fault_offset in fault_offsets[:t_idx]:
            offset = fault_offset - file_offset
            page = math.floor(offset / PAGE_SIZE)
            x_idx = page % COLUMN_COUNT
            y_idx = math.floor(page / COLUMN_COUNT)
            pages_accessed.add((t_idx, x_idx, y_idx))

    z = np.array(t)
    for idx, _ in np.ndenumerate(t):
        z[idx] = 1 if idx in pages_accessed else 0

    offsets = np.array(t)
    for idx, _ in np.ndenumerate(t):
        offsets[idx] = (idx[1] + idx[2] * 50) * 4096

    # Convert this grid to columnar data expected by Altair
    # Note: This is not very efficient
    source = pd.DataFrame(
        {
            "x": x.ravel(),
            "y": y.ravel(),
            "z": z.ravel(),
            "t": t.ravel(),
            "offset": offsets.ravel(),
        }
    )

    def chart(t1, t2):
        t = t1 or t2
        f = source[source["t"].eq(t)]
        return (
            alt.Chart(f)
            .mark_rect()
            .encode(
                x="x:O",
                y="y:O",
                color="z:N",
                tooltip=["offset:Q"],
            )
            .properties(title=f"Page Faults for {file_name} - {zip_entry_name}")
            .display()
        )

    return interact(
        chart,
        t1=widgets.Play(
            value=0,
            min=0,
            max=len(faults) - 1,
            step=1,
            description="Press play",
            disabled=False,
        ),
        t2=widgets.IntSlider(min=0, max=len(faults) - 1, step=1),
    )


def fault_time_series(faults):
    """
    Create a time series where y-axis is fault offset and x-axis is fault index

    This is useful for more concisely visualizing the page fault behaviors (e.g. random access or contiguous page faults)
    """
    indexed_faults = faults.copy().reset_index()

    min_ts = min(indexed_faults["ts"].to_list())

    chart1 = (
        alt.Chart(indexed_faults)
        .transform_calculate(
            major_count="datum.is_major ? 1 : 0", relative_ts=f"datum.ts - {min_ts}"
        )
        .mark_line()
        .encode(
            x=alt.X("relative_ts:Q", title="Time", axis=alt.Axis(labels=False)),
            y=alt.Y("cumulative_major_faults:Q"),
        )
        .transform_window(cumulative_major_faults="sum(major_count)")
        .properties(width=1600)
    )

    chart2 = (
        alt.Chart(indexed_faults)
        .transform_calculate(
            page_number=f"datum.offset / 4096", relative_ts=f"datum.ts - {min_ts}"
        )
        .mark_point(filled=True)
        .encode(
            x=alt.X("relative_ts:Q", title="Time", axis=alt.Axis(labels=False)),
            y=alt.Y("page_number:Q", title="Page Number"),
            color=alt.Color("is_major:N"),
            order=alt.Order("is_major:N", sort="ascending"),
        )
        .properties(width=1600)
    )

    return alt.vconcat(chart1, chart2)
