import csv
from typing import Optional
import pandas as pd
import os

# TODO: Support variable page sizes. Android will soon support 16KB pages
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
    file_name: str,
    zip_entry_name: Optional[str],
    file_sizes,
    mapped_faults,
    include_minor: bool,
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

    faults = pd.DataFrame(
        [
            entry
            for entry in mapped_faults
            if entry["file_name"] == file_name
            and (not zip_entry_name or entry["zip_entry_name"] == zip_entry_name)
        ]
    )

    if not include_minor:
        faults = faults[faults["is_major"]]

    # Compute delta between fault offsets
    faults["offset"] = faults["offset"].div(PAGE_SIZE)
    faults["offset_diff"] = faults["offset"].diff()

    # Normalize timestamps
    faults["ts"] = faults["ts"] - faults["ts"].min()
    faults.reset_index(drop=True, inplace=True)
    return faults, file_size, file_offset
