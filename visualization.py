import csv
import numpy as np
import pandas as pd
import altair

mapped_faults = []
with open("mapped_faults.csv") as csv_file:
    mapped_faults = [row for row in csv.DictReader(csv_file)]

file_sizes = []
with open("file_sizes.csv") as csv_file:
    file_sizes = [row for row in csv.DictReader(csv_file)]

# Find relevant DEX Files for Youtube APK
dex_files = [
    entry
    for entry in file_sizes
    if entry["file_name"] == "/product/app/YouTube/YouTube.apk"
    and entry["zip_entry_name"].endswith(".dex")
]

dex_faults = [
    entry
    for entry in mapped_faults
    if entry["file_name"] == "/product/app/YouTube/YouTube.apk"
    and entry["zip_entry_name"].endswith(".dex")
]


x, y = np.meshgrid(range(-5, 5), range(-5, 5))
z = x**2 + y**2

# Convert this grid to columnar data expected by Altair
source = pd.DataFrame({"x": x.ravel(), "y": y.ravel(), "z": z.ravel()})
alt.Chart(source).mark_rect().encode(x="x:O", y="y:O", color="z:Q")

x, y = np.meshgrid(range(-5, 5), range(-5, 5))
