import csv
import os
import re
import subprocess
from typing import Optional
from zipfile import ZipFile

def find_map_entry(map_entries, addr: int) -> Optional[any]:
    """
    Find the /proc/pid/map entry matching address
    """
    for map_entry in map_entries:
        if addr >= map_entry['begin_address'] and addr <= map_entry['end_address']:
            return map_entry
    return None

def find_zip_entry(zip_entries, offset: int) -> Optional[any]:
    """
    Find the zip entry matching file offset. 

    This assumes that the zip entries are ordered by offset
    """
    for zip_entry in reversed(zip_entries):
        if zip_entry['offset'] < offset:
            return zip_entry
    return None


# Read file
user_page_fault_entries = []
with open("user_page_faults.csv") as csv_file:
    # Skip empty line
    next(csv_file)
    csv_reader = csv.DictReader(csv_file)

    for row in csv_reader:
        row['address'] = int(row['address'])
        user_page_fault_entries.append(row)

map_entries = []

# Example line:
# address space | perm | offset | dev (storage device) | inode | file path
# 12c00000-52c00000 rw-p 00000000 00:00 0      [anon:dalvik-main space (region space)]
# 77593e689000-77593e693000: 77593e689000-77593e693000 r--p 00148000 07:30 14     /apex/com.android.runtime/bin/linker64
with open("maps.txt") as file:
    for line in file.readlines():
        columns = re.split('\s{1,}', line.strip())

        addr_space = columns[0]
        offset = columns[2]
        inode = columns[4]

        # Only consider files
        if int(inode) == 0 or ' (deleted)' in line:
            continue

        file_path = columns[-1]

        [begin_addr, end_addr] = addr_space.split("-")

        map_entries.append({
            'begin_address': int(begin_addr, 16),
            'end_address': int(end_addr, 16),
            'file_name': file_path,
            'offset': int(offset, 16),
        })

pulled_zips = {}

for map_entry in map_entries:
    file_path = map_entry['file_name']
    if file_path in pulled_zips or not file_path.endswith(".apk"):
        continue

    file_name = os.path.basename(file_path)
    os.makedirs("artifacts", exist_ok=True)
    subprocess.run(f"adb pull {file_path} {os.path.join('artifacts', file_name)}", shell=True, stdout=subprocess.DEVNULL)
    pulled_zips[file_path] = []
    zf = ZipFile(os.path.join("artifacts", file_name))
    for zinfo in zf.infolist():
        pulled_zips[file_path].append({ 
            'file_name': zinfo.filename,
            'offset': int(zinfo.header_offset),
            'size': zinfo.compress_size,
        })

with open('file_sizes.csv', 'w', newline='') as csvfile:
    writer = csv.DictWriter(csvfile, fieldnames=['file_name', 'zip_entry_name', 'size', 'file_offset'])
    writer.writeheader()
    for file_path, zip_entries in pulled_zips.items():
        # Write zip entries
        for zip_entry in zip_entries:
            writer.writerow({
                'file_name': file_path,
                'zip_entry_name': zip_entry['file_name'],
                'size': zip_entry['size'],
                'file_offset': zip_entry['offset']
            })

    seen_files = set()
    for map_entry in map_entries:
        file_name = map_entry['file_name']
        if file_name not in seen_files or not any(extension in file_name for extension in [".vdex", ".apk", ".odex", ".oat", ".art"]):
            continue
        seen_files.add(file_name)
        file_size = subprocess.run(f"adb shell wc {map_entry['file_name']}", shell=True, stdout=subprocess.PIPE).stdout.decode("utf-8").split(" ")[3]
        writer.writerow({
            'file_name': map_entry['file_name'],
            'zip_entry_name': None,
            'size': file_size,
            'file_offset': 0
        })

page_fault_mappings = []

for user_page_fault in user_page_fault_entries:
    map_entry = find_map_entry(map_entries, user_page_fault['address'])
    if not map_entry:
        continue

    file_offset = user_page_fault['address'] - map_entry['begin_address'] + map_entry['offset']

    file_name = map_entry['file_name']

    zip_entry = None
    if file_name in pulled_zips:
        zip_entry = find_zip_entry(pulled_zips[file_name], file_offset)

    page_fault_mappings.append({
        'process_name': user_page_fault['process_name'],
        'thread_name': user_page_fault['thread_name'],
        'file_name': file_name,
        'zip_entry_name': zip_entry['file_name'] if zip_entry else None,
        'offset': file_offset
    })

with open('mapped_faults.csv', 'w', newline='') as csvfile:
    writer = csv.DictWriter(csvfile, fieldnames=['process_name', 'thread_name', 'file_name', 'zip_entry_name', 'offset'])
    writer.writeheader()
    for page_fault in page_fault_mappings:
        writer.writerow(page_fault)