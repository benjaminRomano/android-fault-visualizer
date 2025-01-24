import argparse
import csv
import os
import re
import shutil
import subprocess
from typing import Optional, Dict, List, Tuple
from zipfile import ZipFile


def adb_root_command() -> str:
    if has_root():
        return "adb shell"
    else:
        return "adb shell su -c"


def has_root() -> bool:
    return (
        "adbd cannot run as root in production builds"
        not in subprocess.check_output("adb root", shell=True, text=True)
    )


def find_map_entry(map_entries, addr: int) -> Optional[any]:
    """
    Find the /proc/pid/map entry matching address
    """
    for map_entry in map_entries:
        if map_entry["begin_address"] <= addr <= map_entry["end_address"]:
            return map_entry
    return None


def find_zip_entry(zip_entries, offset: int) -> Optional[any]:
    """
    Find the zip entry matching file offset.

    This assumes that the zip entries are ordered by offset
    """
    for zip_entry in reversed(zip_entries):
        if zip_entry["offset"] < offset:
            return zip_entry
    return None


def parse_user_page_faults(
    process_name: str, output_dir: str, trace: str
) -> List[Dict]:
    query = f"""
        INCLUDE PERFETTO MODULE android.startup.startups;

        SELECT
        ftrace_event.ts,
        process.name as process_name,
        thread.name as thread_name,
        EXTRACT_ARG(ftrace_event.arg_set_id, "address")  as address,
        EXTRACT_ARG(ftrace_event.arg_set_id, "ip")  as ip
        FROM ftrace_event
            left join thread ON ftrace_event.utid = thread.utid
            left join process ON thread.upid = process.upid
        WHERE
        ftrace_event.name = 'page_fault_user'
        AND ftrace_event.ts >= (SELECT MIN(ts) from android_startups WHERE package = process.name)
        AND ftrace_event.ts <= (SELECT MIN(ts_end) from android_startups WHERE package = process.name)
        AND process.name = '{process_name}'
        ORDER BY ts ASC
    """

    with open("/tmp/query.sql", "w") as file:
        file.write(query)

    subprocess.run(
        f"./trace_processor -q /tmp/query.sql {trace} > {os.path.join(output_dir, 'faults.csv')}",
        check=True,
        shell=True,
    )

    user_page_fault_entries = []
    with open(os.path.join(output_dir, "faults.csv")) as csv_file:
        next(csv_file)
        csv_reader = csv.DictReader(csv_file)

        for row in csv_reader:
            row["address"] = int(row["address"])
            user_page_fault_entries.append(row)

    return user_page_fault_entries


def parse_add_to_page_cache(
    process_name: str, output_dir: str, trace: str
) -> List[Dict]:
    query = f"""
        INCLUDE PERFETTO MODULE android.startup.startups;

        SELECT
        ftrace_event.ts,
        process.name as process_name,
        thread.name as thread_name,
        EXTRACT_ARG(ftrace_event.arg_set_id, "s_dev")  as sdev,
        EXTRACT_ARG(ftrace_event.arg_set_id, "i_ino")  as inode,
        EXTRACT_ARG(ftrace_event.arg_set_id, "index")  as offset
        FROM ftrace_event
            left join thread ON ftrace_event.utid = thread.utid
            left join process ON thread.upid = process.upid
        WHERE
        ftrace_event.name = 'mm_filemap_add_to_page_cache'
        AND ftrace_event.ts >= (SELECT MIN(ts) from android_startups WHERE package = process.name)
        AND ftrace_event.ts <= (SELECT MIN(ts_end) from android_startups WHERE package = process.name)
        AND process.name = '{process_name}'
        ORDER BY ts ASC
    """

    with open("/tmp/query.sql", "w") as file:
        file.write(query)

    subprocess.run(
        f"./trace_processor -q /tmp/query.sql {trace} > {os.path.join(output_dir, 'faults.csv')}",
        check=True,
        shell=True,
    )

    user_page_fault_entries = []
    with open(os.path.join(output_dir, "faults.csv")) as csv_file:
        next(csv_file)
        csv_reader = csv.DictReader(csv_file)

        for row in csv_reader:
            row["sdev"] = int(row["sdev"])
            row["inode"] = int(row["inode"])
            # Use byte offests to match user_page_faults
            row["offset"] = int(row["offset"]) * 4096
            user_page_fault_entries.append(row)

    return user_page_fault_entries


def dump_maps(package_name: str, output_dir: str):
    pid = subprocess.check_output(
        f"adb shell pidof {package_name}", encoding="utf-8", shell=True
    ).strip()
    subprocess.run(
        f"{adb_root_command()} 'cat /proc/{pid}/maps' > {os.path.join(output_dir, 'maps.txt')}",
        shell=True,
        check=True,
    )


def dump_inodes(output_dir: str):
    print("Dumping inodes...")

    with open(os.path.join(output_dir, "inodes.txt"), "w") as f:
        f.write(
            subprocess.check_output(
                [
                    "adb",
                    "shell",
                    "su",
                    "-c",
                    "find /apex /system /data /vendor -print0 \| xargs -0 stat -c '\"%d %i %n\"'",
                ],
                encoding="utf-8",
            ).strip()
        )


def collect_trace(package_name: str, output_dir: str):
    subprocess.check_call(f"adb shell am force-stop {package_name}", shell=True)
    subprocess.check_call("adb shell su -c '\"echo 3 > /proc/sys/vm/drop_caches\"'", shell=True)

    p = None
    try:
        p = subprocess.Popen(
            f"./record_android_trace -c ftrace.config -n -o {os.path.join(output_dir, 'faults.pftrace')} -tt",
            stdin=subprocess.PIPE,
            shell=True,
        )
        p.wait()
    except KeyboardInterrupt:
        pass
    finally:
        if p:
            p.wait()

def get_arch() -> str:
    return subprocess.check_output(
        "adb shell getprop ro.product.cpu.abi", shell=True, text=True
    ).strip()


def parse_maps(output_dir: str) -> List[Dict]:
    map_entries = []

    # Example line:
    # address space | perm | offset | dev (storage device) | inode | file path
    # 12c00000-52c00000 rw-p 00000000 00:00 0      [anon:dalvik-main space (region space)]
    # 77593e689000-77593e693000: 77593e689000-77593e693000 r--p 00148000 07:30 14     /apex/com.android.runtime/bin/linker64
    with open(f"{output_dir}/maps.txt") as file:
        for line in file.readlines():
            columns = re.split("\s+", line.strip())

            addr_space = columns[0]
            offset = columns[2]
            inode = columns[4]

            # Only consider files on disk
            if int(inode) == 0 or " (deleted)" in line:
                continue

            file_path = columns[-1]

            [begin_addr, end_addr] = addr_space.split("-")

            map_entries.append(
                {
                    "begin_address": int(begin_addr, 16),
                    "end_address": int(end_addr, 16),
                    "file_name": file_path,
                    "offset": int(offset, 16),
                }
            )

    return map_entries


def pull_apks(file_names: List[str], output_dir: str) -> Dict[str, List[Dict]]:
    print("Pulling APKs...")
    # Pull APKs to compute the offsets of files within
    pulled_apks = {}

    for file_path in file_names:
        if file_path in pulled_apks or not file_path.endswith(".apk"):
            continue

        file_name = os.path.basename(file_path)
        os.makedirs(os.path.join(output_dir, "artifacts"), exist_ok=True)
        result = subprocess.run(
            f"adb pull {file_path} {os.path.join(output_dir, 'artifacts', file_name)}",
            shell=True,
            stdout=subprocess.DEVNULL,
        )
        if result.returncode != 0:
            print(f"Failed to pull: {file_path}")
            continue

        pulled_apks[file_path] = []
        zf = ZipFile(os.path.join(output_dir, "artifacts", file_name))
        for zinfo in zf.infolist():
            pulled_apks[file_path].append(
                {
                    "file_name": zinfo.filename,
                    "offset": int(zinfo.header_offset),
                    "size": zinfo.compress_size,
                }
            )

    return pulled_apks


def compute_inode_mapping(output_dir: str) -> Dict[Tuple[int, int], str]:
    with open(os.path.join(output_dir, "inodes.txt"), "r") as f:
        inode_lines = f.read().split("\n")

    inode_re = re.compile("^(?P<dev>[0-9]+)\s(?P<inode>[0-9]+)\s(?P<filename>.*)$")
    inode_mapping = {}
    for line in inode_lines:
        match = inode_re.match(line)
        dev = int(match.group("dev"))
        inode = int(match.group("inode"))
        file_name = match.group("filename")
        inode_mapping[(dev, inode)] = file_name

    return inode_mapping


# Report the file sizes and APK entry sizes in a csv file
def compute_file_sizes(
    file_names: List[str], output_dir: str, pulled_apks: Dict[str, List[Dict]] = {}
):
    print("Computing file sizes...")
    with open(os.path.join(output_dir, "file_sizes.csv"), "w", newline="") as csvfile:
        writer = csv.DictWriter(
            csvfile, fieldnames=["file_name", "zip_entry_name", "size", "file_offset"]
        )
        writer.writeheader()
        for file_path, zip_entries in pulled_apks.items():
            # Write zip entries
            for zip_entry in zip_entries:
                writer.writerow(
                    {
                        "file_name": file_path,
                        "zip_entry_name": zip_entry["file_name"],
                        "size": zip_entry["size"],
                        "file_offset": zip_entry["offset"],
                    }
                )

        seen_files = set()
        # To speed up processing only compute file sizes files related to application code
        for file_name in file_names:
            if file_name in seen_files or not is_maybe_package_code(file_name):
                continue
            seen_files.add(file_name)
            file_size = (
                subprocess.run(
                    f"adb shell wc {file_name}",
                    shell=True,
                    check=True,
                    stdout=subprocess.PIPE,
                )
                .stdout.decode("utf-8")
                .split(" ")[2]
            )
            writer.writerow(
                {
                    "file_name": file_name,
                    "zip_entry_name": None,
                    "size": file_size,
                    "file_offset": 0,
                }
            )


def is_maybe_package_code(file_name: str):
    return any(
        file_name.endswith(extension) for extension in [".so", ".vdex", ".apk"]
    ) and not any(
        file_name.startswith(prefix)
        for prefix in ["/system/", "/system_ext", "/apex/", "/vendor/"]
    )


def compute_page_cache_mappings(
    page_cache_entries,
    inode_mappings: Dict[Tuple[int, int], str],
    pulled_apks: Dict[str, List[Dict]],
    output_dir: str,
):
    page_fault_mappings = []

    page_faulted_sections = {}

    for page_cache_entry in page_cache_entries:
        inode_entry = inode_mappings.get(
            (page_cache_entry["sdev"], page_cache_entry["inode"]), None
        )

        if not inode_entry:
            continue

        file_name = inode_entry
        file_offset = page_cache_entry["offset"]

        if not is_maybe_package_code(file_name):
            continue

        zip_entry = None
        if file_name in pulled_apks:
            zip_entry = find_zip_entry(pulled_apks[file_name], file_offset)

        fetched_pages = page_faulted_sections.get(file_name, None)
        if not fetched_pages:
            fetched_pages = set()
        is_major = file_offset not in fetched_pages

        # Assume 4KB page size with 128KB lookahead
        fetched_pages.add(file_offset)
        for n in range(1, 33):
            fetched_pages.add(file_offset + 4096 * n)
        page_faulted_sections[file_name] = fetched_pages

        page_fault_mappings.append(
            {
                "ts": page_cache_entry["ts"],
                "process_name": page_cache_entry["process_name"],
                "thread_name": page_cache_entry["thread_name"],
                "file_name": file_name,
                "zip_entry_name": zip_entry["file_name"] if zip_entry else None,
                "offset": file_offset,
                "is_major": is_major,
            }
        )

    with open(
        os.path.join(output_dir, "mapped_faults.csv"), "w", newline=""
    ) as csvfile:
        writer = csv.DictWriter(
            csvfile,
            fieldnames=[
                "ts",
                "process_name",
                "thread_name",
                "file_name",
                "zip_entry_name",
                "offset",
                "is_major",
            ],
        )
        writer.writeheader()
        for page_fault in page_fault_mappings:
            writer.writerow(page_fault)


def compute_user_page_fault_mappings(
    user_page_fault_entries, map_entries, pulled_apks, output_dir
):
    page_fault_mappings = []

    page_faulted_sections = {}

    for user_page_fault in user_page_fault_entries:
        map_entry = find_map_entry(map_entries, user_page_fault["address"])
        if not map_entry:
            continue

        file_name = map_entry["file_name"]

        if not is_maybe_package_code(file_name):
            continue

        file_offset = (
            user_page_fault["address"]
            - map_entry["begin_address"]
            + map_entry["offset"]
        )

        zip_entry = None
        if file_name in pulled_apks:
            zip_entry = find_zip_entry(pulled_apks[file_name], file_offset)

        fetched_pages = page_faulted_sections.get(file_name, None)
        if not fetched_pages:
            fetched_pages = set()
        page_aligned_offset = file_offset - file_offset % 4096
        is_major = page_aligned_offset not in fetched_pages

        # Assume 4KB page size with 128KB lookahead
        fetched_pages.add(page_aligned_offset)
        for n in range(1, 33):
            fetched_pages.add(page_aligned_offset + 4096 * n)
        page_faulted_sections[file_name] = fetched_pages

        page_fault_mappings.append(
            {
                "ts": user_page_fault["ts"],
                "process_name": user_page_fault["process_name"],
                "thread_name": user_page_fault["thread_name"],
                "file_name": file_name,
                "zip_entry_name": zip_entry["file_name"] if zip_entry else None,
                "offset": file_offset,
                "is_major": is_major,
            }
        )

    with open(
        os.path.join(output_dir, "mapped_faults.csv"), "w", newline=""
    ) as csvfile:
        writer = csv.DictWriter(
            csvfile,
            fieldnames=[
                "ts",
                "process_name",
                "thread_name",
                "file_name",
                "zip_entry_name",
                "offset",
                "is_major",
            ],
        )
        writer.writeheader()
        for page_fault in page_fault_mappings:
            writer.writerow(page_fault)


def main():
    parser = argparse.ArgumentParser(description="Process page faults")

    subparsers = parser.add_subparsers(dest="command", help="Choose a command")

    collect = subparsers.add_parser("collect", help="Collect fault data")
    collect.add_argument(
        "--output", type=str, default="output", help="Output directory"
    )
    collect.add_argument("--package", type=str, required=True, help="Package name")

    process = subparsers.add_parser("process", help="Process fault data")

    process.add_argument("--package", type=str, required=True, help="Package name")
    process.add_argument(
        "--output",
        type=str,
        default="output",
        help="Output directory to process",
    )
    process.add_argument(
        "--pull-apks",
        action="store_true",
        default=False,
        help="Whether to pull APKs to get details on which file a page fault in APK corresponds to",
    )

    args = parser.parse_args()
    if args.command == "collect":
        shutil.rmtree(args.output, ignore_errors=True)
        os.makedirs(args.output, exist_ok=True)

        collect_trace(args.package, args.output)

        if "arm" in get_arch():
            dump_inodes(args.output)
        else:
            dump_maps(args.package, args.output)
    elif args.command == "process":
        if "arm" in get_arch():
            page_cache_entries = parse_add_to_page_cache(
                args.package, args.output, os.path.join(args.output, "faults.pftrace")
            )

            inode_mappings = compute_inode_mapping(args.output)

            file_names = list(
                set(
                    filter(
                        lambda x: x is not None,
                        [
                            inode_mappings.get((e["sdev"], e["inode"]), None)
                            for e in page_cache_entries
                        ],
                    )
                )
            )

            pulled_apks = pull_apks(file_names, args.output) if args.pull_apks else {}

            compute_file_sizes(file_names, args.output, pulled_apks)
            compute_page_cache_mappings(
                page_cache_entries, inode_mappings, pulled_apks, args.output
            )
        else:
            user_page_faults = parse_user_page_faults(
                args.package, args.output, os.path.join(args.output, "faults.pftrace")
            )
            map_entries = parse_maps(args.output)

            file_names = list(set([e["file_name"] for e in map_entries]))

            pulled_apks = pull_apks(file_names, args.output) if args.pull_apks else {}
            compute_file_sizes(file_names, args.output, pulled_apks)
            compute_user_page_fault_mappings(
                user_page_faults, map_entries, pulled_apks, args.output
            )
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
