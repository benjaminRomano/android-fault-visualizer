import bisect
import csv
import re
import struct
from dataclasses import dataclass
from pathlib import Path
from typing import Optional
from zipfile import ZIP_STORED, ZipFile


@dataclass(frozen=True)
class MapEntry:
    begin_address: int
    end_address: int
    permissions: str
    file_offset: int
    device: int
    inode: int
    file_name: Optional[str]


@dataclass(frozen=True)
class ZipEntry:
    file_name: str
    header_offset: int
    data_offset: int
    data_end: int
    compressed_size: int
    uncompressed_size: int
    compression: str


@dataclass(frozen=True)
class MappingEvent:
    timestamp_ns: int
    mapping: MapEntry


@dataclass(frozen=True)
class VdexAnalysis:
    format_version: str
    stored_checksums: tuple[int, ...]
    dex_ranges: tuple[ZipEntry, ...]
    identities_verified: bool
    verification_note: str


def sql_string(value: str) -> str:
    return "'" + value.replace("'", "''") + "'"


def is_app_owned_path(file_name: str, package: str) -> bool:
    """Match an exact package path segment or hashed /data/app install segment."""
    escaped = re.escape(package)
    return re.search(rf"(?:^|/){escaped}(?:/|-[^/]+(?:/|$)|$)", file_name) is not None


def linux_device_number(device: str) -> int:
    major_text, minor_text = device.split(":", 1)
    major = int(major_text, 16)
    minor = int(minor_text, 16)
    return (minor & 0xFF) | (major << 8) | ((minor & ~0xFF) << 12)


MAPS_PATTERN = re.compile(
    r"^(?P<begin>[0-9a-fA-F]+)-(?P<end>[0-9a-fA-F]+)\s+"
    r"(?P<permissions>\S+)\s+(?P<offset>[0-9a-fA-F]+)\s+"
    r"(?P<device>[0-9a-fA-F]+:[0-9a-fA-F]+)\s+"
    r"(?P<inode>\d+)(?:\s+(?P<path>.*))?$"
)


def parse_maps_text(text: str) -> list[MapEntry]:
    entries = []
    for line_number, line in enumerate(text.splitlines(), start=1):
        match = MAPS_PATTERN.match(line)
        if not match:
            raise ValueError(f"Malformed maps line {line_number}: {line!r}")
        path = match.group("path")
        entries.append(
            MapEntry(
                begin_address=int(match.group("begin"), 16),
                end_address=int(match.group("end"), 16),
                permissions=match.group("permissions"),
                file_offset=int(match.group("offset"), 16),
                device=linux_device_number(match.group("device")),
                inode=int(match.group("inode")),
                file_name=path,
            )
        )
    return sorted(entries, key=lambda entry: entry.begin_address)


def parse_maps(output_dir: str | Path) -> list[MapEntry]:
    return parse_maps_text((Path(output_dir) / "maps.txt").read_text())


def find_map_entry(map_entries: list[MapEntry], address: int) -> Optional[MapEntry]:
    if not map_entries:
        return None
    begins = [entry.begin_address for entry in map_entries]
    index = bisect.bisect_right(begins, address) - 1
    if index < 0:
        return None
    entry = map_entries[index]
    # /proc/<pid>/maps ranges are half-open: [begin, end).
    return entry if entry.begin_address <= address < entry.end_address else None


def parse_mapping_events(output_dir: Path, pid: int) -> list[MappingEvent]:
    events = []
    with (output_dir / "mapping_events.csv").open() as file:
        for row in csv.DictReader(file):
            if int(row["pid"]) != pid:
                continue
            protection = int(row["protection"])
            permissions = "".join(
                [
                    "r" if protection & 1 else "-",
                    "w" if protection & 2 else "-",
                    "x" if protection & 4 else "-",
                    "s" if int(row["flags"]) & 1 else "p",
                ]
            )
            begin = int(row["address"], 16)
            events.append(
                MappingEvent(
                    timestamp_ns=int(row["timestamp_ns"]),
                    mapping=MapEntry(
                        begin_address=begin,
                        end_address=begin + int(row["length"], 16),
                        permissions=permissions,
                        file_offset=int(row["file_offset"], 16),
                        device=linux_device_number(
                            f"{int(row['device_major']):x}:"
                            f"{int(row['device_minor']):x}"
                        ),
                        inode=int(row["inode"]),
                        file_name=row["file_name"] or None,
                    ),
                )
            )
    return sorted(events, key=lambda event: event.timestamp_ns)


def find_map_entry_at(
    snapshot: list[MapEntry],
    events: list[MappingEvent],
    address: int,
    timestamp_ns: int,
) -> Optional[MapEntry]:
    matching_events = [
        event
        for event in events
        if event.mapping.begin_address <= address < event.mapping.end_address
    ]
    for event in reversed(matching_events):
        if event.timestamp_ns <= timestamp_ns:
            return event.mapping
    # A future event for this address means the final snapshot may describe a
    # mapping that did not exist yet. Snapshot fallback is only safe for
    # inherited mappings that produced no MMAP2 event after collection began.
    return None if matching_events else find_map_entry(snapshot, address)


def read_zip_entries(path: Path) -> list[ZipEntry]:
    entries = []
    with ZipFile(path) as archive, path.open("rb") as raw_file:
        for info in archive.infolist():
            raw_file.seek(info.header_offset)
            header = raw_file.read(30)
            if len(header) != 30:
                raise ValueError(f"Truncated local ZIP header for {info.filename}")
            (
                signature,
                _version,
                _flags,
                _method,
                _time,
                _date,
                _crc,
                _compressed_size,
                _uncompressed_size,
                name_length,
                extra_length,
            ) = struct.unpack("<IHHHHHIIIHH", header)
            if signature != 0x04034B50:
                raise ValueError(f"Invalid local ZIP header for {info.filename}")
            data_offset = info.header_offset + 30 + name_length + extra_length
            entries.append(
                ZipEntry(
                    file_name=info.filename,
                    header_offset=info.header_offset,
                    data_offset=data_offset,
                    data_end=data_offset + info.compress_size,
                    compressed_size=info.compress_size,
                    uncompressed_size=info.file_size,
                    compression=(
                        "stored"
                        if info.compress_type == ZIP_STORED
                        else f"method-{info.compress_type}"
                    ),
                )
            )
    return sorted(entries, key=lambda entry: entry.data_offset)


def _verified_vdex_names(
    stored_checksums: list[int],
    apk_dex_identities: Optional[list[tuple[str, int]]],
) -> list[str]:
    if apk_dex_identities is None:
        return []
    apk_checksums = [checksum for _, checksum in apk_dex_identities]
    if len(apk_checksums) != len(stored_checksums):
        return []
    if apk_checksums != stored_checksums:
        return []
    return [name for name, _ in apk_dex_identities]


def _read_vdex_dex_ranges(
    data: bytes,
    dex_begin: int,
    dex_end: int,
    number_of_dex_files: int,
    verified_names: list[str],
    *,
    quickening_prefix_size: int,
    compression_prefix: str,
) -> list[ZipEntry]:
    entries: list[ZipEntry] = []
    cursor = dex_begin
    for index in range(number_of_dex_files):
        dex_start = cursor + quickening_prefix_size
        if dex_start + 36 > dex_end:
            return []
        magic = data[dex_start : dex_start + 4]
        if magic not in (b"dex\n", b"cdex"):
            return []
        file_size = struct.unpack_from("<I", data, dex_start + 32)[0]
        dex_payload_end = dex_start + file_size
        if file_size < 112 or dex_payload_end > dex_end:
            return []
        verified_name = verified_names[index] if index < len(verified_names) else None
        section_name = verified_name or f"dex #{index + 1} (identity unverified)"
        entries.append(
            ZipEntry(
                file_name=section_name,
                header_offset=cursor,
                data_offset=dex_start,
                data_end=dex_payload_end,
                compressed_size=file_size,
                uncompressed_size=file_size,
                compression=(
                    f"{compression_prefix}-compact"
                    if magic == b"cdex"
                    else f"{compression_prefix}-standard"
                ),
            )
        )
        cursor = (dex_payload_end + 3) & ~3
    return entries if cursor == dex_end else []


def _read_android10_vdex(
    path: Path,
    apk_dex_identities: Optional[list[tuple[str, int]]] = None,
) -> Optional[VdexAnalysis]:
    data = path.read_bytes()
    header_size = 28
    if (
        len(data) < header_size
        or data[:4] != b"vdex"
        or data[4:8] != b"021\0"
        or data[8:12] != b"002\0"
    ):
        return None

    number_of_dex_files, _, _, _ = struct.unpack_from("<4I", data, 12)
    if number_of_dex_files == 0 or number_of_dex_files > 10_000:
        return None
    if header_size + 4 * number_of_dex_files > len(data):
        return None
    vdex_checksums = list(
        struct.unpack_from(f"<{number_of_dex_files}I", data, header_size)
    )
    verified_dex_names = _verified_vdex_names(vdex_checksums, apk_dex_identities)
    dex_section_header_offset = header_size + 4 * number_of_dex_files
    if dex_section_header_offset + 12 > len(data):
        return None
    dex_size, dex_shared_data_size, _ = struct.unpack_from(
        "<3I", data, dex_section_header_offset
    )
    dex_begin = dex_section_header_offset + 12
    dex_end = dex_begin + dex_size
    shared_end = dex_end + dex_shared_data_size
    if dex_end > len(data) or shared_end > len(data):
        return None

    entries = _read_vdex_dex_ranges(
        data,
        dex_begin,
        dex_end,
        number_of_dex_files,
        verified_dex_names,
        quickening_prefix_size=4,
        compression_prefix="vdex-021",
    )
    if not entries and dex_size:
        return None
    verified = len(verified_dex_names) == number_of_dex_files
    return VdexAnalysis(
        format_version="021/002",
        stored_checksums=tuple(vdex_checksums),
        dex_ranges=tuple(entries),
        identities_verified=verified,
        verification_note=(
            "All ART location checksums match the APK dex entries in order."
            if verified
            else "APK dex identity was not assigned because the complete ordered "
            "checksum set did not match."
        ),
    )


def _read_sectioned_vdex(
    path: Path,
    apk_dex_identities: Optional[list[tuple[str, int]]] = None,
) -> Optional[VdexAnalysis]:
    """Read ART's sectioned VDEX 027 format used by Android 12 through 16."""
    data = path.read_bytes()
    header_size = 12
    if len(data) < header_size or data[:4] != b"vdex" or data[4:8] != b"027\0":
        return None
    number_of_sections = struct.unpack_from("<I", data, 8)[0]
    if number_of_sections < 3 or number_of_sections > 64:
        return None
    section_table_end = header_size + number_of_sections * 12
    if section_table_end > len(data):
        return None

    sections: dict[int, tuple[int, int]] = {}
    occupied: list[tuple[int, int]] = []
    for index in range(number_of_sections):
        kind, offset, size = struct.unpack_from("<3I", data, header_size + index * 12)
        if kind in sections or offset > len(data) or size > len(data) - offset:
            return None
        if size and offset < section_table_end:
            return None
        sections[kind] = (offset, size)
        if size:
            occupied.append((offset, offset + size))
    occupied.sort()
    if any(left[1] > right[0] for left, right in zip(occupied, occupied[1:])):
        return None

    checksum_section = sections.get(0)
    dex_section = sections.get(1)
    verifier_section = sections.get(2)
    if checksum_section is None or dex_section is None or verifier_section is None:
        return None
    checksum_offset, checksum_size = checksum_section
    if checksum_size % 4:
        return None
    number_of_dex_files = checksum_size // 4
    stored_checksums = list(
        struct.unpack_from(f"<{number_of_dex_files}I", data, checksum_offset)
    )
    verified_names = _verified_vdex_names(stored_checksums, apk_dex_identities)
    dex_offset, dex_size = dex_section
    entries: list[ZipEntry] = []
    if dex_size:
        entries = _read_vdex_dex_ranges(
            data,
            dex_offset,
            dex_offset + dex_size,
            number_of_dex_files,
            verified_names,
            quickening_prefix_size=0,
            compression_prefix="vdex-027",
        )
        if len(entries) != number_of_dex_files:
            return None
    verified = number_of_dex_files > 0 and len(verified_names) == number_of_dex_files
    return VdexAnalysis(
        format_version="027",
        stored_checksums=tuple(stored_checksums),
        dex_ranges=tuple(entries),
        identities_verified=verified,
        verification_note=(
            "All ART location checksums match the APK dex entries in order."
            if verified
            else "APK dex identity was not assigned because the complete ordered "
            "checksum set did not match."
        ),
    )


def read_vdex(
    path: Path,
    apk_dex_identities: Optional[list[tuple[str, int]]] = None,
) -> Optional[VdexAnalysis]:
    """Parse supported VDEX formats without guessing at unknown layouts."""
    return _read_android10_vdex(path, apk_dex_identities) or _read_sectioned_vdex(
        path, apk_dex_identities
    )


def read_apk_dex_identities(path: Path) -> list[tuple[str, int]]:
    """Read APK multidex names/location checksums in ART's canonical order.

    ART's location checksum for a dex opened from a ZIP is the ZIP entry's
    CRC32, not the Adler-32 checksum embedded in the DEX header.
    """
    with ZipFile(path) as archive:
        dex_entries = sorted(
            [
                info
                for info in archive.infolist()
                if re.fullmatch(r"classes(?:\d+)?\.dex", info.filename)
            ],
            key=lambda info: (
                1 if info.filename == "classes.dex" else int(info.filename[7:-4])
            ),
        )
        return [(info.filename, info.CRC) for info in dex_entries]


def find_zip_entry(zip_entries: list[ZipEntry], offset: int) -> Optional[ZipEntry]:
    if not zip_entries:
        return None
    starts = [entry.data_offset for entry in zip_entries]
    index = bisect.bisect_right(starts, offset) - 1
    if index < 0:
        return None
    entry = zip_entries[index]
    return entry if entry.data_offset <= offset < entry.data_end else None
