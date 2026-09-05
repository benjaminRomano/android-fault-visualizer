"""Bounded ELF/DEX inspection. File content is not a call-stack observation."""

import bisect
import csv
import json
import struct
import subprocess
from dataclasses import dataclass
from pathlib import Path
from zipfile import ZipFile

from .artifacts import read_apk_dex_identities, read_vdex, read_zip_entries


@dataclass(frozen=True)
class Region:
    start: int
    end: int
    name: str
    address: int = 0


def elf_regions(data: bytes) -> tuple[list[Region], list[Region]]:
    """Return file-backed load segments and allocated sections, never BSS bytes."""
    if len(data) < 64 or data[:4] != b"\x7fELF" or data[5] != 1:
        return [], []
    bits = data[4]
    if bits not in (1, 2):
        return [], []
    try:
        if bits == 2:
            phoff, shoff = struct.unpack_from("<QQ", data, 32)
            phsize, phnum, shsize, shnum, names_index = struct.unpack_from(
                "<5H", data, 54
            )
            phfmt, shfmt = "<IIQQQQQQ", "<IIQQQQIIQQ"
        else:
            phoff, shoff = struct.unpack_from("<II", data, 28)
            phsize, phnum, shsize, shnum, names_index = struct.unpack_from(
                "<5H", data, 42
            )
            phfmt, shfmt = "<8I", "<10I"
        if (phnum and phsize < struct.calcsize(phfmt)) or (
            shnum and shsize < struct.calcsize(shfmt)
        ):
            return [], []
        if phoff + phnum * phsize > len(data) or shoff + shnum * shsize > len(data):
            return [], []
        segments = []
        for i in range(phnum):
            p = struct.unpack_from(phfmt, data, phoff + i * phsize)
            kind, offset, address, size = (
                (p[0], p[2], p[3], p[5]) if bits == 2 else (p[0], p[1], p[2], p[4])
            )
            if kind == 1 and size and offset + size <= len(data):
                segments.append(Region(offset, offset + size, "PT_LOAD", address))
        headers = [
            struct.unpack_from(shfmt, data, shoff + i * shsize) for i in range(shnum)
        ]
        if not headers or names_index >= len(headers):
            return segments, []
        names_header = headers[names_index]
        names = data[names_header[4] : names_header[4] + names_header[5]]
        sections = []
        for s in headers:
            name_offset, kind, flags, address, offset, size = s[:6]
            if not flags & 2 or kind == 8 or not size or offset + size > len(data):
                continue
            end = names.find(b"\0", name_offset)
            if name_offset >= len(names) or end < 0:
                continue
            name = names[name_offset:end].decode("utf-8", errors="replace")
            sections.append(Region(offset, offset + size, name, address))
        return segments, sections
    except (struct.error, IndexError):
        return [], []


def dex_methods(data: bytes) -> list[Region]:
    """Standard DEX 035–040 instruction ranges. CompactDex/041 containers omitted."""
    if (
        len(data) < 112
        or data[:4] != b"dex\n"
        or data[4:8] not in {b"035\0", b"037\0", b"038\0", b"039\0", b"040\0"}
    ):
        return []
    try:
        size, header_size, endian = struct.unpack_from("<III", data, 32)
        if size != len(data) or header_size != 112 or endian != 0x12345678:
            return []
        data_size, data_start = struct.unpack_from("<II", data, 104)
        data_end = data_start + data_size
        if (
            not data_size
            or data_start < header_size
            or data_start % 4
            or data_end > size
        ):
            return []

        def u32(offset):
            if offset < 0 or offset + 4 > size:
                raise ValueError("DEX offset outside file")
            return struct.unpack_from("<I", data, offset)[0]

        tables = []

        def table(at, width):
            count, offset = struct.unpack_from("<II", data, at)
            if count == 0:
                if offset:
                    raise ValueError("nonempty offset for empty DEX table")
                return 0, 0
            end = offset + count * width
            if (
                count > 2_000_000
                or offset < header_size
                or offset % 4
                or end > data_start
            ):
                raise ValueError("DEX table outside file")
            if any(
                offset < other_end and other_start < end
                for other_start, other_end in tables
            ):
                raise ValueError("overlapping DEX tables")
            tables.append((offset, end))
            return count, offset

        def uleb(offset):
            if not data_start <= offset < data_end:
                raise ValueError("DEX data pointer outside data section")
            value = 0
            for shift in range(0, 35, 7):
                if offset >= data_end:
                    raise ValueError("truncated ULEB128")
                byte = data[offset]
                offset += 1
                if shift == 28 and byte > 15:
                    raise ValueError("overflow ULEB128")
                value |= (byte & 127) << shift
                if not byte & 128:
                    return value, offset
            raise ValueError("invalid ULEB128")

        string_count, strings_offset = table(56, 4)
        type_count, types_offset = table(64, 4)
        proto_count, _ = table(72, 12)
        field_count, fields_offset = table(80, 8)
        method_count, methods_offset = table(88, 8)
        class_count, classes_offset = table(96, 32)
        strings = {}

        def string(index):
            if index >= string_count:
                raise ValueError("invalid DEX string index")
            if index not in strings:
                utf16_size, start = uleb(u32(strings_offset + index * 4))
                end = data.find(b"\0", start, data_end)
                if end < 0:
                    raise ValueError("unterminated DEX string")
                # DEX uses modified UTF-8: NUL is C0 80, and supplementary
                # characters are represented by two separately encoded UTF-16 units.
                units = (
                    data[start:end]
                    .replace(b"\xc0\x80", b"\0")
                    .decode("utf-8", errors="surrogatepass")
                )
                if len(units) != utf16_size or any(
                    ord(unit) > 0xFFFF for unit in units
                ):
                    raise ValueError("invalid modified UTF-8 string")
                strings[index] = units.encode(
                    "utf-16-le", errors="surrogatepass"
                ).decode("utf-16-le", errors="surrogatepass")
            return strings[index]

        result = []
        for i in range(class_count):
            owner = u32(classes_offset + i * 32)
            if owner >= type_count:
                raise ValueError("invalid class definition index")
            cursor = u32(classes_offset + i * 32 + 24)
            if not cursor:
                continue
            counts = []
            for _ in range(4):
                count, cursor = uleb(cursor)
                counts.append(count)
            if sum(counts) > size:
                raise ValueError("invalid class data counts")
            for count in counts[:2]:
                field_index = 0
                for ordinal in range(count):
                    delta, cursor = uleb(cursor)
                    field_index += delta
                    _, cursor = uleb(cursor)
                    if field_index >= field_count or (ordinal and not delta):
                        raise ValueError("invalid field index")
                    if (
                        struct.unpack_from("<H", data, fields_offset + field_index * 8)[
                            0
                        ]
                        != owner
                    ):
                        raise ValueError("field belongs to a different class")
            for count in counts[2:]:
                method_index = 0
                for ordinal in range(count):
                    delta, cursor = uleb(cursor)
                    method_index += delta
                    _, cursor = uleb(cursor)
                    code_offset, cursor = uleb(cursor)
                    if method_index >= method_count or (ordinal and not delta):
                        raise ValueError("invalid method index")
                    class_index, proto_index, name_index = struct.unpack_from(
                        "<HHI", data, methods_offset + method_index * 8
                    )
                    if (
                        class_index != owner
                        or proto_index >= proto_count
                        or name_index >= string_count
                    ):
                        raise ValueError("invalid method identity")
                    if not code_offset:
                        continue
                    instructions = code_offset + 16
                    if code_offset < data_start or instructions > data_end:
                        raise ValueError("code_item outside data section")
                    end = instructions + 2 * u32(code_offset + 12)
                    if code_offset % 4 or end > data_end:
                        raise ValueError("invalid code_item")
                    class_name = (
                        string(u32(types_offset + class_index * 4))
                        .removeprefix("L")
                        .removesuffix(";")
                        .replace("/", ".")
                    )
                    if end > instructions:
                        result.append(
                            Region(
                                instructions, end, class_name + "." + string(name_index)
                            )
                        )
        return sorted(result, key=lambda r: r.start)
    except (ValueError, UnicodeError, struct.error, IndexError):
        return []


def enrich_capture(output: Path, artifacts: dict[str, Path], page_size: int) -> None:
    """Attach exact binary sections and DEX page contents; symbolize captured IPs."""
    regions: dict[str, list[Region]] = {}
    methods: dict[str, list[Region]] = {}
    dex_ranges: dict[str, list[Region]] = {}
    apk_ids = {
        p: read_apk_dex_identities(local)
        for p, local in artifacts.items()
        if p.endswith(".apk")
    }
    for remote, local in artifacts.items():
        data = local.read_bytes()
        if data.startswith(b"\x7fELF"):
            _, regions[remote] = elf_regions(data)
        elif remote.endswith(".apk"):
            entries = read_zip_entries(local)
            with ZipFile(local) as archive:
                for e in entries:
                    if not e.file_name.endswith(".dex") or e.compression != "stored":
                        continue
                    dex_ranges.setdefault(remote, []).append(
                        Region(e.data_offset, e.data_end, e.file_name)
                    )
                    # Bound decompression even though this entry is stored.
                    if e.uncompressed_size <= 256 * 1024 * 1024:
                        methods.setdefault(remote, []).extend(
                            Region(
                                e.data_offset + m.start,
                                e.data_offset + m.end,
                                e.file_name + ": " + m.name,
                            )
                            for m in dex_methods(archive.read(e.file_name))
                        )
        elif remote.endswith(".vdex"):
            parents = Path(remote).parents
            apk = (
                str(parents[2] / (Path(remote).stem + ".apk"))
                if len(parents) > 2
                else ""
            )
            vdex = read_vdex(local, apk_ids.get(apk))
            if not vdex or not vdex.identities_verified:
                continue
            for e in vdex.dex_ranges:
                dex_ranges.setdefault(remote, []).append(
                    Region(e.data_offset, e.data_end, e.file_name)
                )
                methods.setdefault(remote, []).extend(
                    Region(
                        e.data_offset + m.start,
                        e.data_offset + m.end,
                        e.file_name + ": " + m.name,
                    )
                    for m in dex_methods(data[e.data_offset : e.data_end])
                )
    details = []
    method_indices = {
        p: (sorted(ms, key=lambda m: m.start), sorted(m.start for m in ms))
        for p, ms in methods.items()
    }
    with (output / "all_faults.csv").open() as file:
        for row in csv.DictReader(file):
            remote, offset = row["file_name"], row["offset"]
            if not offset:
                continue
            offset = int(offset)
            section = next(
                (r.name for r in regions.get(remote, []) if r.start <= offset < r.end),
                "",
            )
            dex = next(
                (
                    r.name
                    for r in dex_ranges.get(remote, [])
                    if r.start <= offset < r.end
                ),
                "",
            )
            start = offset // page_size * page_size
            ms, starts = method_indices.get(remote, ([], []))
            stop = bisect.bisect_left(starts, start + page_size)
            # Methods are non-overlapping code ranges in valid DEX. Include all
            # overlapping candidates, not just the method containing the address.
            begin = bisect.bisect_left(starts, start)
            while begin > 0 and ms[begin - 1].end > start:
                begin -= 1
            candidates = sorted({m.name for m in ms[begin:stop] if m.end > start})
            if section or dex or candidates:
                details.append(
                    {
                        "sequence": int(row["sequence"]),
                        "section": section,
                        "dex": dex,
                        "page_methods": candidates,
                    }
                )
    (output / "fault_details.json").write_text(
        json.dumps(details, separators=(",", ":"))
    )


def symbolize_callchains(
    output: Path, artifacts: dict[str, Path], symbolizer: Path
) -> None:
    path = output / "resolved_fault_callchains.csv"
    if not path.exists() or not symbolizer.exists():
        return
    with path.open() as file:
        reader = csv.DictReader(file)
        fields = reader.fieldnames
        rows = list(reader)
    grouped = {}
    for row in rows:
        if (
            row["frame_kind"] == "user"
            and row["file_name"] in artifacts
            and row["file_offset"]
        ):
            grouped.setdefault(row["file_name"], []).append(row)
    for remote, frames in grouped.items():
        local = artifacts[remote]
        segments, _ = elf_regions(local.read_bytes())
        addresses = {}
        for row in frames:
            offset = int(row["file_offset"])
            segment = next((s for s in segments if s.start <= offset < s.end), None)
            if segment:
                addresses[offset] = segment.address + offset - segment.start
        if not addresses:
            continue
        result = subprocess.run(
            [
                str(symbolizer),
                "--obj",
                str(local),
                "--output-style=JSON",
                "--no-inlines",
                "--demangle",
            ],
            input="".join(f"0x{a:x}\n" for a in addresses.values()),
            text=True,
            capture_output=True,
            timeout=60,
            check=True,
        )
        values = [json.loads(line) for line in result.stdout.splitlines() if line]
        if len(values) != len(addresses):
            raise RuntimeError("Symbolizer output does not match submitted addresses")
        labels = {}
        for offset, value in zip(addresses, values):
            symbols = value.get("Symbol", [])
            name = symbols[0].get("FunctionName") if symbols else None
            if name and name != "??":
                labels[offset] = name
        for row in frames:
            if int(row["file_offset"]) in labels:
                row["label"] = labels[int(row["file_offset"])]
    with path.open("w", newline="") as file:
        writer = csv.DictWriter(file, fieldnames=fields)
        writer.writeheader()
        writer.writerows(rows)
