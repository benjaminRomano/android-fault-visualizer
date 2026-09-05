import csv
import json
import struct
import tempfile
import unittest
from pathlib import Path

from android_fault_visualizer.binary import dex_methods, elf_regions
from android_fault_visualizer.simpleperf import parse_samples
from report import build_report, report_run


def dex_fixture():
    data = bytearray(512)
    data[:8] = b"dex\n035\0"
    struct.pack_into("<III", data, 32, 512, 112, 0x12345678)
    for at, count, offset in [
        (56, 2, 112),
        (64, 1, 120),
        (72, 1, 124),
        (88, 1, 136),
        (96, 1, 144),
        (104, 320, 192),
    ]:
        struct.pack_into("<II", data, at, count, offset)
    struct.pack_into("<II", data, 112, 192, 220)
    struct.pack_into("<I", data, 120, 0)
    struct.pack_into("<HHI", data, 136, 0, 0, 1)
    struct.pack_into("<I", data, 144 + 24, 256)
    name = b"Lexample/Startup;"
    data[192 : 192 + len(name) + 2] = bytes([len(name)]) + name + b"\0"
    data[220:227] = b"\x05start\0"
    data[256:264] = bytes([0, 0, 1, 0, 0, 1, 0xC0, 2])
    struct.pack_into("<I", data, 332, 4)
    return data


def elf_fixture():
    data = bytearray(1024)
    data[:6] = b"\x7fELF\x02\x01"
    struct.pack_into("<QQ", data, 32, 64, 128)
    struct.pack_into("<5H", data, 54, 56, 1, 64, 3, 1)
    struct.pack_into("<IIQQQQQQ", data, 64, 1, 5, 0, 0x400000, 0, 1024, 1024, 4096)
    struct.pack_into("<IIQQQQIIQQ", data, 192, 1, 3, 0, 0, 512, 17, 0, 0, 1, 0)
    struct.pack_into("<IIQQQQIIQQ", data, 256, 11, 1, 6, 0x400280, 640, 16, 0, 0, 4, 0)
    data[512:529] = b"\0.shstrtab\0.text\0\0"
    return data


class BinaryTests(unittest.TestCase):
    def test_dex_content_names_and_instruction_byte_ranges(self):
        methods = dex_methods(bytes(dex_fixture()))
        self.assertEqual(
            [(336, 344, "example.Startup.start")],
            [(r.start, r.end, r.name) for r in methods],
        )

    def test_malformed_dex_fails_closed(self):
        data = dex_fixture()
        struct.pack_into("<I", data, 168, 0xFFFFFFF0)
        self.assertEqual([], dex_methods(bytes(data)))
        data = dex_fixture()
        data[4:7] = b"041"
        self.assertEqual([], dex_methods(bytes(data)))
        data = dex_fixture()
        struct.pack_into("<I", data, 332, 10000)
        self.assertEqual([], dex_methods(bytes(data)))

    def test_dex_rejects_header_pointers_overlapping_tables_and_invalid_identity(self):
        for offset, value in [
            (108, 0),  # No data section.
            (112, 36),  # String data points into the header.
            (168, 44),  # Class data points into the header.
            (92, 112),  # Method table overlaps string IDs.
            (144, 1),  # Class definition names a nonexistent type.
        ]:
            with self.subTest(offset=offset):
                data = dex_fixture()
                struct.pack_into("<I", data, offset, value)
                self.assertEqual([], dex_methods(bytes(data)))
        data = dex_fixture()
        struct.pack_into("<H", data, 136, 1)
        self.assertEqual([], dex_methods(bytes(data)))
        data = dex_fixture()
        struct.pack_into("<H", data, 138, 1)
        self.assertEqual([], dex_methods(bytes(data)))
        # A declared instruction range may not cross the data section's end.
        data = dex_fixture()
        struct.pack_into("<I", data, 104, 146)
        self.assertEqual([], dex_methods(bytes(data)))
        data = dex_fixture()
        data[262] = 64  # code_off now points to the header, not the data section.
        self.assertEqual([], dex_methods(bytes(data)))

    def test_dex_modified_utf8_names_are_decoded_without_replacement(self):
        data = dex_fixture()
        data[220:229] = b"\x02\xed\xa0\xbd\xed\xb8\x80\x00\x00"
        self.assertEqual("example.Startup.\U0001f600", dex_methods(bytes(data))[0].name)
        data = dex_fixture()
        data[220] = 4  # Declared UTF-16 length disagrees.
        self.assertEqual([], dex_methods(bytes(data)))

    def test_elf_offset_to_virtual_address_and_section(self):
        segments, sections = elf_regions(bytes(elf_fixture()))
        self.assertEqual(0x400280, segments[0].address + 640 - segments[0].start)
        self.assertEqual(".text", sections[0].name)
        self.assertEqual([], elf_regions(bytes(elf_fixture()[:150]))[0])

    def test_simpleperf_keeps_recursive_frames_and_sample_period(self):
        text = """sample:
  event_type: major-faults:u
  time: 123
  event_count: 1
  thread_id: 42
  thread_name: main
  vaddr_in_file: 12
  file: /data/app/test/base.odex
  symbol: Startup.load
  callchain:
    vaddr_in_file: 12
    file: /data/app/test/base.odex
    symbol: Startup.load
"""
        self.assertEqual(2, len(parse_samples(text)[0]["stack"]))
        with self.assertRaises(ValueError):
            parse_samples(text.replace("event_count: 1", "event_count: 20"))


class ReportTests(unittest.TestCase):
    def make_capture(self, path):
        metadata = {
            "schema_version": 5,
            "capture_status": "collected",
            "page_size": 4096,
            "package": "com.example.app",
            "results": {"all_faults": 3},
            "cache_verification": {"files_checked": 1, "resident_pages": 0},
        }
        (path / "capture_metadata.json").write_text(json.dumps(metadata))
        rows = [
            {
                "sequence": i,
                "elapsed_ms": i,
                "event_type": "major" if i != 1 else "minor",
                "address": 0x1000 + i * 4096,
                "file_name": "/data/app/com.example.app-hash/base.vdex",
                "offset": i * 4096,
                "tid": 42,
                "thread_name": "main",
                "zip_entry_name": "classes2.dex" if i else "classes.dex",
            }
            for i in range(3)
        ]
        with (path / "all_faults.csv").open("w") as file:
            w = csv.DictWriter(file, fieldnames=rows[0])
            w.writeheader()
            w.writerows(rows)
        (path / "vdex_dex_boundaries.csv").write_text(
            "file_name,dex_name,start_offset,identity_verified\n/data/app/com.example.app-hash/base.vdex,classes.dex,64,True\n/data/app/com.example.app-hash/base.vdex,classes2.dex,8192,False\n"
        )
        return metadata

    def test_whole_vdex_counts_verified_boundaries_and_exact_offsets(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory)
            self.make_capture(path)
            run = report_run(path)
            self.assertEqual(1, len(run["sources"]))
            self.assertEqual(2, sum(e["major"] for e in run["events"]))
            self.assertEqual([0, 1, 2], [e["page"] for e in run["events"]])
            source = next(iter(run["sources"].values()))
            self.assertEqual(
                [{"page": 64 / 4096, "label": "classes.dex"}], source["boundaries"]
            )
            build_report(path, path / "report.html")
            html = (path / "report.html").read_text()
            self.assertTrue('value="major"' in html, "Missing major-fault filter")
            self.assertTrue('plotType = "scatter"' in html, "Missing SVG fallback")
            self.assertTrue('color: "#ba3030"' in html, "Missing boundary markers")
            self.assertNotIn("<script src=", html)

    def test_loss_and_inconsistent_count_are_hard_failures(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory)
            metadata = self.make_capture(path)
            metadata["collector_lost"] = 1
            (path / "capture_metadata.json").write_text(json.dumps(metadata))
            with self.assertRaisesRegex(ValueError, "integrity"):
                report_run(path)
            metadata["collector_lost"] = 0
            metadata["results"]["all_faults"] = 4
            (path / "capture_metadata.json").write_text(json.dumps(metadata))
            with self.assertRaisesRegex(ValueError, "count"):
                report_run(path)
