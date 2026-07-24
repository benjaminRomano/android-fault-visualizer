import csv
import io
import struct
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from zipfile import ZIP_DEFLATED, ZIP_STORED, ZipFile

import pandas as pd

from faults import (
    MapEntry,
    MappingEvent,
    cache_targets,
    classify_source,
    drop_caches,
    find_map_entry,
    find_map_entry_at,
    find_zip_entry,
    linux_device_number,
    parse_maps_text,
    parse_residency,
    read_apk_dex_identities,
    read_android10_vdex_entries,
    read_zip_entries,
    reset_output_directory,
    run_collector_file_command,
    stop_and_enumerate_cache_targets,
    verify_cache_target_set,
    verify_cache_residency,
)
from report import (
    Capture,
    all_fault_address_figure,
    build_report,
    category_figure,
    comparison_sequence_figure,
    locality_metrics,
    overall_timeline_figure,
    page_cache_figure,
    sequence_figure,
    sequence_views,
    selector_control,
    source_summary,
    validate_comparison,
)


class MapTests(unittest.TestCase):
    def test_maps_are_half_open_and_paths_may_contain_spaces(self):
        entries = parse_maps_text(
            "1000-2000 r--p 00002000 fe:20 42 /data/app/a file.apk\n"
            "3000-4000 rw-p 00000000 00:00 0 [anon:dalvik-main space]\n"
        )

        self.assertEqual(find_map_entry(entries, 0x1000), entries[0])
        self.assertEqual(find_map_entry(entries, 0x1FFF), entries[0])
        self.assertIsNone(find_map_entry(entries, 0x2000))
        self.assertEqual(entries[0].file_name, "/data/app/a file.apk")

    def test_linux_device_encoding_matches_stat_dev_shape(self):
        self.assertEqual(linux_device_number("fe:20"), 65056)

    def test_mapping_timeline_wins_and_does_not_apply_future_mapping(self):
        inherited = MapEntry(0x1000, 0x2000, "r--p", 0, 1, 1, "/old")
        replacement = MapEntry(0x1000, 0x2000, "r-xp", 0, 1, 2, "/new")
        events = [MappingEvent(200, replacement)]

        self.assertIsNone(find_map_entry_at([inherited], events, 0x1800, 100))
        self.assertEqual(
            find_map_entry_at([inherited], events, 0x1800, 200), replacement
        )
        self.assertEqual(find_map_entry_at([inherited], [], 0x1800, 100), inherited)


class ZipTests(unittest.TestCase):
    def test_offsets_refer_to_payload_and_not_local_header_or_gaps(self):
        with tempfile.TemporaryDirectory() as directory:
            archive_path = Path(directory) / "sample.apk"
            with ZipFile(archive_path, "w") as archive:
                archive.writestr("classes.dex", b"dex\n" * 64, ZIP_STORED)
                archive.writestr("assets/config.json", b"{}" * 64, ZIP_DEFLATED)

            entries = read_zip_entries(archive_path)
            dex = next(entry for entry in entries if entry.file_name == "classes.dex")
            asset = next(
                entry for entry in entries if entry.file_name == "assets/config.json"
            )

            self.assertGreater(dex.data_offset, dex.header_offset)
            self.assertEqual(find_zip_entry(entries, dex.data_offset), dex)
            self.assertEqual(find_zip_entry(entries, dex.data_end - 1), dex)
            self.assertIsNone(find_zip_entry(entries, dex.header_offset))
            self.assertIsNone(find_zip_entry(entries, dex.data_end))
            self.assertEqual(find_zip_entry(entries, asset.data_offset), asset)


class VdexTests(unittest.TestCase):
    def test_apk_dex_identity_uses_zip_crc_in_multidex_order(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "base.apk"
            with ZipFile(path, "w") as archive:
                archive.writestr("classes2.dex", b"dex\n035\0" + b"second")
                archive.writestr("classes.dex", b"dex\n035\0" + b"first")

            with ZipFile(path) as archive:
                expected = [
                    ("classes.dex", archive.getinfo("classes.dex").CRC),
                    ("classes2.dex", archive.getinfo("classes2.dex").CRC),
                ]

            self.assertEqual(read_apk_dex_identities(path), expected)

    def test_android10_multidex_ranges_keep_shared_data_separate(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "base.vdex"
            dex_count = 2
            dex_file_size = 112
            header_size = 28
            dex_section_offset = header_size + 4 * dex_count
            dex_begin = dex_section_offset + 12
            dex_size = dex_count * (4 + dex_file_size)
            shared_size = 64
            data = bytearray(dex_begin + dex_size + shared_size)
            data[:12] = b"vdex021\x00002\x00"
            struct.pack_into("<4I", data, 12, dex_count, 0, 0, 0)
            struct.pack_into("<3I", data, dex_section_offset, dex_size, shared_size, 0)
            cursor = dex_begin
            for _ in range(dex_count):
                dex_start = cursor + 4
                data[dex_start : dex_start + 8] = b"cdex001\0"
                struct.pack_into("<I", data, dex_start + 32, dex_file_size)
                cursor = dex_start + dex_file_size
            path.write_bytes(data)

            entries = read_android10_vdex_entries(
                path, [("classes.dex", 0), ("classes2.dex", 0)]
            )

            self.assertEqual(
                [entry.file_name for entry in entries],
                [
                    "dex #1 · classes.dex",
                    "dex #2 · classes2.dex",
                    "shared CompactDex data",
                ],
            )
            self.assertEqual(
                find_zip_entry(entries, entries[0].data_offset), entries[0]
            )
            self.assertEqual(
                find_zip_entry(entries, entries[1].data_offset), entries[1]
            )
            self.assertEqual(
                find_zip_entry(entries, entries[2].data_offset), entries[2]
            )

            mismatched = read_android10_vdex_entries(
                path, [("classes.dex", 123), ("classes2.dex", 456)]
            )
            self.assertEqual(
                [entry.file_name for entry in mismatched],
                ["dex #1", "dex #2", "shared CompactDex data"],
            )

    def test_unknown_vdex_revision_is_not_guessed(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "base.vdex"
            path.write_bytes(b"vdex999\x00002\x00" + b"\0" * 64)
            self.assertEqual(read_android10_vdex_entries(path), [])


class ClassificationTests(unittest.TestCase):
    def test_compiled_and_archive_sources_are_distinguished(self):
        self.assertEqual(
            classify_source("/data/app/oat/arm64/base.odex", None), "compiled_code"
        )
        self.assertEqual(classify_source("/data/app/base.apk", "classes2.dex"), "dex")
        self.assertEqual(
            classify_source("/data/app/oat/arm64/base.vdex", "dex #2 · classes2.dex"),
            "dex",
        )
        self.assertEqual(
            classify_source("/data/app/base.apk", "assets/model.bin"), "asset"
        )
        self.assertEqual(
            classify_source("/data/app/base.apk", "res/drawable/a.png"), "image"
        )


class OutputSafetyTests(unittest.TestCase):
    def test_repository_root_cannot_be_replaced(self):
        with self.assertRaises(ValueError):
            reset_output_directory(Path(__file__).resolve().parents[1])


class CacheVerificationTests(unittest.TestCase):
    def test_every_regular_app_file_is_a_cache_target(self):
        files = [
            "/data/app/base.apk",
            "/data/user/0/pkg/databases/startup.db",
            "/data/user/0/pkg/files/model.bin",
            "/data/user/0/pkg/code_cache/secondary.dex",
        ]
        self.assertEqual(cache_targets(files), sorted(files))

    def test_residency_commands_are_batched_without_duplicate_headers(self):
        class FakeAdb:
            def __init__(self):
                self.calls = []

            def root_shell(self, command, **_kwargs):
                import shlex

                self.calls.append(command)
                paths = shlex.split(command)[2:]
                rows = ["file_name,size_bytes,total_pages,resident_pages"]
                rows.extend(f'"{path}",4096,1,0' for path in paths)
                return SimpleNamespace(stdout="\n".join(rows) + "\n")

        adb = FakeAdb()
        files = [f"/data/app/{index:04d}-{'x' * 180}.apk" for index in range(200)]
        output = run_collector_file_command(adb, "--residency", files)
        rows = list(csv.DictReader(io.StringIO(output)))

        self.assertGreater(len(adb.calls), 1)
        self.assertEqual(len(rows), len(files))

    def test_csv_escaped_filename_preserves_real_residency(self):
        path = '/data/user/0/pkg/evil",4096,1,0,".bin'
        output = io.StringIO()
        writer = csv.writer(output)
        writer.writerow(["file_name", "size_bytes", "total_pages", "resident_pages"])
        writer.writerow([path, 8192, 2, 2])

        rows = parse_residency(output.getvalue(), "after_drop", [path])

        self.assertEqual(rows[0]["file_name"], path)
        self.assertEqual(rows[0]["resident_pages"], 2)

    def test_malformed_csv_and_incomplete_coverage_are_rejected(self):
        forged = (
            "file_name,size_bytes,total_pages,resident_pages\n"
            '"/data/user/0/pkg/evil",4096,1,0,".bin",8192,2,2\n'
        )
        with self.assertRaisesRegex(RuntimeError, "Malformed"):
            parse_residency(forged, "after_drop")

        valid_but_incomplete = (
            "file_name,size_bytes,total_pages,resident_pages\n"
            '"/data/app/base.apk",4096,1,0\n'
        )
        with self.assertRaisesRegex(RuntimeError, "coverage mismatch"):
            parse_residency(
                valid_but_incomplete,
                "after_drop",
                ["/data/app/base.apk", "/data/user/0/pkg/startup.db"],
            )

    def test_android_12_property_fallback_waits_for_reset_then_evicts(self):
        class FakeAdb:
            def __init__(self):
                self.commands = []
                self.properties = iter(["3", "0"])

            def root_shell(self, command, **_kwargs):
                self.commands.append(command)
                if command == "echo 3 > /proc/sys/vm/drop_caches":
                    return SimpleNamespace(
                        returncode=1, stdout="", stderr="permission denied"
                    )
                return SimpleNamespace(returncode=0, stdout="", stderr="")

            def shell(self, args, **_kwargs):
                self.commands.append(args)
                return SimpleNamespace(returncode=0, stdout="", stderr="")

            def getprop(self, name):
                self.commands.append(f"getprop {name}")
                return next(self.properties)

        adb = FakeAdb()
        drop_caches(adb, 31, ["/data/app/base.apk"])

        self.assertEqual(adb.commands[0], "sync")
        self.assertEqual(adb.commands[1], "echo 3 > /proc/sys/vm/drop_caches")
        self.assertEqual(adb.commands[2], ["setprop", "perf.drop_caches", "3"])
        self.assertEqual(adb.commands[3:5], ["getprop perf.drop_caches"] * 2)
        self.assertIn("--evict", adb.commands[5])

    def test_pre_android_12_direct_drop_failure_is_fatal(self):
        class FakeAdb:
            def root_shell(self, command, **_kwargs):
                if command == "echo 3 > /proc/sys/vm/drop_caches":
                    return SimpleNamespace(
                        returncode=1, stdout="", stderr="permission denied"
                    )
                return SimpleNamespace(returncode=0, stdout="", stderr="")

        with self.assertRaisesRegex(RuntimeError, "permission denied"):
            drop_caches(FakeAdb(), 29, ["/data/app/base.apk"])

    def test_zero_residency_passes_strict_verification(self):
        verify_cache_residency(
            [
                {
                    "phase": "before_launch",
                    "file_name": "/data/app/base.apk",
                    "resident_pages": 0,
                    "total_pages": 100,
                }
            ],
            0,
            "before_launch",
        )

    def test_residency_fails_with_file_level_evidence(self):
        with self.assertRaisesRegex(RuntimeError, r"base\.apk=7/100 pages"):
            verify_cache_residency(
                [
                    {
                        "phase": "before_launch",
                        "file_name": "/data/app/base.apk",
                        "resident_pages": 7,
                        "total_pages": 100,
                    }
                ],
                0,
                "before_launch",
            )

    def test_explicit_nonzero_threshold_allows_known_residency(self):
        verify_cache_residency(
            [
                {
                    "phase": "before_launch",
                    "file_name": "/data/app/base.apk",
                    "resident_pages": 7,
                    "total_pages": 100,
                }
            ],
            7,
            "before_launch",
        )

    def test_cache_target_drift_is_rejected(self):
        with self.assertRaisesRegex(
            RuntimeError, r"added=\['/data/user/0/com\.example/new\.db'\]"
        ):
            verify_cache_target_set(
                ["/data/app/base.apk"],
                ["/data/app/base.apk", "/data/user/0/com.example/new.db"],
            )

    def test_package_is_stopped_before_cache_targets_are_enumerated(self):
        events = []

        class FakeAdb:
            def shell(self, args, **_kwargs):
                events.append(("shell", args))
                if args[:3] == ["ps", "-A", "-o"]:
                    return SimpleNamespace(stdout="NAME\n")
                return SimpleNamespace(stdout="")

            def root_shell(self, command, **_kwargs):
                events.append(("root_shell", command))
                return SimpleNamespace(stdout="/data/app/base.apk\0")

        targets = stop_and_enumerate_cache_targets(
            FakeAdb(), "com.example", ["/data/app/base.apk"]
        )

        self.assertEqual(targets, ["/data/app/base.apk"])
        self.assertEqual(events[0], ("shell", ["am", "force-stop", "com.example"]))
        self.assertEqual(events[1], ("shell", ["ps", "-A", "-o", "NAME"]))
        self.assertEqual(events[2][0], "root_shell")


class ReportTests(unittest.TestCase):
    @staticmethod
    def capture(**metadata_overrides):
        metadata = {
            "schema_version": 5,
            "package": "com.example",
            "activity": "com.example/.MainActivity",
            "sdk": 29,
            "release": "10",
            "abi": "arm64-v8a",
            "page_size": 4096,
            "kernel": "test",
            "collector": "perf-software-page-fault-events",
            "collector_version": 2,
            "cache_procedure": (
                "force-stop-wait+stable-target-set+sync+drop_caches+fadvise+mincore-v3"
            ),
            "cache_max_resident_pages": 0,
            "reboot_before_collect": True,
            "serial": "emulator-5554",
            "device": "generic_arm64",
            "build_fingerprint": "test/fingerprint",
            "collector_source_sha256": "source-hash",
            "collector_binary_sha256": "binary-hash",
            "trace_config_sha256": "config-hash",
            "ndk": "29.0",
            "compiler": "clang",
            "pid": 123,
            "startup": {"ts": 10, "ts_end": 20, "duration_ns": 10},
            "results": {"all_faults": 0, "file_backed_faults": 0},
            "cache_verification": {
                "resident_pages": 0,
                "total_pages": 0,
                "fully_evicted_files": 0,
                "files_checked": 0,
            },
            "collector_lost": 0,
        }
        metadata.update(metadata_overrides)
        return Capture(
            path=Path("/capture"),
            label="capture",
            metadata=metadata,
            all_faults=pd.DataFrame(columns=["event_type"]),
            mapped_faults=pd.DataFrame(
                columns=[
                    "file_name",
                    "event_type",
                    "is_major",
                    "source_label",
                    "unit_key",
                    "category",
                    "ts",
                    "section_page",
                ]
            ),
            page_cache=pd.DataFrame(
                columns=["file_name", "source_label", "page_count"]
            ),
            residency=pd.DataFrame(),
        )

    def test_sparse_report_helpers_do_not_crash(self):
        capture = self.capture()
        self.assertTrue(source_summary(capture).empty)
        self.assertTrue(locality_metrics(capture).empty)
        self.assertEqual(len(category_figure(capture).data), 0)
        self.assertEqual(len(all_fault_address_figure(capture).data), 0)
        self.assertEqual(len(overall_timeline_figure(capture).data), 0)
        self.assertEqual(len(sequence_figure(capture).data), 0)
        self.assertEqual(len(page_cache_figure(capture).data), 0)
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "report.html"
            build_report(capture, output)
            self.assertIn("No file-backed major faults", output.read_text())

    def test_timeline_keeps_each_source_in_a_distinct_lane(self):
        capture = self.capture()
        capture.mapped_faults = pd.DataFrame(
            [
                {
                    "elapsed_ms": float(index),
                    "event_type": "minor",
                    "thread_name": "main",
                    "source_label": f"/system/lib64/source-{index}.so",
                    "page_index": index,
                    "category": "native_code",
                }
                for index in range(20)
            ]
        )

        figure = overall_timeline_figure(capture)

        self.assertEqual(len(set(figure.data[0].y)), 20)
        self.assertEqual(len(figure.layout.yaxis.ticktext), 18)
        self.assertNotIn("Other file-backed", figure.layout.yaxis.ticktext)

    def test_page_cache_legend_stays_below_the_plot(self):
        capture = self.capture()
        capture.page_cache = pd.DataFrame(
            [
                {
                    "file_name": "/data/app/base.vdex",
                    "source_label": "oat/arm64/base.vdex",
                    "page_count": 1,
                    "elapsed_ms": 1.0,
                    "page_index": 2,
                    "thread_name": "main",
                    "category": "dex",
                }
            ]
        )

        figure = page_cache_figure(capture)

        self.assertEqual(figure.layout.legend.y, -0.18)
        self.assertEqual(figure.layout.legend.yanchor, "top")
        self.assertEqual(figure.layout.margin.b, 150)

    def test_sequence_uses_native_selector_metadata(self):
        capture = self.capture()
        capture.mapped_faults = pd.DataFrame(
            [
                {
                    "unit_key": "oat/arm64/base.vdex",
                    "source_label": "oat/arm64/base.vdex",
                    "file_name": "/data/app/com.example-a/oat/arm64/base.vdex",
                    "zip_entry_name": None,
                    "ts": index,
                    "event_type": "major" if index == 0 else "minor",
                    "section_page": index,
                    "page_index": index,
                    "elapsed_ms": float(index),
                    "thread_name": "main",
                    "offset": index * 4096,
                    "category": "dex",
                }
                for index in range(3)
            ]
        )

        figure = sequence_figure(capture)
        control = selector_control(figure, "chart-sequence", "File or section")

        self.assertEqual(figure.layout.meta["traces_per_option"], 2)
        self.assertEqual(
            figure.layout.meta["selector_options"][0],
            "oat/arm64/base.vdex · entire file",
        )
        self.assertFalse(figure.layout.updatemenus)
        self.assertIn('<select id="chart-sequence-selector">', control)

    def test_vdex_sequence_defaults_to_whole_file_and_hides_shared_drilldown(self):
        capture = self.capture()
        file_name = "/data/app/com.example-a/oat/arm64/base.vdex"
        rows = []
        for index, (entry, file_page, section_page) in enumerate(
            [
                (None, 0, 0),
                ("dex #1 · classes.dex", 16, 0),
                ("dex #1 · classes.dex", 81, 65),
                ("dex #1 · classes.dex", 124, 108),
                ("shared CompactDex data", 200, 0),
                ("shared CompactDex data", 350, 150),
                ("shared CompactDex data", 700, 500),
            ]
        ):
            source = "oat/arm64/base.vdex"
            key = source
            if entry:
                source = f"{source} › {entry}"
                key = f"oat/arm64/base.vdex::{entry}"
            rows.append(
                {
                    "unit_key": key,
                    "source_label": source,
                    "file_name": file_name,
                    "zip_entry_name": entry,
                    "ts": index,
                    "event_type": "major" if index % 2 else "minor",
                    "is_major": bool(index % 2),
                    "section_page": section_page,
                    "page_index": file_page,
                    "elapsed_ms": float(index),
                    "thread_name": "main",
                    "offset": file_page * 4096,
                    "category": "dex",
                }
            )
        capture.mapped_faults = pd.DataFrame(rows)

        views = sequence_views(capture)
        figure = sequence_figure(capture)
        comparison = comparison_sequence_figure(capture, capture)
        locality = locality_metrics(capture)

        self.assertEqual(views[0].label, "oat/arm64/base.vdex · entire file")
        self.assertEqual(
            views[0].faults["sequence_page"].tolist(),
            [0, 16, 81, 124, 200, 350, 700],
        )
        self.assertIn(
            "oat/arm64/base.vdex › dex #1 · classes.dex",
            [view.label for view in views],
        )
        self.assertFalse(any("shared" in view.label.lower() for view in views))
        self.assertEqual(list(figure.data[0].y), [0, 81, 200, 700])
        self.assertEqual(
            comparison.layout.meta["selector_options"][0],
            "oat/arm64/base.vdex · entire file",
        )
        self.assertFalse(
            any(
                "shared" in option.lower()
                for option in comparison.layout.meta["selector_options"]
            )
        )
        self.assertEqual(locality.iloc[0]["faults"], 7)
        self.assertFalse(locality["source"].str.contains("shared", case=False).any())

    def test_all_fault_address_view_keeps_every_fault_and_hex_ticks(self):
        capture = self.capture()
        capture.all_faults = pd.DataFrame(
            [
                {
                    "elapsed_ms": 1.0,
                    "address": 0x1000,
                    "event_type": "minor",
                    "mapping_kind": "file",
                    "file_name": "/data/app/base.apk",
                    "source_label": "base.apk",
                    "offset": 0,
                    "page_index": 0,
                    "thread_name": "main",
                    "tid": 123,
                    "category": "apk_container",
                    "sequence": 0,
                },
                {
                    "elapsed_ms": 2.0,
                    "address": 0x2000,
                    "event_type": "minor",
                    "mapping_kind": "anonymous",
                    "file_name": "[stack]",
                    "source_label": "[stack]",
                    "offset": None,
                    "page_index": None,
                    "thread_name": "main",
                    "tid": 123,
                    "category": "anonymous",
                    "sequence": 1,
                },
                {
                    "elapsed_ms": 3.0,
                    "address": 0x3000,
                    "event_type": "major",
                    "mapping_kind": "unmapped",
                    "file_name": None,
                    "source_label": "nan",
                    "offset": None,
                    "page_index": None,
                    "thread_name": "main",
                    "tid": 123,
                    "category": "anonymous",
                    "sequence": 2,
                },
            ]
        )

        figure = all_fault_address_figure(capture)

        self.assertEqual(len(figure.data), 8)
        self.assertEqual(sum(len(trace.x) for trace in figure.data[:2]), 3)
        self.assertEqual(figure.data[0].marker.symbol, "circle")
        self.assertEqual(figure.data[1].marker.symbol, "diamond")
        self.assertEqual(
            [len(trace.x) for trace in figure.data[2:]], [1, 0, 1, 0, 0, 1]
        )
        self.assertEqual(figure.data[4].customdata[0][1], "[stack]")
        self.assertEqual(figure.data[7].customdata[0][1], "Unmapped address")
        self.assertTrue(
            all(label.startswith("0x") for label in figure.layout.yaxis.ticktext)
        )
        self.assertEqual(
            [button.label for button in figure.layout.updatemenus[0].buttons],
            [
                "All faults",
                "Regular-file backed",
                "Anonymous / non-regular",
                "Unmapped only",
            ],
        )

    def test_comparison_rejects_different_page_sizes(self):
        with self.assertRaisesRegex(RuntimeError, "page_size"):
            validate_comparison(self.capture(), self.capture(page_size=16384))

    def test_comparison_rejects_different_collector_binary(self):
        with self.assertRaisesRegex(RuntimeError, "collector_binary_sha256"):
            validate_comparison(
                self.capture(), self.capture(collector_binary_sha256="different")
            )

    def test_comparison_rejects_different_reboot_policy(self):
        with self.assertRaisesRegex(RuntimeError, "reboot_before_collect"):
            validate_comparison(
                self.capture(), self.capture(reboot_before_collect=False)
            )

    def test_comparison_rejects_provenance_missing_from_both(self):
        base = self.capture()
        test = self.capture()
        del base.metadata["trace_config_sha256"]
        del test.metadata["trace_config_sha256"]
        with self.assertRaisesRegex(RuntimeError, "required provenance is missing"):
            validate_comparison(base, test)


if __name__ == "__main__":
    unittest.main()
