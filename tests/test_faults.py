import csv
import io
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from zipfile import ZIP_DEFLATED, ZIP_STORED, ZipFile

from faults import reset_output_directory
from android_fault_visualizer.artifacts import (
    MapEntry,
    MappingEvent,
    find_map_entry,
    find_map_entry_at,
    find_zip_entry,
    linux_device_number,
    parse_maps_text,
    read_apk_dex_identities,
    read_zip_entries,
)
from android_fault_visualizer.device import (
    cache_targets,
    drop_caches,
    parse_residency,
    run_collector_file_command,
    stop_and_enumerate_cache_targets,
    verify_cache_residency,
)
from android_fault_visualizer.processing import classify_source


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
            reset_output_directory(Path(__file__).resolve().parents[1], True)


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
                return SimpleNamespace(
                    stdout="\n".join(rows) + "\n",
                    returncode=0,
                    stderr="",
                    check_returncode=lambda: None,
                )

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
                ["/data/user/0/pkg/startup.db"],
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
                return SimpleNamespace(
                    returncode=0, stdout="", stderr="", check_returncode=lambda: None
                )

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
