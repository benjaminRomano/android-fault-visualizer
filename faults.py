import argparse
import hashlib
import os
import shlex
import shutil
import subprocess
import time
from pathlib import Path
from typing import Optional

from android_fault_visualizer.paths import (
    ROOT_DIR,
    TRACE_CONFIG,
    REMOTE_FAULTS,
    REMOTE_MAPPINGS,
    REMOTE_CALLCHAINS,
    CAPTURE_MARKER,
    CAPTURE_MARKER_CONTENT,
)
from android_fault_visualizer.device import (
    Adb,
    build_and_push_collector,
    package_paths,
    package_files,
    cache_targets,
    run_collector_file_command,
    parse_residency,
    write_residency,
    write_capture_metadata,
    record_cache_gate,
    stop_and_enumerate_cache_targets,
    drop_caches,
    reclaim_mapped_apks,
    resolve_activity,
    dump_process_state,
    dump_inode_mapping,
    pull_artifacts,
)
from android_fault_visualizer.recording import (
    start_perfetto,
    stop_perfetto,
    start_fault_collector,
    stop_fault_collector,
)
from android_fault_visualizer.processing import (
    process_capture,
)
from android_fault_visualizer.device import pull_stack_binaries


def collect(
    adb: Adb,
    package: str,
    activity: Optional[str],
    output_dir: Path,
    settle_ms: int,
    should_pull_apks: bool,
    max_resident_pages: int,
    rebooted_before_collect: bool,
    capture_stacks: bool,
    dwarf_stacks: bool = False,
    reclaim_apk_mappings: bool = False,
) -> None:
    adb.ensure_root()
    sdk = int(adb.getprop("ro.build.version.sdk"))
    abi = adb.getprop("ro.product.cpu.abi")
    page_size = int(
        adb.shell(
            ["getconf", "PAGESIZE"], capture_output=True, text=True, check=True
        ).stdout.strip()
    )
    apk_paths = package_paths(adb, package)
    activity_name = resolve_activity(adb, package, activity)
    build_info = build_and_push_collector(adb, output_dir, abi, sdk)

    metadata: dict[str, object] = {
        "schema_version": 5,
        "package": package,
        "activity": activity_name,
        "serial": adb.serial,
        "sdk": sdk,
        "release": adb.getprop("ro.build.version.release"),
        "build_fingerprint": adb.getprop("ro.build.fingerprint"),
        "device": adb.getprop("ro.product.device"),
        "kernel": adb.shell(
            ["uname", "-r"], capture_output=True, text=True, check=True
        ).stdout.strip(),
        "abi": abi,
        "page_size": page_size,
        "online_cpus_sysfs": adb.shell(
            ["cat", "/sys/devices/system/cpu/online"],
            capture_output=True,
            text=True,
            check=True,
        ).stdout.strip(),
        "collector": "perf-software-page-fault-events",
        "collector_clock": "boottime",
        "collector_version": 5,
        "capture_native_callchains": capture_stacks,
        "cache_procedure": (
            "force-stop-wait+stable-target-set+sync+drop_caches+fadvise+mincore-v3"
        ),
        "cache_max_resident_pages": max_resident_pages,
        "reclaim_mapped_apks": reclaim_apk_mappings,
        "reboot_before_collect": rebooted_before_collect,
        "boot_id": adb.shell(
            ["cat", "/proc/sys/kernel/random/boot_id"],
            capture_output=True,
            text=True,
            check=True,
        ).stdout.strip(),
        "device_uptime_seconds": float(
            adb.shell(
                ["cat", "/proc/uptime"],
                capture_output=True,
                text=True,
                check=True,
            ).stdout.split()[0]
        ),
        "trace_config_sha256": hashlib.sha256(TRACE_CONFIG.read_bytes()).hexdigest(),
        "capture_status": "preparing",
        **build_info,
    }
    capture_warnings: list[str] = []
    metadata["warnings"] = capture_warnings
    if reclaim_apk_mappings:
        metadata["cache_procedure"] = metadata["cache_procedure"].replace(
            "+mincore-v3", "+exact-read-only-APK-MADV_PAGEOUT+fadvise+mincore-v4"
        )
        metadata["mapped_apk_reclaim"] = []
    write_capture_metadata(output_dir, metadata)

    targets = stop_and_enumerate_cache_targets(adb, package, apk_paths)
    dump_inode_mapping(adb, package, apk_paths, output_dir)

    residency_rows = []
    residency_rows.extend(
        parse_residency(
            run_collector_file_command(adb, "--residency", targets),
            "before_drop",
            targets,
            apk_paths,
            capture_warnings,
        )
    )
    write_residency(output_dir, residency_rows)

    drop_caches(adb, sdk, targets)
    if reclaim_apk_mappings:
        diagnostics = reclaim_mapped_apks(adb, apk_paths, output_dir, "after_drop")
        metadata["mapped_apk_reclaim"].append(diagnostics)
        if diagnostics.get("warning"):
            capture_warnings.append(diagnostics["warning"])
        write_capture_metadata(output_dir, metadata)
    residency_rows.extend(
        parse_residency(
            run_collector_file_command(adb, "--residency", targets),
            "after_drop",
            targets,
            apk_paths,
            capture_warnings,
        )
    )
    write_residency(output_dir, residency_rows)
    record_cache_gate(
        output_dir,
        metadata,
        residency_rows,
        max_resident_pages,
        "after_drop",
    )

    trace_key = f"afv_{os.getpid()}_{int(time.time())}"
    remote_trace = f"/data/misc/perfetto-traces/{trace_key}.pftrace"
    collector_process = None
    collector_pid = None
    perfetto_process = None
    perfetto_pid = None
    dwarf_recorder = None
    from android_fault_visualizer import simpleperf

    try:
        perfetto_process, perfetto_pid = start_perfetto(adb, remote_trace)
        (
            collector_process,
            collector_pid,
            collector_start,
            collector_online_cpus,
        ) = start_fault_collector(adb, capture_stacks)
        metadata["collector_start_ns"] = collector_start
        metadata["collector_online_cpus"] = collector_online_cpus
        if dwarf_stacks:
            dwarf_recorder = simpleperf.start(adb)
        if collector_online_cpus != metadata["online_cpus_sysfs"]:
            raise RuntimeError(
                "CPU topology changed while starting the collector: "
                f"sysfs={metadata['online_cpus_sysfs']!r}, "
                f"collector={collector_online_cpus!r}"
            )

        current_targets = cache_targets(
            package_files(adb, package, package_paths(adb, package))
        )
        missing_required = sorted(set(apk_paths) - set(current_targets))
        if missing_required:
            raise RuntimeError(
                "Installed APK cache targets disappeared before launch: "
                + ", ".join(missing_required)
            )
        removed_targets = sorted(set(targets) - set(current_targets))
        added_targets = sorted(set(current_targets) - set(targets))
        if removed_targets:
            capture_warnings.append(
                "Before launch, ignored non-essential app files that "
                "disappeared: " + ", ".join(removed_targets)
            )
        if added_targets:
            capture_warnings.append(
                "Before launch, evicted and verified newly discovered app "
                "files: " + ", ".join(added_targets)
            )
            run_collector_file_command(adb, "--evict", added_targets)
        targets = current_targets

        if reclaim_apk_mappings:
            diagnostics = reclaim_mapped_apks(
                adb, apk_paths, output_dir, "before_launch"
            )
            metadata["mapped_apk_reclaim"].append(diagnostics)
            if diagnostics.get("warning"):
                capture_warnings.append(diagnostics["warning"])
            write_capture_metadata(output_dir, metadata)

        residency_rows.extend(
            parse_residency(
                run_collector_file_command(adb, "--residency", targets),
                "before_launch",
                targets,
                apk_paths,
                capture_warnings,
            )
        )
        write_residency(output_dir, residency_rows)
        record_cache_gate(
            output_dir,
            metadata,
            residency_rows,
            max_resident_pages,
            "before_launch",
        )

        launch = adb.shell(
            ["am", "start", "-W", "-n", activity_name],
            capture_output=True,
            text=True,
            check=True,
        )
        (output_dir / "launch.txt").write_text(launch.stdout)
        if "Status: ok" not in launch.stdout:
            raise RuntimeError("Activity launch failed:\n" + launch.stdout)

        pid = dump_process_state(adb, package, output_dir)
        metadata["pid"] = pid
        dump_inode_mapping(adb, package, apk_paths, output_dir, append=True)

        time.sleep(settle_ms / 1000)
        post_launch_diagnostics: list[dict[str, object]] = []
        post_launch_warnings: list[str] = []
        try:
            residency_rows.extend(
                parse_residency(
                    run_collector_file_command(
                        adb,
                        "--residency",
                        targets,
                        post_launch_diagnostics,
                    ),
                    "after_launch",
                    targets,
                    (),
                    post_launch_warnings,
                )
            )
            write_residency(output_dir, residency_rows)
            skipped_details = [
                str(command["stderr"])
                for command in post_launch_diagnostics
                if command["stderr"]
            ] + post_launch_warnings
            if skipped_details:
                capture_warnings.append(
                    "Post-launch residency check completed with collector exit "
                    "status 0 and skipped changing files: "
                    + " | ".join(skipped_details)
                )
        except (subprocess.CalledProcessError, RuntimeError) as error:
            exit_status = (
                error.returncode
                if isinstance(error, subprocess.CalledProcessError)
                else 0
            )
            capture_warnings.append(
                "Post-launch residency check failed after the startup trace was "
                f"captured (collector exit status {exit_status}: {error}); the "
                "capture was preserved. Pre-launch eviction verification was "
                "not affected."
            )
            metadata["post_launch_residency_exit_status"] = exit_status
            metadata["post_launch_residency_error"] = str(error)
        finally:
            metadata["post_launch_residency_commands"] = post_launch_diagnostics
            write_capture_metadata(output_dir, metadata)
    finally:
        try:
            if collector_process is not None and collector_pid is not None:
                return_code, collector_metadata = stop_fault_collector(
                    adb, collector_process, collector_pid
                )
                metadata.update(
                    {
                        f"collector_{key}": value
                        for key, value in collector_metadata.items()
                    }
                )
                metadata["collector_return_code"] = return_code
                metadata["collector_loss_detection"] = (
                    "counter_and_ring"
                    if collector_metadata.get("lost_counter_supported") == 1
                    else "ring_records_only"
                )
        finally:
            try:
                if perfetto_process is not None and perfetto_pid is not None:
                    stop_perfetto(adb, perfetto_process, perfetto_pid)
            finally:
                try:
                    if dwarf_recorder:
                        simpleperf.finish(
                            adb, *dwarf_recorder, metadata.get("pid"), output_dir
                        )
                        metadata["simpleperf_status"] = "complete"
                except (RuntimeError, subprocess.SubprocessError) as error:
                    metadata["simpleperf_status"] = "failed"
                    capture_warnings.append(
                        f"DWARF companion unavailable; exact capture preserved: {error}"
                    )
                finally:
                    write_capture_metadata(output_dir, metadata)

    adb.pull_with_root_fallback(REMOTE_FAULTS, output_dir / "fault_events.csv")
    adb.pull_with_root_fallback(REMOTE_MAPPINGS, output_dir / "mapping_events.csv")
    if capture_stacks:
        adb.pull_with_root_fallback(
            REMOTE_CALLCHAINS,
            output_dir / "fault_callchains.csv",
        )
    adb.pull_with_root_fallback(remote_trace, output_dir / "faults.pftrace")
    adb.root_shell(
        f"rm -f {shlex.quote(REMOTE_FAULTS)} "
        f"{shlex.quote(REMOTE_MAPPINGS)} "
        f"{shlex.quote(REMOTE_CALLCHAINS)} {shlex.quote(remote_trace)}",
        check=True,
    )

    if should_pull_apks:
        pull_artifacts(adb, apk_paths, abi, output_dir)
        if capture_stacks:
            pull_stack_binaries(adb, output_dir, capture_warnings)

    integrity_failures = {
        key: int(metadata.get(f"collector_{key}", 0))
        for key in ("lost", "integrity_errors", "throttled", "callchain_overflow")
    }
    if int(metadata.get("collector_return_code", 0)) != 0 or any(
        integrity_failures.values()
    ):
        metadata["capture_status"] = "collector_integrity_failed"
        write_capture_metadata(output_dir, metadata)
        raise RuntimeError(
            "Fault collector integrity failure: "
            + ", ".join(f"{key}={value}" for key, value in integrity_failures.items())
        )
    metadata["capture_status"] = "collected"
    write_capture_metadata(output_dir, metadata)


def reset_output_directory(output_dir: Path, overwrite: bool) -> None:
    if output_dir.is_symlink():
        raise ValueError(f"Refusing a symlink output directory: {output_dir}")
    resolved = output_dir.resolve()
    protected = {Path("/").resolve(), Path.home().resolve(), ROOT_DIR.resolve()}
    if len(resolved.parts) < 3 or any(
        protected_path == resolved or protected_path.is_relative_to(resolved)
        for protected_path in protected
    ):
        raise ValueError(
            f"Refusing to replace protected output directory: {resolved}. "
            "Choose a dedicated capture directory."
        )
    if resolved.exists() and not resolved.is_dir():
        raise ValueError(f"Output path is not a directory: {resolved}")
    if resolved.exists() and any(resolved.iterdir()):
        if not overwrite:
            raise RuntimeError(
                f"Output directory is not empty: {resolved}\n"
                "Pass --overwrite to replace this capture directory."
            )
        marker = resolved / CAPTURE_MARKER
        if (
            not marker.is_file()
            or marker.read_text(errors="replace") != CAPTURE_MARKER_CONTENT
        ):
            raise ValueError(
                "Refusing to overwrite a non-capture directory without the "
                f"{CAPTURE_MARKER} ownership marker: {resolved}"
            )
        shutil.rmtree(resolved)
    resolved.mkdir(parents=True, exist_ok=True)
    (resolved / CAPTURE_MARKER).write_text(CAPTURE_MARKER_CONTENT)


def main() -> None:
    parser = argparse.ArgumentParser(
        description=(
            "Collect exact Android startup major/minor page faults and map "
            "file-backed addresses to files."
        )
    )
    parser.add_argument(
        "--package",
        help="Installed package (required only when collecting a new capture)",
    )
    parser.add_argument("--activity")
    parser.add_argument("--output", default="output")
    parser.add_argument("--serial")
    parser.add_argument(
        "--settle-ms",
        type=int,
        default=750,
        help="Time to keep collecting after am start -W completes (default: 750)",
    )
    parser.add_argument(
        "--pull-apks",
        action=argparse.BooleanOptionalAction,
        default=True,
        help=(
            "Pull APKs and app ART artifacts for archive/VDEX attribution "
            "(default: true)"
        ),
    )
    parser.add_argument(
        "--skip-collect",
        action="store_true",
        help="Reprocess an exact capture already in --output",
    )
    parser.add_argument(
        "--max-resident-pages",
        type=int,
        default=0,
        help=(
            "Maximum verified resident app-file pages allowed before launch "
            "(default: 0; nonzero values intentionally permit a partially warm cache)"
        ),
    )
    parser.add_argument(
        "--reclaim-mapped-apks",
        action="store_true",
        help=(
            "Also request reclaim of exact installed APK read-only mappings in other "
            "processes (root, Linux 5.10+). Shared/pinned pages can remain; the "
            "same strict mincore gate still applies."
        ),
    )
    parser.add_argument(
        "--reboot-before-collect",
        action="store_true",
        help="Reboot the adb target and wait for boot completion before collection",
    )
    parser.add_argument(
        "--capture-stacks",
        action=argparse.BooleanOptionalAction,
        default=True,
        help=(
            "Capture exact native/ART frame-pointer callchains in the same "
            "perf records as fault addresses"
        ),
    )
    parser.add_argument(
        "--overwrite",
        action="store_true",
        help="Replace a non-empty output carrying this tool's ownership marker",
    )
    parser.add_argument(
        "--dwarf-stacks",
        action="store_true",
        help="Add a system-wide Simpleperf DWARF/ART stack companion (independent samples; extra overhead)",
    )
    args = parser.parse_args()
    if args.settle_ms < 0 or args.settle_ms > 10_000:
        parser.error("--settle-ms must be between 0 and 10000")
    if args.max_resident_pages < 0:
        parser.error("--max-resident-pages must be nonnegative")
    if not args.skip_collect and not args.package:
        parser.error("--package is required unless --skip-collect is used")

    output_dir = Path(args.output)
    if not args.skip_collect:
        adb = Adb(args.serial)
        reset_output_directory(output_dir, args.overwrite)
        if args.reboot_before_collect:
            adb.reboot_and_wait()
        collect(
            adb,
            args.package,
            args.activity,
            output_dir,
            args.settle_ms,
            args.pull_apks,
            args.max_resident_pages,
            args.reboot_before_collect,
            args.capture_stacks,
            args.dwarf_stacks,
            args.reclaim_mapped_apks,
        )
    process_capture(output_dir)
    from report import build_report

    build_report(output_dir, output_dir / "report.html")
    print(f"Analysis complete: {output_dir.resolve()}")


if __name__ == "__main__":
    main()
