import csv
import hashlib
import io
import json
import os
import platform
import re
import shlex
import subprocess
import time
from pathlib import Path
from typing import Iterable, Optional

from android_fault_visualizer.paths import (
    COLLECTOR_SOURCE,
    REMOTE_DIR,
    REMOTE_COLLECTOR,
    CACHE_RESIDENCY_FIELDS,
)


class Adb:
    def __init__(self, serial: Optional[str] = None):
        self.serial = self._resolve_serial(serial)
        self._root_template: Optional[str] = None

    @staticmethod
    def _resolve_serial(requested: Optional[str]) -> str:
        result = subprocess.run(
            ["adb", "devices"], capture_output=True, text=True, check=True
        )
        devices = []
        for line in result.stdout.splitlines()[1:]:
            columns = line.split()
            if len(columns) >= 2 and columns[1] == "device":
                devices.append(columns[0])

        if requested:
            if requested not in devices:
                raise RuntimeError(
                    f"ADB device {requested!r} is not connected. Connected: {devices}"
                )
            return requested
        if not devices:
            raise RuntimeError("No connected ADB device found")
        if len(devices) > 1:
            raise RuntimeError(
                "Multiple ADB devices are connected; select one with --serial: "
                + ", ".join(devices)
            )
        return devices[0]

    @property
    def base_command(self) -> list[str]:
        return ["adb", "-s", self.serial]

    def run(self, args: list[str], **kwargs) -> subprocess.CompletedProcess:
        return subprocess.run(self.base_command + args, **kwargs)

    def shell(self, args: list[str], **kwargs) -> subprocess.CompletedProcess:
        return self.run(["shell", *args], **kwargs)

    def shell_text(self, command: str, **kwargs) -> subprocess.CompletedProcess:
        return self.run(["shell", command], **kwargs)

    def ensure_root(self) -> None:
        root_result = self.run(["root"], capture_output=True, text=True)
        if root_result.returncode == 0:
            self.run(["wait-for-device"], check=True)

        candidates = [
            "sh -c {command}",
            "su 0 sh -c {command}",
            "su -c {command}",
        ]
        for template in candidates:
            command = template.format(command=shlex.quote("id"))
            result = self.shell_text(command, capture_output=True, text=True)
            if result.returncode == 0 and "uid=0" in result.stdout:
                self._root_template = template
                return
        raise RuntimeError(
            "Unable to acquire a root shell. Use a userdebug emulator/image or "
            "a rooted device with adb-accessible su."
        )

    def root_command(self, command: str) -> list[str]:
        if self._root_template is None:
            raise RuntimeError("ensure_root() must be called first")
        remote_command = self._root_template.format(command=shlex.quote(command))
        return self.base_command + ["shell", remote_command]

    def root_shell(self, command: str, **kwargs) -> subprocess.CompletedProcess:
        return subprocess.run(self.root_command(command), **kwargs)

    def getprop(self, name: str) -> str:
        return self.shell(
            ["getprop", name], capture_output=True, text=True, check=True
        ).stdout.strip()

    def reboot_and_wait(self, timeout_seconds: int = 180) -> None:
        self.run(["reboot"], check=True)
        self.run(["wait-for-device"], check=True)
        deadline = time.monotonic() + timeout_seconds
        while time.monotonic() < deadline:
            result = self.shell(
                ["getprop", "sys.boot_completed"],
                capture_output=True,
                text=True,
            )
            if result.returncode == 0 and result.stdout.strip() == "1":
                return
            time.sleep(1)
        raise RuntimeError("Timed out waiting for Android to finish rebooting")

    def pull_with_root_fallback(self, remote: str, local: Path) -> None:
        result = self.run(
            ["pull", remote, str(local)],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.PIPE,
            text=True,
        )
        if result.returncode == 0:
            return
        if self._root_template is None:
            raise RuntimeError(f"Unable to pull {remote}: {result.stderr.strip()}")
        remote_command = self._root_template.format(
            command=shlex.quote(f"cat {shlex.quote(remote)}")
        )
        with local.open("wb") as output:
            fallback = subprocess.run(
                self.base_command + ["exec-out", remote_command],
                stdout=output,
                stderr=subprocess.PIPE,
            )
        if fallback.returncode != 0:
            local.unlink(missing_ok=True)
            raise RuntimeError(
                f"Unable to pull {remote} with root: "
                + fallback.stderr.decode(errors="replace").strip()
            )


def find_ndk() -> Path:
    explicit = os.environ.get("ANDROID_NDK_HOME") or os.environ.get("ANDROID_NDK_ROOT")
    if explicit:
        path = Path(explicit)
        if path.is_dir():
            return path

    sdk_root = os.environ.get("ANDROID_HOME") or os.environ.get("ANDROID_SDK_ROOT")
    if not sdk_root:
        sdk_root = str(Path.home() / "Library" / "Android" / "sdk")
    ndk_root = Path(sdk_root) / "ndk"
    candidates = [path for path in ndk_root.iterdir()] if ndk_root.is_dir() else []
    candidates = [path for path in candidates if path.is_dir()]
    if not candidates:
        raise RuntimeError(
            "Android NDK not found. Install an NDK or set ANDROID_NDK_HOME."
        )

    def version_key(path: Path) -> tuple[int, ...]:
        return tuple(int(part) for part in re.findall(r"\d+", path.name))

    return max(candidates, key=version_key)


def find_compiler(ndk: Path, abi: str, sdk: int) -> Path:
    prebuilt_root = ndk / "toolchains" / "llvm" / "prebuilt"
    prebuilts = [path for path in prebuilt_root.iterdir() if path.is_dir()]
    if not prebuilts:
        raise RuntimeError(f"No LLVM prebuilt found in {ndk}")
    host_name = platform.system().lower()
    preferred = [
        path
        for path in prebuilts
        if (
            (host_name == "darwin" and path.name.startswith("darwin"))
            or (host_name == "linux" and path.name.startswith("linux"))
            or (host_name == "windows" and path.name.startswith("windows"))
        )
    ]
    prebuilt = preferred[0] if preferred else prebuilts[0]
    prefixes = {
        "arm64-v8a": "aarch64-linux-android",
        "armeabi-v7a": "armv7a-linux-androideabi",
        "x86_64": "x86_64-linux-android",
        "x86": "i686-linux-android",
    }
    if abi not in prefixes:
        raise RuntimeError(f"Unsupported Android ABI for collector: {abi}")
    prefix = prefixes[abi]
    compiler = prebuilt / "bin" / f"{prefix}{max(21, sdk)}-clang"
    if compiler.exists():
        return compiler

    matches = list((prebuilt / "bin").glob(f"{prefix}*-clang"))
    if not matches:
        raise RuntimeError(f"No {prefix} compiler found in {prebuilt / 'bin'}")

    def compiler_api(path: Path) -> int:
        match = re.search(r"(\d+)-clang$", path.name)
        return int(match.group(1)) if match else 0

    compatible = [path for path in matches if compiler_api(path) <= sdk]
    return max(compatible or matches, key=compiler_api)


def build_and_push_collector(
    adb: Adb, output_dir: Path, abi: str, sdk: int
) -> dict[str, str]:
    ndk = find_ndk()
    compiler = find_compiler(ndk, abi, sdk)
    local_binary = output_dir / "page_fault_collector"
    subprocess.run(
        [
            str(compiler),
            "-O2",
            "-Wall",
            "-Wextra",
            "-Werror",
            str(COLLECTOR_SOURCE),
            "-o",
            str(local_binary),
        ],
        check=True,
    )
    adb.root_shell(f"mkdir -p {shlex.quote(REMOTE_DIR)}", check=True)
    adb.run(
        ["push", str(local_binary), REMOTE_COLLECTOR],
        check=True,
        stdout=subprocess.DEVNULL,
    )
    adb.root_shell(f"chmod 755 {shlex.quote(REMOTE_COLLECTOR)}", check=True)
    return {
        "ndk": ndk.name,
        "compiler": compiler.name,
        "collector_source_sha256": hashlib.sha256(
            COLLECTOR_SOURCE.read_bytes()
        ).hexdigest(),
        "collector_cpu_list_header_sha256": hashlib.sha256(
            COLLECTOR_SOURCE.with_name("cpu_list.h").read_bytes()
        ).hexdigest(),
        "collector_binary_sha256": hashlib.sha256(
            local_binary.read_bytes()
        ).hexdigest(),
    }


def package_paths(adb: Adb, package: str) -> list[str]:
    result = adb.shell(
        ["pm", "path", package], capture_output=True, text=True, check=True
    )
    paths = []
    for line in result.stdout.splitlines():
        if line.startswith("package:"):
            paths.append(line.removeprefix("package:").strip())
    if not paths:
        raise RuntimeError(f"No installed APK paths found for {package}")
    return paths


def package_files(adb: Adb, package: str, apk_paths: list[str]) -> list[str]:
    roots = sorted({str(Path(path).parent) for path in apk_paths})
    data_roots = [f"/data/user/0/{package}", f"/data/user_de/0/{package}"]
    commands = [
        f"test -f {shlex.quote(path)} || "
        f"{{ echo 'Installed APK disappeared: {shlex.quote(path)}' >&2; exit 74; }};"
        for path in apk_paths
    ]
    for root in [*roots, *data_roots]:
        commands.append(
            f"if [ -d {shlex.quote(root)} ]; then "
            f"find {shlex.quote(root)} -type f -print0 2>/dev/null || true; fi;"
        )
    result = adb.root_shell(
        " ".join(commands), capture_output=True, text=True, check=True
    )
    return sorted(set(apk_paths) | set(filter(None, result.stdout.split("\0"))))


def cache_targets(files: Iterable[str]) -> list[str]:
    return sorted(set(filter(None, files)))


def run_collector_file_command(
    adb: Adb,
    mode: str,
    files: list[str],
    diagnostics: Optional[list[dict[str, object]]] = None,
) -> str:
    if not files:
        return ""
    if mode not in ("--residency", "--evict"):
        raise ValueError(f"Unsupported collector file mode: {mode}")

    batches: list[list[str]] = []
    batch: list[str] = []
    batch_length = len(REMOTE_COLLECTOR) + len(mode) + 2
    for file_name in files:
        quoted_length = len(shlex.quote(file_name)) + 1
        if batch and batch_length + quoted_length > 24_000:
            batches.append(batch)
            batch = []
            batch_length = len(REMOTE_COLLECTOR) + len(mode) + 2
        batch.append(file_name)
        batch_length += quoted_length
    if batch:
        batches.append(batch)

    outputs: list[str] = []
    residency_header = "file_name,size_bytes,total_pages,resident_pages\n"
    for batch_index, file_batch in enumerate(batches):
        command = " ".join(
            [
                shlex.quote(REMOTE_COLLECTOR),
                mode,
                *(shlex.quote(file_name) for file_name in file_batch),
            ]
        )
        result = adb.root_shell(command, capture_output=True, text=True)
        if diagnostics is not None:
            diagnostics.append(
                {
                    "batch": batch_index,
                    "target_count": len(file_batch),
                    "exit_status": result.returncode,
                    "stderr": result.stderr.strip(),
                }
            )
        result.check_returncode()
        stdout = result.stdout
        if mode == "--residency":
            if not stdout.startswith(residency_header):
                raise RuntimeError("Residency collector returned an invalid CSV header")
            if batch_index > 0:
                stdout = stdout[len(residency_header) :]
        outputs.append(stdout)
    return "".join(outputs)


def parse_residency(
    text: str,
    phase: str,
    expected_files: Optional[Iterable[str]] = None,
    required_files: Optional[Iterable[str]] = None,
    warnings: Optional[list[str]] = None,
) -> list[dict[str, object]]:
    if not text:
        return []
    rows = []
    reader = csv.DictReader(io.StringIO(text))
    expected_header = [
        "file_name",
        "size_bytes",
        "total_pages",
        "resident_pages",
    ]
    if reader.fieldnames != expected_header:
        raise RuntimeError(f"Invalid cache-residency CSV header: {reader.fieldnames!r}")
    seen = set()
    for row in reader:
        if None in row or any(value is None for value in row.values()):
            raise RuntimeError(f"Malformed cache-residency row: {row!r}")
        file_name = row["file_name"]
        if file_name in seen:
            raise RuntimeError(f"Duplicate cache-residency row for {file_name!r}")
        seen.add(file_name)
        size_bytes = int(row["size_bytes"])
        total_pages = int(row["total_pages"])
        resident_pages = int(row["resident_pages"])
        if (
            size_bytes < 0
            or total_pages < 0
            or resident_pages < 0
            or resident_pages > total_pages
        ):
            raise RuntimeError(f"Invalid cache-residency counts: {row!r}")
        rows.append(
            {
                "phase": phase,
                "file_name": file_name,
                "size_bytes": size_bytes,
                "total_pages": total_pages,
                "resident_pages": resident_pages,
            }
        )
    if expected_files is not None:
        expected = set(expected_files)
        missing = sorted(expected - seen)
        unexpected = sorted(seen - expected)
        required_missing = sorted(set(required_files or ()) - seen)
        if required_missing or unexpected:
            raise RuntimeError(
                "Cache-residency coverage mismatch: "
                f"missing_required={required_missing!r}, "
                f"unexpected={unexpected!r}"
            )
        if missing and warnings is not None:
            warnings.append(
                f"{phase}: ignored {len(missing)} non-essential app files that "
                "disappeared during the residency check: " + ", ".join(missing)
            )
    return rows


def write_residency(output_dir: Path, rows: list[dict[str, object]]) -> None:
    with (output_dir / "cache_residency.csv").open("w", newline="") as file:
        writer = csv.DictWriter(file, fieldnames=CACHE_RESIDENCY_FIELDS)
        writer.writeheader()
        writer.writerows(rows)


def verify_cache_residency(
    rows: list[dict[str, object]], max_resident_pages: int, phase: str
) -> None:
    phase_rows = [row for row in rows if row["phase"] == phase]
    if not phase_rows:
        raise RuntimeError(f"No cache-residency evidence was captured for {phase}")
    resident_pages = sum(int(row["resident_pages"]) for row in phase_rows)
    if resident_pages <= max_resident_pages:
        return
    resident_files = [
        f"{row['file_name']}={row['resident_pages']}/{row['total_pages']} pages"
        for row in phase_rows
        if int(row["resident_pages"]) > 0
    ]
    raise RuntimeError(
        f"Page-cache eviction verification failed at {phase}: "
        f"{resident_pages} resident pages exceeds --max-resident-pages="
        f"{max_resident_pages}. "
        + "; ".join(resident_files)
        + ". Reboot the target before the next iteration, or use an explicit "
        "nonzero threshold only if a partially warm cache is intentional."
    )


def cache_verification_summary(
    rows: list[dict[str, object]], phase: str
) -> dict[str, object]:
    phase_rows = [row for row in rows if row["phase"] == phase]
    return {
        "phase": phase,
        "files_checked": len(phase_rows),
        "resident_pages": sum(int(row["resident_pages"]) for row in phase_rows),
        "total_pages": sum(int(row["total_pages"]) for row in phase_rows),
        "fully_evicted_files": sum(
            int(row["resident_pages"]) == 0 for row in phase_rows
        ),
    }


def write_capture_metadata(output_dir: Path, metadata: dict[str, object]) -> None:
    (output_dir / "capture_metadata.json").write_text(
        json.dumps(metadata, indent=2, sort_keys=True) + "\n"
    )


def record_cache_gate(
    output_dir: Path,
    metadata: dict[str, object],
    rows: list[dict[str, object]],
    max_resident_pages: int,
    phase: str,
) -> None:
    metadata["cache_verification"] = cache_verification_summary(rows, phase)
    try:
        verify_cache_residency(rows, max_resident_pages, phase)
    except RuntimeError as error:
        metadata["capture_status"] = "cache_verification_failed"
        metadata["failure"] = str(error)
        write_capture_metadata(output_dir, metadata)
        raise
    metadata["capture_status"] = f"cache_verified_{phase}"
    metadata.pop("failure", None)
    write_capture_metadata(output_dir, metadata)


def wait_for_package_stopped(adb: Adb, package: str, timeout_seconds: int = 10) -> None:
    deadline = time.monotonic() + timeout_seconds
    while time.monotonic() < deadline:
        result = adb.shell(
            ["ps", "-A", "-o", "NAME"], capture_output=True, text=True, check=True
        )
        names = [line.strip() for line in result.stdout.splitlines()[1:]]
        remaining = [
            name for name in names if name == package or name.startswith(f"{package}:")
        ]
        if not remaining:
            return
        time.sleep(0.05)
    raise RuntimeError(
        f"Package processes did not stop within {timeout_seconds}s: "
        + ", ".join(remaining)
    )


def stop_and_enumerate_cache_targets(
    adb: Adb, package: str, apk_paths: list[str]
) -> list[str]:
    adb.shell(["am", "force-stop", package], check=True)
    wait_for_package_stopped(adb, package)
    return cache_targets(package_files(adb, package, apk_paths))


def drop_caches(adb: Adb, sdk: int, files: list[str]) -> None:
    adb.root_shell("sync", check=True)
    direct = adb.root_shell(
        "echo 3 > /proc/sys/vm/drop_caches",
        capture_output=True,
        text=True,
    )
    if direct.returncode != 0:
        if sdk < 31:
            raise RuntimeError(
                "drop_caches failed: " + (direct.stderr or direct.stdout).strip()
            )
        # Android deliberately grants this property to the adb shell domain.
        # On the common production-adbd + Magisk/KernelSU arrangement, an
        # explicit root_shell() would enter a third-party domain that SELinux
        # may not permit to set perf_drop_caches_prop. Plain adb shell preserves
        # the permitted domain there. A root-adbd userdebug image can keep a
        # root SELinux domain even for this call, but normally succeeds through
        # the direct sysctl path above; either failure remains fatal.
        adb.shell(["setprop", "perf.drop_caches", "3"], check=True)
        deadline = time.monotonic() + 10
        while time.monotonic() < deadline:
            value = adb.getprop("perf.drop_caches")
            if value == "0":
                break
            time.sleep(0.1)
        else:
            raise RuntimeError("Timed out waiting for perf.drop_caches to complete")

    # This is file-scoped and harmless if global reclaim already evicted a page.
    run_collector_file_command(adb, "--evict", files)


def resolve_activity(adb: Adb, package: str, requested: Optional[str]) -> str:
    if requested:
        if "/" in requested:
            return requested
        return f"{package}/{requested}"
    result = adb.shell(
        ["cmd", "package", "resolve-activity", "--brief", package],
        capture_output=True,
        text=True,
        check=True,
    )
    candidates = [line.strip() for line in result.stdout.splitlines() if "/" in line]
    if not candidates:
        raise RuntimeError(f"Unable to resolve launcher activity for {package}")
    return candidates[-1]


def dump_process_state(adb: Adb, package: str, output_dir: Path) -> int:
    pid_text = adb.shell(
        ["pidof", "-s", package], capture_output=True, text=True, check=False
    ).stdout.strip()
    if not pid_text:
        raise RuntimeError(f"Process {package} exited before state capture")
    pid = int(pid_text)
    maps = adb.root_shell(
        f"cat /proc/{pid}/maps", capture_output=True, text=True, check=True
    ).stdout
    (output_dir / "maps.txt").write_text(maps)
    stat = adb.root_shell(
        f"cat /proc/{pid}/stat", capture_output=True, text=True, check=True
    ).stdout.strip()
    (output_dir / "process_stat.txt").write_text(stat + "\n")
    return pid


def dump_inode_mapping(
    adb: Adb,
    package: str,
    apk_paths: list[str],
    output_dir: Path,
    *,
    append: bool = False,
) -> None:
    roots = sorted({str(Path(path).parent) for path in apk_paths})
    roots.extend([f"/data/user/0/{package}", f"/data/user_de/0/{package}"])
    parts = [
        (
            f"stat -c '%d|%i|%s|%n' {shlex.quote(apk_path)} || "
            f"{{ echo 'Unable to identify installed APK inode: "
            f"{shlex.quote(apk_path)}' >&2; exit 75; }};"
        )
        for apk_path in apk_paths
    ]
    for root in roots:
        parts.append(
            f"if [ -d {shlex.quote(root)} ]; then "
            f"find {shlex.quote(root)} -type f "
            "-exec sh -c 'for file do "
            "stat -c '\"'\"'%d|%i|%s|%n'\"'\"' \"$file\" 2>/dev/null || true; "
            "done' sh {} + 2>/dev/null || true; fi;"
        )
    result = adb.root_shell(
        "{ " + " ".join(parts) + " }",
        capture_output=True,
        text=True,
        check=True,
    )
    with (output_dir / "inodes.txt").open("a" if append else "w") as output:
        output.write(result.stdout)


def pull_artifacts(
    adb: Adb, apk_paths: list[str], abi: str, output_dir: Path
) -> dict[str, str]:
    artifacts_dir = output_dir / "artifacts"
    artifacts_dir.mkdir(exist_ok=True)
    mapping = {}
    remote_paths = list(apk_paths)
    oat_arch = {
        "armeabi-v7a": "arm",
        "arm64-v8a": "arm64",
        "x86": "x86",
        "x86_64": "x86_64",
    }.get(abi, abi)
    for apk_path in apk_paths:
        oat_directory = Path(apk_path).parent / "oat" / oat_arch
        artifact_stem = Path(apk_path).stem
        candidates = [
            str(oat_directory / f"{artifact_stem}{suffix}")
            for suffix in (".odex", ".vdex", ".art")
        ]
        command = " ".join(
            [
                "for candidate in",
                *(shlex.quote(candidate) for candidate in candidates),
                '; do [ -f "$candidate" ] && printf "%s\\n" "$candidate"; done; true',
            ]
        )
        result = adb.root_shell(command, capture_output=True, text=True, check=True)
        remote_paths.extend(result.stdout.splitlines())
    for remote_path in dict.fromkeys(remote_paths):
        digest = hashlib.sha256(remote_path.encode()).hexdigest()[:10]
        local_path = artifacts_dir / f"{digest}-{Path(remote_path).name}"
        adb.pull_with_root_fallback(remote_path, local_path)
        mapping[remote_path] = str(local_path.relative_to(output_dir))
    (output_dir / "artifacts.json").write_text(
        json.dumps(mapping, indent=2, sort_keys=True) + "\n"
    )
    return mapping


def pull_stack_binaries(adb: Adb, output_dir: Path, warnings: list[str]) -> None:
    """Read symbol-bearing libraries after recording, never before cache checks."""
    from .artifacts import parse_maps

    mapping_path = output_dir / "artifacts.json"
    mapping = json.loads(mapping_path.read_text()) if mapping_path.exists() else {}
    (output_dir / "artifacts").mkdir(exist_ok=True)
    attempted: set[str] = set()
    for entry in parse_maps(output_dir):
        if not entry.file_name:
            continue
        # A deleted mapping may now name a different file. Keep its raw IPs
        # rather than symbolizing it with whatever replaced the original file.
        if entry.file_name.endswith(" (deleted)"):
            continue
        remote = entry.file_name
        if (
            not (
                remote.endswith(".so")
                or Path(remote).name
                in {"linker", "linker64", "app_process32", "app_process64"}
            )
            or not remote.startswith("/")
            or remote in mapping
            or remote in attempted
        ):
            continue
        attempted.add(remote)
        local = (
            output_dir
            / "artifacts"
            / (
                hashlib.sha256(remote.encode()).hexdigest()[:10]
                + "-"
                + Path(remote).name
            )
        )
        try:
            adb.pull_with_root_fallback(remote, local)
            mapping[remote] = str(local.relative_to(output_dir))
        except (RuntimeError, OSError, subprocess.CalledProcessError) as error:
            warnings.append(
                f"Could not pull stack symbols for {remote}; raw addresses retained: {error}"
            )
    mapping_path.write_text(json.dumps(mapping, indent=2) + "\n")
