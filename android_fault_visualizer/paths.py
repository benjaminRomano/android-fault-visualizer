from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parent.parent
TRACE_PROCESSOR = ROOT_DIR / "trace_processor"
TRACE_CONFIG = ROOT_DIR / "ftrace.config"
COLLECTOR_SOURCE = ROOT_DIR / "native" / "page_fault_collector.c"
REMOTE_DIR = "/data/local/tmp/android-fault-visualizer"
REMOTE_COLLECTOR = f"{REMOTE_DIR}/page_fault_collector"
REMOTE_FAULTS = f"{REMOTE_DIR}/fault_events.csv"
REMOTE_MAPPINGS = f"{REMOTE_DIR}/mapping_events.csv"
REMOTE_CALLCHAINS = f"{REMOTE_DIR}/fault_callchains.csv"
CAPTURE_MARKER = ".android-fault-visualizer-capture"
CAPTURE_MARKER_CONTENT = "android-fault-visualizer capture v1\n"
CACHE_RESIDENCY_FIELDS = [
    "phase",
    "file_name",
    "size_bytes",
    "total_pages",
    "resident_pages",
]
