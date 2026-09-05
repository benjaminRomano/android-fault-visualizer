"""Portable fault explorer shared (vendored) by the Android and iOS tools."""

import html
import json
import re
from pathlib import Path


def write_report(data: dict, output: Path, plotly_js: str) -> None:
    assets = Path(__file__).parent
    document = (assets / "report.html").read_text()
    payload = json.dumps(data, separators=(",", ":"), allow_nan=False)
    # Trace symbols and paths are untrusted. Never allow them to close a script.
    payload = (
        payload.replace("<", "\\u003c").replace(">", "\\u003e").replace("&", "\\u0026")
    )
    replacements = {
        "TITLE": html.escape(data["title"]),
        "STYLE": (assets / "report.css").read_text(),
        "PLOTLY": plotly_js,
        "DATA": payload,
        "SCRIPT": (assets / "report.js").read_text(),
        "MODEL": (assets / "model.js").read_text(),
        "STACKS": (assets / "stacks.js").read_text(),
    }
    # One pass: a symbol containing __SCRIPT__ must remain data, not a template.
    document = re.sub(
        r"__(TITLE|STYLE|PLOTLY|DATA|SCRIPT|MODEL|STACKS)__",
        lambda match: replacements[match.group(1)],
        document,
    )
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(document)
