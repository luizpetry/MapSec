"""JSON output writer."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from mapsec.core.models import ScanReport


def write_json(report: ScanReport, output_path: str | Path) -> Path:
    """Write scan report to JSON file.

    Args:
        report: The scan report to serialize.
        output_path: Path to write the JSON file.

    Returns:
        The Path object of the written file.
    """
    path = Path(output_path)
    data = report.to_dict()

    path.write_text(
        json.dumps(data, indent=2, ensure_ascii=False),
        encoding="utf-8",
    )

    return path


def report_to_json_string(report: ScanReport) -> str:
    """Convert scan report to JSON string.

    Args:
        report: The scan report to serialize.

    Returns:
        JSON string representation.
    """
    return json.dumps(report.to_dict(), indent=2, ensure_ascii=False)
