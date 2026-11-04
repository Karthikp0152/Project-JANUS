"""M0 stub. Owner: Pradeep Krishnamoorthy. Reports no leaks or escapes without scanning."""
from __future__ import annotations

from typing import Any

from janus.types import ScanReport


def scan(artifacts: dict[str, Any], canaries: list[str], export: dict[str, Any]) -> ScanReport:
    return ScanReport(leaks=0, escapes=0, details=[])
