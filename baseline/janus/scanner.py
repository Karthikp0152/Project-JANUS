"""Independent leak / escape scanner. Owner: Pradeep Krishnamoorthy.

This module imports only `janus.types`. It never calls pipeline, verifier or gate code, so
a bug there cannot hide a leak from the scanner (M1 Section 3.7: "scan of the twin and every prompt").

Definitions (COORDINATION 11.6 / 12.7):
- LEAK:   a planted canary secret (or a common secret shape) appears in the twin dump, in any
          LLM prompt, in any log line, or anywhere in the serialized export.
- ESCAPE: the export contains a trace, a tool call or probe content (a Witness, an Action,
          a Violation record, or a value equal to something the probe used). The fields a valid
          DefenseRule must hold (`applies_to` tool name, `require_field`, condition values) are
          exempt from the value check, because rules legitimately mention tools and labels.

Limitations (stated on purpose, see Section 5 of the report):
- Substring match only: a canary split across two list items or encoded (base64, hex) is not found.
- Escape detection is key- and value-based; a trace paraphrased into free text is not found.
- `artifacts["probe_values"]` must be filled by the pipeline, otherwise the value check is skipped.
"""
from __future__ import annotations

import json
import re
from typing import Any

from janus.types import ALL_TOOLS, ScanReport

# Keys that never belong in an exported DefenseRule or briefing. `applies_to` (a tool name) is allowed.
ESCAPE_KEYS = frozenset(
    {"action_id", "tool", "args", "prefix", "violation", "steps_log", "trace", "witness", "witnesses"}
)

# Common secret shapes. The key=value forms skip values already redacted by the mirror ([REDACTED]).
SECRET_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    ("api-key", re.compile(r"sk-[A-Za-z0-9]{16,}")),
    ("bearer", re.compile(r"(?i)bearer\s+(?!\[REDACTED\])[A-Za-z0-9._\-]{8,}")),
    ("aws-key", re.compile(r"AKIA[0-9A-Z]{16}")),
    ("private-key", re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----")),
    (
        "key=value",
        re.compile(r"(?i)\b(?:password|passwd|secret|token|api[_-]?key)\s*[:=]\s*(?!\[REDACTED\])[^\s,;\"']{4,}"),
    ),
]


def mask(text: str) -> str:
    """Show at most 2 characters of a secret so the report itself never leaks it."""
    if len(text) <= 4:
        return "*" * len(text)
    return f"{text[:2]}...({len(text)} chars)"


def _as_text(value: Any) -> str:
    if isinstance(value, str):
        return value
    return json.dumps(value, sort_keys=True, default=str)


def _locations(artifacts: dict[str, Any], export: dict[str, Any]) -> list[tuple[str, str]]:
    """Flatten everything that must be secret-free into (location label, text) pairs."""
    places: list[tuple[str, str]] = []
    places.append(("twin_dump", _as_text(artifacts.get("twin_dump", ""))))
    for i, prompt in enumerate(artifacts.get("llm_prompts", []) or []):
        places.append((f"llm_prompts[{i}]", _as_text(prompt)))
    for i, line in enumerate(artifacts.get("logs", []) or []):
        places.append((f"logs[{i}]", _as_text(line)))
    places.append(("export", _as_text(export)))
    return places


def _scan_leaks(places: list[tuple[str, str]], canaries: list[str], details: list[str]) -> int:
    leaks = 0
    for where, text in places:
        for canary in canaries:
            if canary and canary in text:
                leaks += 1
                details.append(f"leak: canary {mask(canary)} found in {where}")
        for label, pattern in SECRET_PATTERNS:
            for match in pattern.finditer(text):
                leaks += 1
                details.append(f"leak: {label} pattern {mask(match.group(0))} found in {where}")
    return leaks


def _walk(node: Any, path: str):
    """Yield (path, key or None, value) for every node of a nested JSON-like structure."""
    if isinstance(node, dict):
        for key, value in node.items():
            child = f"{path}.{key}" if path else str(key)
            yield child, str(key), value
            yield from _walk(value, child)
    elif isinstance(node, (list, tuple)):
        for i, value in enumerate(node):
            child = f"{path}[{i}]"
            yield child, None, value
            yield from _walk(value, child)


RULE_CONDITION_VALUE = re.compile(r"\.conditions\[\d+\]\.value$")


def _is_rule_field(path: str, value: Any) -> bool:
    """Fields a valid DefenseRule must contain, so matching probe content there is not an escape:
    `applies_to` (a tool name), `require_field`, and the `value` of a condition."""
    if path.endswith(".applies_to"):
        return value in ALL_TOOLS
    return path.endswith(".require_field") or bool(RULE_CONDITION_VALUE.search(path))


def _scan_escapes(export: dict[str, Any], probe_values: list[str], details: list[str]) -> int:
    escapes = 0
    probe_set = {str(v) for v in probe_values if str(v)}
    for path, key, value in _walk(export, ""):
        if key is not None and key.lower() in ESCAPE_KEYS:
            escapes += 1
            details.append(f"escape: key '{key}' at export.{path}")
        if isinstance(value, str) and value in probe_set and not _is_rule_field(path, value):
            escapes += 1
            details.append(f"escape: value equal to probe content {mask(value)} at export.{path}")
    return escapes


def scan(artifacts: dict[str, Any], canaries: list[str], export: dict[str, Any]) -> ScanReport:
    """Return leak and escape counts for one run.

    artifacts: {"twin_dump": str, "llm_prompts": [str], "logs": [str], "probe_values": [str]}
    canaries:  Scenario.secrets (the planted secret strings)
    export:    RunResult.exports, everything that crossed the Gate
    """
    artifacts = artifacts or {}
    export = export or {}
    details: list[str] = []
    leaks = _scan_leaks(_locations(artifacts, export), list(canaries or []), details)
    escapes = _scan_escapes(export, list(artifacts.get("probe_values", []) or []), details)
    return ScanReport(leaks=leaks, escapes=escapes, details=details)
