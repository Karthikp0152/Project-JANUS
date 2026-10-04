from __future__ import annotations

import re
from copy import deepcopy
from typing import Any

from .world import EnterpriseWorld

SECRET_KEYS = {"token", "password", "secret", "api_key", "authorization"}
SECRET_RE = re.compile(r"(?i)(token|password|secret|api[_-]?key)\s*[:=]\s*\S+")


def sanitize_value(value: Any) -> Any:
    if isinstance(value, dict):
        return {
            key: "[REDACTED]" if key.lower() in SECRET_KEYS else sanitize_value(item)
            for key, item in value.items()
        }
    if isinstance(value, list):
        return [sanitize_value(item) for item in value]
    if isinstance(value, str):
        return SECRET_RE.sub(r"\1=[REDACTED]", value)
    return value


class RealityMirroringEngine:
    def mirror(self, light: EnterpriseWorld, telemetry: list[dict[str, Any]]) -> dict[str, Any]:
        clean_telemetry = sanitize_value(deepcopy(telemetry))
        shadow = light.snapshot()
        for meta in shadow.files.values():
            meta["contents"] = "[SANITIZED]"
        applied = []
        for event in clean_telemetry:
            applied.append(shadow.ingest_telemetry(event))
        return {
            "shadow": shadow,
            "sanitized_telemetry": clean_telemetry,
            "applied_events": applied,
            "redactions": self._redaction_report(telemetry, clean_telemetry),
        }

    def _redaction_report(self, raw: Any, clean: Any) -> int:
        raw_s = str(raw)
        clean_s = str(clean)
        return clean_s.count("[REDACTED]") + clean_s.count("[SANITIZED]") - raw_s.count("[REDACTED]")
