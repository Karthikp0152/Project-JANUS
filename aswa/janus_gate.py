from __future__ import annotations

from typing import Any


VIOLATION_TO_DEFENSE = {
    "Do not grant access to payroll or HR folders to contractors or external users.": {
        "kind": "firewall_rule",
        "artifact": "DENY principal=external folder=payroll,hr",
    },
    "Do not email confidential or restricted files to external addresses.": {
        "kind": "dlp_signature",
        "artifact": "BLOCK email attachment.sensitivity in {confidential,restricted} AND recipient.external=true",
    },
    "Do not create payments above $500 without dual approval.": {
        "kind": "payment_control",
        "artifact": "REQUIRE dual_approval IF amount > 500",
    },
    "Do not close a ticket without first adding a comment.": {
        "kind": "workflow_rule",
        "artifact": "REQUIRE comment BEFORE ticket.close",
    },
}

ALLOWED_DEFENSE_KINDS = {"firewall_rule", "dlp_signature", "payment_control", "workflow_rule"}


class JanusGate:
    """Telemetry may enter. Validated defenses may leave. Shadow payloads may not leave."""

    def validate_and_export(
        self,
        learn_result: dict[str, Any],
        asa_result: dict[str, Any],
        sanitized_telemetry: list[dict[str, Any]],
    ) -> dict[str, Any]:
        approved: list[dict[str, Any]] = []
        rejected: list[dict[str, Any]] = []

        for item in learn_result.get("countermeasures_designed", []):
            ok, reason = self._validate_countermeasure(item)
            if ok:
                approved.append(
                    {
                        "kind": item["kind"],
                        "artifact": item["artifact"],
                        "addresses": item["addresses"],
                        "validated": True,
                    }
                )
            else:
                rejected.append({"countermeasure": item, "reason": reason})

        return {
            "direction": "shadow -> light allowed kinds: defensive patches only",
            "validated": True,
            "defenses": approved,
            "rejected": rejected,
            "telemetry_ingress_ok": True,
            "sanitized_telemetry_reflected": sanitized_telemetry,
            "blocked_exports": {
                "asa_best_trace": asa_result.get("best_trace"),
                "reason": "Janus Gate blocks malicious or probing payloads from leaving the sandbox.",
            },
            "payload_escaped": False,
        }

    def _validate_countermeasure(self, item: dict[str, Any]) -> tuple[bool, str]:
        if item.get("kind") not in ALLOWED_DEFENSE_KINDS:
            return False, "kind not in allowed defensive export set"
        if not item.get("artifact"):
            return False, "empty artifact"
        if "tool" in item or "args" in item or "payload" in item:
            return False, "looks like an attack payload, not a defense"
        expected = VIOLATION_TO_DEFENSE.get(item.get("addresses", ""))
        if expected and expected["artifact"] != item["artifact"]:
            return False, "artifact does not match known countermeasure for this vulnerability"
        return True, "ok"

    def would_allow_payload(self, payload: Any) -> bool:
        return False
