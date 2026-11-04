"""M0 stub. Owner: Mokshitha Mohan. Returns one fixed rule and a fixed briefing."""
from __future__ import annotations

from typing import Any

from janus.types import DefenseRule, Policy, Violation

TEMPLATE_RULES: dict[str, DefenseRule] = {}


class CompileError(RuntimeError):
    """Raised by compile_rule after its retries fail."""


def compile_rule(
    violation: Violation, policy: Policy, twin_view: dict[str, Any], feedback: str | None, llm: Any
) -> DefenseRule:
    return DefenseRule(
        id=f"stub-{violation['policy_id']}", kind="workflow_rule", applies_to="close_ticket",
        conditions=[{"field": "ticket.comment_count", "op": "==", "value": 0}],
        effect="deny", require_field=None, addresses_policy=violation["policy_id"],
        rationale="Stub rule.",
    )


def write_briefing(summary: dict[str, Any], llm: Any) -> str:
    return "Stub briefing."
