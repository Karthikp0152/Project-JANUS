"""Gate: the only way rules and text leave the sandbox (owner: Sai Vignesha).

export() lets through only rules whose GateDecision is "approved", plus the briefing
(a str or None). Anything else raises GateViolation, and nothing is exported.
Rejected and escalated decisions are never exported; the pipeline reports them as
unresolved risks in the briefing. evaluate_only() is the read-only canary endpoint.
"""
from __future__ import annotations

import json
from typing import Any, Literal

from janus.rules import RULE_KEYS, enforce
from janus.types import Action, DefenseRule, GateDecision

# Keys from traces, probes or actions. None of them may appear in an exported rule.
FORBIDDEN_KEYS = {"action_id", "tool", "args", "prefix", "violation", "steps_log", "trace", "witness"}


class GateViolation(Exception):
    """Raised when something other than approved rules and a briefing tries to cross the Gate."""


def _has_forbidden_keys(obj: Any) -> bool:
    if isinstance(obj, dict):
        return any(k in FORBIDDEN_KEYS or _has_forbidden_keys(v) for k, v in obj.items())
    if isinstance(obj, list):
        return any(_has_forbidden_keys(v) for v in obj)
    return False


def export(
    decisions: list[GateDecision],
    rules: list[DefenseRule],
    briefing: str | None,
    canaries: list[str] | None = None,
) -> dict[str, Any]:
    """Return {"rules": [...approved only...], "briefing": str | None}, or raise GateViolation.

    Safe to call repeatedly with the same rules. An empty rules list is valid, and so is
    briefing=None. Decisions that are not approved are ignored; they just don't export.
    """
    if briefing is not None and not isinstance(briefing, str):
        raise GateViolation("briefing must be a str or None")

    approved_ids = {d.get("rule_id") for d in decisions if d.get("status") == "approved"}
    exported: list[DefenseRule] = []
    for rule in rules:
        if not isinstance(rule, dict) or set(rule) != set(RULE_KEYS):
            raise GateViolation("rule is not in the DefenseRule shape")
        if _has_forbidden_keys(rule):
            raise GateViolation("rule contains trace, tool-call or probe fields")
        if rule["id"] not in approved_ids:
            raise GateViolation("rule has no approved decision")
        exported.append(rule)

    text = json.dumps(exported, sort_keys=True, default=str) + (briefing or "")
    for secret in canaries or []:
        if secret and secret in text:
            raise GateViolation("canary found in exported content")

    return {"rules": exported, "briefing": briefing}


def evaluate_only(rules: list[DefenseRule], action: Action, world: dict[str, Any]) -> Literal["allow", "deny"]:
    """Canary endpoint: what the shared interpreter would decide. Never executes the action."""
    return enforce(rules, action, world)
