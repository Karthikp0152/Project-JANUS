"""M0 stub. Owner: Sai Vignesha Shesha Shyla. Passes rules through without checking them."""
from __future__ import annotations

from typing import Any, Literal

from janus.types import Action, DefenseRule, GateDecision


class GateViolation(Exception):
    """Raised when something other than approved rules and a briefing tries to cross the Gate."""


def export(
    decisions: list[GateDecision],
    rules: list[DefenseRule],
    briefing: str | None,
    canaries: list[str] | None = None,
) -> dict[str, Any]:
    return {"rules": list(rules), "briefing": briefing}


def evaluate_only(rules: list[DefenseRule], action: Action, world: dict[str, Any]) -> Literal["allow", "deny"]:
    return "allow"
