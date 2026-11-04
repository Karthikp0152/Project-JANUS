"""M0 stub. Owner: Sai Vignesha Shesha Shyla. Accepts every rule and allows every action."""
from __future__ import annotations

from typing import Any, Callable, Literal

from janus.types import Action, DefenseRule

FIELDS: dict[str, Callable[[Action, dict[str, Any]], Any]] = {}


def validate_schema(rule: DefenseRule) -> tuple[bool, str]:
    return True, ""


def enforce(rules: list[DefenseRule], action: Action, world: dict[str, Any]) -> Literal["allow", "deny"]:
    return "allow"
