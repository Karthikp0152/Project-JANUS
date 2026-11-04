"""M0 stub. Owner: Sai Vignesha Shesha Shyla. Approves every rule without checking it."""
from __future__ import annotations

from typing import Any

from janus.types import Action, DefenseRule, GateDecision, Scenario, Violation, Witness


def make_variants(violation: Violation, world: dict[str, Any]) -> list[Action]:
    return []


def verify(rule: DefenseRule, witness: Witness, scenario: Scenario, installed: list[DefenseRule]) -> GateDecision:
    return GateDecision(
        rule_id=rule["id"], status="approved",
        checks={f"V{i}": True for i in range(1, 7)}, reason="", rounds=1,
    )
