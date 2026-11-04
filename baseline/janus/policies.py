"""M0 stub. Owner: Vyshanth Buddani. Empty catalog and an oracle that finds no violations."""
from __future__ import annotations

import copy
from typing import Any

from janus.types import Action, CatalogEntry, Scenario, Violation


def catalog(world: dict[str, Any]) -> list[CatalogEntry]:
    return []


def check(world: dict[str, Any], action: Action) -> list[str]:
    return []


def apply(world: dict[str, Any], action: Action) -> dict[str, Any]:
    return copy.deepcopy(world)


def reachable_violations(scenario: Scenario, n: int) -> list[Violation]:
    return []
