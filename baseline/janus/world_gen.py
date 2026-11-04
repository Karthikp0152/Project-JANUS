"""M0 stub. Owner: Vyshanth Buddani. Returns empty-but-valid scenarios."""
from __future__ import annotations

from janus.types import DEFAULT_SEED, Scenario


def generate(split: str, n: int, seed: int = DEFAULT_SEED) -> list[Scenario]:
    world = {
        "users": {}, "folders": {}, "files": {}, "tickets": {}, "payments": [], "emails": [],
        "links": [], "roles": {}, "vendors": {}, "audit": [],
        "thresholds": {"payment_dual_approval": 500},
    }
    return [
        Scenario(
            id=f"{split}-{i:03d}", split=split, seed=seed, world=dict(world), policies=[],
            enforced_policy_ids=[], telemetry=[], secrets=[], ground_truth=[],
            benign_actions=[], hidden_variants=[],
        )
        for i in range(n)
    ]
