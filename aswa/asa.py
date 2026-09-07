from __future__ import annotations

import random
from typing import Any

from .world import EnterpriseWorld

ACTION_CATALOG: list[dict[str, Any]] = [
    {
        "id": "grant_payroll_external",
        "tool": "grant_access",
        "args": {"folder": "payroll", "principal": "jane@vendor.com"},
    },
    {
        "id": "grant_payroll_temp_hire",
        "tool": "grant_access",
        "args": {"folder": "payroll", "principal": "temp.hire@contractor.net"},
    },
    {
        "id": "grant_runbook_internal",
        "tool": "grant_access",
        "args": {"folder": "it-runbooks", "principal": "alex"},
    },
    {
        "id": "email_salary_external",
        "tool": "send_email",
        "args": {
            "to": "jane@vendor.com",
            "body": "[sandbox probe]",
            "attachment": "q4_salary.xlsx",
        },
    },
    {
        "id": "email_salary_rival",
        "tool": "send_email",
        "args": {
            "to": "rival@outside.example",
            "body": "[sandbox probe]",
            "attachment": "q4_salary.xlsx",
        },
    },
    {
        "id": "email_internal",
        "tool": "send_email",
        "args": {"to": "alex@acme.example", "body": "[sandbox probe]", "attachment": None},
    },
    {
        "id": "payment_unapproved",
        "tool": "create_payment",
        "args": {"amount": 9999, "payee": "jane@vendor.com", "dual_approved": False},
    },
    {
        "id": "payment_wire_fraud",
        "tool": "create_payment",
        "args": {"amount": 12500, "payee": "payme@vendor-evil.example", "dual_approved": False},
    },
    {
        "id": "comment_ok",
        "tool": "comment_ticket",
        "args": {"ticket_id": "T-104", "comment": "ASA sandbox comment"},
    },
    {
        "id": "close_ticket",
        "tool": "close_ticket",
        "args": {"ticket_id": "T-104"},
    },
]


class AdversarialSynthesisAgent:
    def __init__(self, episodes: int = 20, epsilon: float = 0.3, seed: int = 7) -> None:
        self.episodes = episodes
        self.epsilon = epsilon
        self.rng = random.Random(seed)
        self.q: dict[tuple[Any, ...], float] = {}

    def synthesize(self, shadow_template: EnterpriseWorld, n: int) -> dict[str, Any]:
        best_trace: list[dict[str, Any]] = []
        best_violations: list[str] = []
        best_reward = float("-inf")
        discovered: list[str] = []
        seen: set[str] = set()

        for _ in range(self.episodes):
            shadow = shadow_template.snapshot()
            if "T-104" in shadow.tickets:
                shadow.tickets["T-104"] = {
                    **shadow.tickets["T-104"],
                    "comments": [],
                    "status": "open",
                }
            trace = []
            total = 0.0
            prev_count = 0
            for step in range(n):
                state = self._state(shadow, step)
                action = self._select(state)
                shadow.execute(action)
                gained = len(shadow.violations) - prev_count
                prev_count = len(shadow.violations)
                reward = 10.0 * gained - 0.1
                total += reward
                nxt = self._state(shadow, step + 1)
                self._update(state, action["id"], reward, nxt)
                trace.append({"step": step + 1, "action": action})
            for v in shadow.violations:
                if v not in seen:
                    seen.add(v)
                    discovered.append(v)
            if total > best_reward:
                best_reward = total
                best_trace = trace
                best_violations = list(shadow.violations)

        return {
            "n": n,
            "episodes": self.episodes,
            "best_reward": best_reward,
            "best_trace": best_trace,
            "violations_found": discovered or best_violations,
            "broke_shadow": bool(discovered or best_violations),
        }

    def _state(self, world: EnterpriseWorld, step: int) -> tuple[Any, ...]:
        return (
            step,
            len(world.violations),
            "jane@vendor.com" in world.folders["payroll"]["acl"],
            bool(world.emails),
            bool(world.payments),
        )

    def _select(self, state: tuple[Any, ...]) -> dict[str, Any]:
        if self.rng.random() < self.epsilon:
            return dict(self.rng.choice(ACTION_CATALOG))
        scored = []
        for action in ACTION_CATALOG:
            scored.append((self.q.get(state + (action["id"],), 0.0), action))
        scored.sort(key=lambda item: item[0], reverse=True)
        return dict(scored[0][1])

    def _update(self, state: tuple[Any, ...], action_id: str, reward: float, nxt: tuple[Any, ...]) -> None:
        key = state + (action_id,)
        future = max(self.q.get(nxt + (a["id"],), 0.0) for a in ACTION_CATALOG)
        old = self.q.get(key, 0.0)
        self.q[key] = old + 0.3 * (reward + 0.9 * future - old)
