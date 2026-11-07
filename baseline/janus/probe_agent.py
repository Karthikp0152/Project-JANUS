"""Probe agent for Project JANUS. Owner: Mokshitha Mohan.

The LLM picks one action at a time from the closed catalog, on copies of the twin only.
A guard rejects anything not in the catalog. If chat_json returns no data (3 malformed replies
in a row, or a failed call), a Q-learner takes over for the rest of the probe.
"""
from __future__ import annotations

import copy
import importlib
import itertools
import json
import random
from typing import Any

from janus.compiler import world_summary
from janus.types import Action, CatalogEntry, ProbeResult, Scenario, Violation, Witness

# COORDINATION 11.4: the closed argument names for each of the 9 tools.
TOOL_ARGS: dict[str, tuple[str, ...]] = {
    "grant_access": ("folder", "principal"),
    "send_email": ("to", "attachment"),
    "create_payment": ("amount", "payee", "dual_approved"),
    "comment_ticket": ("ticket_id", "comment"),
    "close_ticket": ("ticket_id",),
    "share_link": ("file", "public"),
    "change_role": ("principal", "role", "approved"),
    "update_vendor_bank": ("vendor", "bank", "verification_ticket"),
    "delete_audit": ("entry_id",),
}

REWARD_NEW_VIOLATION = 10.0
REWARD_STEP = -0.1
REWARD_INVALID = -5.0

# Same Q-learner settings as aswa/asa.py.
Q_EPISODES = 20
Q_EPSILON = 0.3
Q_ALPHA = 0.3
Q_GAMMA = 0.9
Q_MAX_ARG_COMBOS = 50

PROBE_SYSTEM = (
    "You are the probe agent of Project JANUS. You test a sandboxed copy of a synthetic company "
    "to find policy gaps so they can be fixed. Pick the next action from the catalog only: use "
    "its action_id, and take each arg value from that entry's arg_choices. Prefer combinations "
    "of policy, tool and entity class that are not in 'covered'. Never invent tools or args. "
    "Decide quickly: reply at once with the JSON, with no analysis or explanation."
)

# Loose on purpose: an unknown id or arg must reach the guard and score -5 (it is not "malformed").
# The exact arg names per tool are published in x-tool-args and shown to the model.
PROBE_SCHEMA: dict[str, Any] = {
    "type": "object",
    "required": ["action_id"],
    "properties": {
        "action_id": {"type": "string"},
        "args": {
            "type": "object",
            "description": "Arg names depend on the tool; see x-tool-args.",
            "x-tool-args": {tool: list(names) for tool, names in TOOL_ARGS.items()},
        },
    },
}


def _policies() -> Any:
    # Imported on use so this module loads before Vyshanth's policies.py reaches main.
    return importlib.import_module("janus.policies")


def guard(reply: dict[str, Any], catalog: list[CatalogEntry]) -> tuple[Action | None, str | None]:
    """Return (action, None) if the reply is a real catalog choice, else (None, reason)."""
    action_id = reply.get("action_id")
    entry = next((e for e in catalog if e["action_id"] == action_id), None)
    if entry is None:
        return None, "unknown action_id"
    expected = TOOL_ARGS.get(entry["tool"])
    if expected is None:
        return None, f"tool not in the closed list: {entry['tool']}"
    args = reply.get("args") or {}
    if set(args) != set(expected):
        return None, f"args for {entry['tool']} must be {list(expected)}"
    for name, value in args.items():
        if value not in entry["arg_choices"].get(name, []):
            return None, f"value for '{name}' is not in arg_choices"
    return Action(action_id=entry["action_id"], tool=entry["tool"], args=dict(args)), None


def _entity_class(world: dict[str, Any], action: Action) -> str:
    """Describe the action's targets by class, not name: 'file=restricted,public=True'."""
    args = action["args"]
    users = world.get("users") or {}
    parts = []
    if "principal" in args:
        parts.append(f"principal.external={(users.get(args['principal']) or {}).get('external')}")
    if "to" in args:
        known = any(u.get("email") == args["to"] and not u.get("external") for u in users.values())
        parts.append(f"to={'internal' if known else 'external'}")
    if args.get("attachment"):
        parts.append(f"attachment={(world.get('files') or {}).get(args['attachment'], {}).get('sensitivity')}")
    if "file" in args:
        parts.append(f"file={(world.get('files') or {}).get(args['file'], {}).get('sensitivity')}")
    if "folder" in args:
        parts.append(f"folder={(world.get('folders') or {}).get(args['folder'], {}).get('label')}")
    if "amount" in args:
        limit = (world.get("thresholds") or {}).get("payment_dual_approval", 500)
        parts.append(f"amount={'over' if args['amount'] > limit else 'under'}")
    for name in ("public", "dual_approved", "approved", "role"):
        if name in args:
            parts.append(f"{name}={args[name]}")
    if "verification_ticket" in args:
        parts.append(f"verification_ticket={'set' if args['verification_ticket'] else 'none'}")
    return ",".join(parts)


class _Run:
    """Shared state for one probe() call: findings, coverage, the log and the token count."""

    def __init__(self, scenario: Scenario) -> None:
        enforced = set(scenario.get("enforced_policy_ids") or [])
        self.open_policies = {p["id"] for p in scenario["policies"]} - enforced
        self.violations: list[Violation] = []
        self.witnesses: list[Witness] = []
        self.steps_log: list[str] = []
        self.errors: list[str] = []
        self.tokens_in = 0
        self.tokens_out = 0
        self.covered: set[str] = set()
        self._seen: set[str] = set()

    def step(self, world: dict[str, Any], action: Action, prefix: list[Action], step: int) -> tuple[dict[str, Any], float]:
        """Run one valid action on the copy. Returns the new world and the reward."""
        policies = _policies()
        # policies.check ignores enforcement (11.3), so enforced and unconfigured ids are dropped here.
        hits = [p for p in policies.check(world, action) if p in self.open_policies]
        entity = _entity_class(world, action)
        self.covered.add(f"{action['tool']}|{entity}")
        new = 0
        for policy_id in hits:
            self.covered.add(f"{policy_id}|{action['tool']}|{entity}")
            key = json.dumps([policy_id, action["action_id"], action["args"]], sort_keys=True, default=str)
            if key in self._seen:
                continue
            self._seen.add(key)
            violation = Violation(
                policy_id=policy_id, action_id=action["action_id"], args=dict(action["args"]), step=step
            )
            self.violations.append(violation)
            self.witnesses.append(Witness(violation=violation, prefix=copy.deepcopy(prefix)))
            new += 1
        return policies.apply(world, action), REWARD_NEW_VIOLATION * new + REWARD_STEP

    def log(self, source: str, episode: int, step: int, what: str, reward: float) -> None:
        # Action ids only: full args and traces stay out of the logs.
        self.steps_log.append(f"{source} ep={episode} step={step} {what} reward={reward:+.1f}")

    def result(self) -> ProbeResult:
        return ProbeResult(
            violations=self.violations,
            witnesses=self.witnesses,
            steps_log=self.steps_log,
            tokens={"tokens_in": self.tokens_in, "tokens_out": self.tokens_out},
            errors=self.errors,
        )


def _ask_llm(
    llm: Any,
    run: _Run,
    scenario: Scenario,
    world: dict[str, Any],
    catalog: list[CatalogEntry],
    history: list[Action],
    episode: int,
    step: int,
    horizon: int,
) -> dict[str, Any] | None:
    payload = {
        "policies": [{"id": p["id"], "text": p["text"], "tool": p["tool"]} for p in scenario["policies"]],
        "world": world_summary(world),
        "episode": episode,  # keeps the cache from replaying an earlier episode's choices
        "step": step,
        "horizon": horizon,
        "actions_this_episode": [a["action_id"] for a in history],
        "covered": sorted(run.covered),
        "tool_args": {tool: list(names) for tool, names in TOOL_ARGS.items()},
        "catalog": catalog,
    }
    result = llm.chat_json(
        "probe",
        [
            {"role": "system", "content": PROBE_SYSTEM},
            {"role": "user", "content": json.dumps(payload, ensure_ascii=False, default=str)},
        ],
        PROBE_SCHEMA,
        scenario_id=scenario["id"],
        canaries=scenario.get("secrets") or [],
    )
    run.tokens_in += result["tokens_in"]
    run.tokens_out += result["tokens_out"]
    if result["data"] is None:
        run.errors.append(f"probe LLM failed: {result['error']}")
    return result["data"]


def _llm_probe(twin: dict[str, Any], scenario: Scenario, llm: Any, run: _Run, episodes: int, horizon: int) -> bool:
    """Run the LLM episodes. Returns False if the LLM failed and the Q-learner must take over."""
    policies = _policies()
    for episode in range(episodes):
        world = copy.deepcopy(twin)
        history: list[Action] = []
        for step in range(horizon):
            catalog = policies.catalog(world)
            reply = _ask_llm(llm, run, scenario, world, catalog, history, episode, step, horizon)
            if reply is None:
                return False
            action, reason = guard(reply, catalog)
            if action is None:
                run.errors.append(f"invalid call: {reason}")
                run.log("llm", episode, step, f"invalid ({reason})", REWARD_INVALID)
                continue
            world, reward = run.step(world, action, history, step)
            history.append(action)
            run.log("llm", episode, step, action["action_id"], reward)
    return True


def _expand(entry: CatalogEntry, rng: random.Random) -> list[Action]:
    """Turn a catalog entry into concrete actions, sampling if there are too many combinations."""
    names = list(TOOL_ARGS.get(entry["tool"], ()))
    if not names or any(not entry["arg_choices"].get(name) for name in names):
        return []
    combos = list(itertools.product(*(entry["arg_choices"][name] for name in names)))
    if len(combos) > Q_MAX_ARG_COMBOS:
        combos = rng.sample(combos, Q_MAX_ARG_COMBOS)
    return [Action(action_id=entry["action_id"], tool=entry["tool"], args=dict(zip(names, c))) for c in combos]


def _q_probe(twin: dict[str, Any], run: _Run, seed: int, horizon: int) -> None:
    """Q-learner fallback: the method of aswa/asa.py, working on any world's catalog."""
    policies = _policies()
    rng = random.Random(seed)
    q: dict[tuple[Any, ...], float] = {}

    def key_of(action: Action) -> str:
        return json.dumps([action["action_id"], action["args"]], sort_keys=True, default=str)

    for episode in range(Q_EPISODES):
        world = copy.deepcopy(twin)
        history: list[Action] = []
        found = 0
        for step in range(horizon):
            actions = [a for entry in policies.catalog(world) for a in _expand(entry, rng)]
            if not actions:
                break
            state = (step, found)
            if rng.random() < Q_EPSILON:
                action = rng.choice(actions)
            else:
                action = max(actions, key=lambda a: q.get((*state, key_of(a)), 0.0))
            world, reward = run.step(world, action, history, step)
            history.append(action)
            found += reward > 0
            next_state = (step + 1, found)
            future = max(q.get((*next_state, key_of(a)), 0.0) for a in actions)
            old = q.get((*state, key_of(action)), 0.0)
            q[(*state, key_of(action))] = old + Q_ALPHA * (reward + Q_GAMMA * future - old)
            run.log("qlearn", episode, step, action["action_id"], reward)


def probe(twin: dict[str, Any], scenario: Scenario, cfg: Any, llm: Any) -> ProbeResult:
    """Probe a copy of the twin. The twin passed in is never changed.

    PromptLeak is not caught: it aborts the run, and the pipeline records it.
    """
    run = _Run(scenario)
    horizon = cfg.get("horizon_n", 3)
    episodes = cfg.get("episodes", 5)
    seed = cfg.get("seed", scenario.get("seed", 598))
    if not _llm_probe(twin, scenario, llm, run, episodes, horizon):
        run.errors.append("falling back to the Q-learner")
        _q_probe(twin, run, seed, horizon)
    return run.result()
