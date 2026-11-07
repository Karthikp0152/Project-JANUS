"""B0 adapter over the frozen aswa baseline. Owner: Karthik Ponugoti.

`run_b0` translates a JanusBench scenario into aswa's world format, runs `aswa.pipeline.run_janus`
unchanged and reports the outcome as a RunResult, so B0 is scored by the same harness as B1 and P.

Translation (COORDINATION 11.6):
- audit:   contract [{"id", "entry"}] -> aswa [str]
- folders: drop `label`, which aswa does not have
- tickets: aswa needs `title` and `assignee`; the contract `kind` is dropped
- links, roles, vendors, thresholds: aswa has no such fields, so they are dropped
- violations: aswa reports policy text; it maps to a policy id and tool through B0_TO_RULE

B0_TO_RULE maps B0's four text defenses to DefenseRules so `rules.enforce` can score them:

    B0 kind          tool            conditions                                  effect
    firewall_rule    grant_access    principal.external, folder.label restricted deny (P1)
    dlp_signature    send_email      to.external, attachment sensitive           deny (P2)
    payment_control  create_payment  amount > world threshold                    require dual_approved (P3)
    workflow_rule    close_ticket    ticket.comment_count == 0                   deny (P4)

P3 uses the scenario's threshold as the plan specifies, although aswa itself hard-codes 500. B0 has no
replay gate, so its gate_log holds only a V1 check and every B0 rule counts as unverified (11.6).
B0 ignores the scenario's policies, so it also deploys its templates on heldout and benign worlds.
"""
from __future__ import annotations

import contextlib
import json
import time
from collections.abc import Iterator
from copy import deepcopy
from dataclasses import asdict
from typing import Any

import aswa.llm
from aswa.janus_gate import VIOLATION_TO_DEFENSE
from aswa.pipeline import run_janus
from aswa.rme import RealityMirroringEngine
from aswa.world import EnterpriseWorld

from janus import rules
from janus.types import (
    DEFAULT_HORIZON_N,
    DEFAULT_SEED,
    DefenseRule,
    GateDecision,
    PipelineConfig,
    RunResult,
    Scenario,
    TokenUse,
    Violation,
)

DEFAULT_THRESHOLD = 500
SENSITIVE = ["confidential", "restricted"]

B0_TO_RULE: dict[str, dict[str, Any]] = {
    "firewall_rule": {
        "applies_to": "grant_access",
        "addresses_policy": "P1",
        "conditions": [
            {"field": "principal.external", "op": "is_true", "value": None},
            {"field": "folder.label", "op": "in", "value": ["restricted"]},
        ],
        "effect": "deny",
        "require_field": None,
    },
    "dlp_signature": {
        "applies_to": "send_email",
        "addresses_policy": "P2",
        "conditions": [
            {"field": "to.external", "op": "is_true", "value": None},
            {"field": "attachment.sensitivity", "op": "in", "value": SENSITIVE},
        ],
        "effect": "deny",
        "require_field": None,
    },
    "payment_control": {
        "applies_to": "create_payment",
        "addresses_policy": "P3",
        "conditions": [{"field": "amount", "op": ">", "value": DEFAULT_THRESHOLD}],
        "effect": "require",
        "require_field": "dual_approved",
    },
    "workflow_rule": {
        "applies_to": "close_ticket",
        "addresses_policy": "P4",
        "conditions": [{"field": "ticket.comment_count", "op": "==", "value": 0}],
        "effect": "deny",
        "require_field": None,
    },
}


def _to_aswa_world(world: dict[str, Any]) -> EnterpriseWorld:
    source = deepcopy(world)
    return EnterpriseWorld(
        tickets={
            ticket_id: {
                "title": "",
                "status": ticket.get("status", "open"),
                "assignee": "it-ops",
                "comments": ticket.get("comments", []),
            }
            for ticket_id, ticket in source.get("tickets", {}).items()
        },
        files=source.get("files", {}),
        folders={name: {"acl": folder.get("acl", [])} for name, folder in source.get("folders", {}).items()},
        users=source.get("users", {}),
        emails=source.get("emails", []),
        payments=source.get("payments", []),
        audit=[item["entry"] for item in source.get("audit", [])],
    )


@contextlib.contextmanager
def _optional_llm_off() -> Iterator[None]:
    """B0 is evaluated without its optional OpenAI features, even when a key is configured (M1 Section 5.1)."""
    original = aswa.llm.llm_enabled
    aswa.llm.llm_enabled = lambda: False
    try:
        yield
    finally:
        aswa.llm.llm_enabled = original


def _to_violation(text: str) -> Violation | None:
    defense = VIOLATION_TO_DEFENSE.get(text)
    if defense is None:
        return None
    mapped = B0_TO_RULE[defense["kind"]]
    # aswa reports only the policy text, so the arguments and step of the attempt are not available.
    return Violation(policy_id=mapped["addresses_policy"], action_id=mapped["applies_to"], args={}, step=0)


def _to_rule(defense: dict[str, Any], threshold: Any) -> DefenseRule:
    mapped = deepcopy(B0_TO_RULE[defense["kind"]])
    if mapped["addresses_policy"] == "P3":
        mapped["conditions"][0]["value"] = threshold
    return DefenseRule(
        id=f"b0-{mapped['addresses_policy']}",
        kind=defense["kind"],
        rationale=defense["artifact"],
        **mapped,
    )


def _v1_only(rule: DefenseRule) -> GateDecision:
    ok, reason = rules.validate_schema(rule)
    return GateDecision(rule_id=rule["id"], status="approved", checks={"V1": ok}, reason=reason, rounds=1)


def _probe_values(best_trace: list[dict[str, Any]]) -> list[str]:
    values: set[str] = set()
    for step in best_trace:
        action = step["action"]
        values.add(str(action["tool"]))
        values.update(str(value) for value in action["args"].values() if value is not None)
    return sorted(values)


def run_b0(scenario: Scenario, cfg: PipelineConfig) -> RunResult:
    horizon = cfg.get("horizon_n", DEFAULT_HORIZON_N)
    started = time.perf_counter()
    result = RunResult(
        scenario_id=scenario["id"], system="B0", seed=cfg.get("seed", DEFAULT_SEED), horizon_n=horizon,
        violations_found=[], rules_deployed=[], gate_log=[], exports={"rules": [], "briefing": None},
        artifacts={"twin_dump": "", "llm_prompts": [], "logs": [], "probe_values": []},
        tokens=TokenUse(tokens_in=0, tokens_out=0), cost_usd=0.0, latency_s=0.0, errors=[],
    )
    try:
        with _optional_llm_off():
            run = run_janus(deepcopy(scenario["telemetry"]), n=horizon, world=_to_aswa_world(scenario["world"]))

        threshold = scenario["world"].get("thresholds", {}).get("payment_dual_approval", DEFAULT_THRESHOLD)
        deployed = [_to_rule(defense, threshold) for defense in run["deploy"]["defensive_patches"]]
        found = [_to_violation(text) for text in run["attack"]["violations_found"]]
        result["violations_found"] = [violation for violation in found if violation]
        result["rules_deployed"] = deployed
        result["gate_log"] = [_v1_only(rule) for rule in deployed]
        result["exports"] = {"rules": deployed, "briefing": None}
        # The twin B0 actually built, so the scanner checks the same thing as for P. Never copy `run`
        # itself: it also holds the raw telemetry and the attack trace.
        shadow = RealityMirroringEngine().mirror(_to_aswa_world(scenario["world"]), scenario["telemetry"])["shadow"]
        result["artifacts"]["twin_dump"] = json.dumps(asdict(shadow), sort_keys=True, default=str)
        result["artifacts"]["probe_values"] = _probe_values(run["attack"]["best_trace"])
        result["artifacts"]["logs"] = [
            f"B0: {run['duplicate']['redactions']} redactions",
            f"B0: {len(result['violations_found'])} violations, {len(deployed)} rules deployed",
        ]
    except Exception as exc:  # a world B0 cannot run counts as a B0 failure (12.3)
        result["rules_deployed"] = []
        result["gate_log"] = []
        result["exports"] = {"rules": [], "briefing": None}
        result["errors"].append(f"B0 failed: {type(exc).__name__}")
    result["latency_s"] = time.perf_counter() - started
    return result
