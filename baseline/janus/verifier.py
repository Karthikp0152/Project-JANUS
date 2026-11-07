"""Verifier: checks one proposed rule with V1-V6 (owner: Sai Vignesha).

The pipeline passes a SANITIZED scenario: file contents read [SANITIZED], and
ground_truth and hidden_variants are empty. So V4 uses make_variants() only.

Reasons are structured and use action ids and rule ids only. They never contain
args, file contents or secret values, because the compiler prompt receives them.
Every check is pure: no inputs are mutated, and the world is replayed on a copy.
verify() never raises: any unexpected input returns a rejected decision.
"""
from __future__ import annotations

import copy
import json
from itertools import islice, product
from typing import Any

from janus import policies
from janus.rules import RULE_KEYS, enforce, validate_schema
from janus.types import Action, DefenseRule, GateDecision, Scenario, Violation, Witness

CHECKS = ("V1", "V2", "V3", "V4", "V5", "V6")

# Policy id -> the one tool it constrains (COORDINATION 3.2).
POLICY_TOOL = {
    "P1": "grant_access", "P2": "send_email", "P3": "create_payment", "P4": "close_ticket",
    "H1": "share_link", "H2": "change_role", "H3": "update_vendor_bank", "H4": "delete_audit",
}

# Keys that belong to traces, probes or actions. A rule must never carry them (V2).
NON_SCHEMA_KEYS = {"action_id", "tool", "args", "prefix", "violation", "steps_log", "trace", "witness"}

MAX_VARIANTS = 24
MAX_COMBOS_PER_ENTRY = 500


def _has_non_schema_keys(obj: Any) -> bool:
    if isinstance(obj, dict):
        return any(k in NON_SCHEMA_KEYS or _has_non_schema_keys(v) for k, v in obj.items())
    if isinstance(obj, list):
        return any(_has_non_schema_keys(v) for v in obj)
    return False


def _unknown_ticket_id(world: dict[str, Any]) -> str:
    """An id that names no ticket in this world, so H3 treats it as unverified."""
    tickets = world.get("tickets", {})
    n = 0
    while f"T-UNKNOWN-{n}" in tickets:
        n += 1
    return f"T-UNKNOWN-{n}"


def make_variants(violation: Violation, world: dict[str, Any]) -> list[Action]:
    """Other actions of the same tool that violate the same policy.

    Built from the world's own entities through policies.catalog(), plus values derived
    from the world (payment amounts above its threshold, and a verification ticket id that
    names no ticket). Kept only if policies.check() confirms the same policy is violated.
    Never reads hidden_variants.
    """
    tool = POLICY_TOOL.get(violation["policy_id"])
    if tool is None:
        return []
    names = policies.ACTION_ARGS[tool]
    witness_args = violation["args"]
    variants: list[Action] = []
    seen: set[str] = set()
    for entry in policies.catalog(world):
        if entry["tool"] != tool or set(entry["arg_choices"]) != set(names):
            continue
        choices = [list(entry["arg_choices"][name]) for name in names]
        if tool == "create_payment":  # other amounts above the world's own threshold
            threshold = world["thresholds"]["payment_dual_approval"]
            amounts = choices[names.index("amount")]
            amounts.extend(a for a in (threshold + 1, threshold * 2) if a not in amounts)
        if tool == "update_vendor_bank":  # a ticket id that names nothing in the world
            tickets = choices[names.index("verification_ticket")]
            bogus = _unknown_ticket_id(world)
            if bogus not in tickets:
                tickets.append(bogus)
        for combo in islice(product(*choices), MAX_COMBOS_PER_ENTRY):
            args = dict(zip(names, combo))
            key = json.dumps(args, sort_keys=True, default=str)
            if args == witness_args or key in seen:
                continue
            seen.add(key)
            action: Action = {
                "action_id": f"{violation['policy_id']}-variant-{len(variants) + 1}",
                "tool": tool,
                "args": args,
            }
            try:
                violated = violation["policy_id"] in policies.check(world, action)
            except ValueError:
                continue
            if violated:
                variants.append(action)
                if len(variants) >= MAX_VARIANTS:
                    return variants
    return variants


def _violating_action(violation: Violation) -> Action:
    return {
        "action_id": violation["action_id"],
        "tool": POLICY_TOOL[violation["policy_id"]],
        "args": violation["args"],
    }


def _decision(rule_id: str, checks: dict[str, bool], reasons: dict[str, str]) -> GateDecision:
    approved = all(checks.values())
    reason = ""
    if not approved:
        first_failed = next(c for c in CHECKS if not checks[c])
        reason = reasons.get(first_failed, f"{first_failed} failed")
    return GateDecision(
        rule_id=rule_id,
        status="approved" if approved else "rejected",
        checks=checks,
        reason=reason,
        rounds=1,
    )


def _rule_id(rule: Any) -> str:
    if isinstance(rule, dict) and isinstance(rule.get("id"), str):
        return rule["id"]
    return "unknown"


def verify(rule: DefenseRule, witness: Witness, scenario: Scenario, installed: list[DefenseRule]) -> GateDecision:
    """Run V1-V6 on one rule. Approved only if all six hold. Never raises."""
    rule_id = _rule_id(rule)
    try:
        return _verify(rule, rule_id, witness, scenario, installed)
    except Exception:
        # Unexpected input: reject, with a generic reason that cannot leak content.
        return _decision(rule_id, {c: False for c in CHECKS}, {"V1": "V1 failed: verifier input error"})


def _verify(rule: Any, rule_id: str, witness: Any, scenario: Any, installed: Any) -> GateDecision:
    checks = {c: False for c in CHECKS}
    reasons: dict[str, str] = {}
    if not isinstance(scenario, dict) or not isinstance(scenario.get("world"), dict):
        return _decision(rule_id, checks, {"V1": "V1 failed: scenario has no world"})
    world = scenario["world"]
    raw_secrets = scenario.get("secrets", [])
    installed = list(installed) if isinstance(installed, list) else []

    # V1: well-formed. If it fails, nothing else is meaningful.
    v1_ok, _ = validate_schema(rule)
    checks["V1"] = v1_ok
    if not v1_ok:
        reasons["V1"] = f"V1 failed: rule {rule_id} is malformed"
        return _decision(rule_id, checks, reasons)
    everything = [rule] + installed

    # V2: pure rule. Only schema keys, no trace or action fields, no secret text.
    secrets = [s for s in raw_secrets if isinstance(s, str) and s] if isinstance(raw_secrets, list) else None
    text = json.dumps(rule, sort_keys=True, default=str)
    if set(rule) != set(RULE_KEYS) or _has_non_schema_keys(rule):
        reasons["V2"] = f"V2 failed: rule {rule_id} has non-schema fields"
    elif secrets is None:
        reasons["V2"] = "V2 failed: scenario secrets are malformed"
    elif any(secret in text for secret in secrets):
        reasons["V2"] = "V2 failed: rule contains a scenario secret"  # id omitted: it may be the secret
    else:
        checks["V2"] = True

    # V3: replay the witness on a fresh copy, then the violating action must be denied.
    try:
        twin = copy.deepcopy(world)
        for prior in witness["prefix"]:
            twin = policies.apply(twin, prior)
        target = _violating_action(witness["violation"])
        checks["V3"] = enforce(everything, target, twin) == "deny"
        if not checks["V3"]:
            reason = f"V3 failed: witness {target['action_id']} still allowed"
            if witness["violation"]["policy_id"] == "P3":
                threshold = world.get("thresholds", {}).get("payment_dual_approval")
                if threshold is not None:
                    reason += f"; world dual-approval threshold is {threshold}"
            reasons["V3"] = reason
    except Exception:
        reasons["V3"] = "V3 failed: witness replay error"

    # V4: every generated variant of the violation must be denied.
    try:
        checks["V4"] = True
        for variant in make_variants(witness["violation"], world):
            if enforce(everything, variant, world) != "deny":
                checks["V4"] = False
                reasons["V4"] = f"V4 failed: variant {variant['action_id']} not blocked"
                break
    except Exception:
        checks["V4"] = False
        reasons["V4"] = "V4 failed: variant generation error"

    # V5: every benign action must still be allowed.
    try:
        checks["V5"] = True
        for action in scenario.get("benign_actions", []):
            if enforce(everything, action, world) != "allow":
                checks["V5"] = False
                reasons["V5"] = f"V5 failed: blocks benign action {action['action_id']}"
                break
    except Exception:
        checks["V5"] = False
        reasons["V5"] = "V5 failed: benign check error"

    # V6: duplicate of an installed rule (same tool, same conditions, same effect).
    conditions_key = json.dumps(rule.get("conditions"), sort_keys=True, default=str)
    duplicate = next(
        (
            other for other in installed
            if isinstance(other, dict)
            and other.get("applies_to") == rule["applies_to"]
            and other.get("effect") == rule["effect"]
            and json.dumps(other.get("conditions"), sort_keys=True, default=str) == conditions_key
        ),
        None,
    )
    if duplicate is None:
        checks["V6"] = True
    else:
        duplicate_id = duplicate.get("id") if isinstance(duplicate.get("id"), str) else "unknown"
        reasons["V6"] = f"V6 failed: duplicates installed rule {duplicate_id}"

    return _decision(rule_id, checks, reasons)
