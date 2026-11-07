"""Tests for verifier.verify (V1-V6), make_variants, and gate.export / evaluate_only."""
from __future__ import annotations

import copy

import pytest

from janus import gate, policies, verifier, world_gen
from janus.gate import GateViolation
from janus.rules import EXAMPLE_RULES, enforce
from janus.types import GateDecision


@pytest.fixture(scope="module")
def scenario():
    return world_gen.generate("seen", 1)[0]


def _witness(scenario, policy_id):
    violation = next(v for v in policies.reachable_violations(scenario, 3) if v["policy_id"] == policy_id)
    return {"violation": violation, "prefix": []}


def _rule(kind, **overrides):
    rule = copy.deepcopy(EXAMPLE_RULES[kind])
    rule.update(overrides)
    return rule


# ---------------------------------------------------------------- verify


def test_good_rule_is_approved_with_all_six_checks(scenario):
    decision = verifier.verify(EXAMPLE_RULES["firewall_rule"], _witness(scenario, "P1"), scenario, [])
    assert decision["status"] == "approved"
    assert decision["checks"] == {f"V{i}": True for i in range(1, 7)}
    assert decision["reason"] == ""
    assert decision["rounds"] == 1


@pytest.mark.parametrize("kind,policy", [
    ("firewall_rule", "P1"), ("dlp_signature", "P2"), ("payment_control", "P3"), ("workflow_rule", "P4"),
])
def test_seen_example_rules_are_approved(scenario, kind, policy):
    decision = verifier.verify(EXAMPLE_RULES[kind], _witness(scenario, policy), scenario, [])
    assert decision["status"] == "approved", decision["reason"]


def test_over_broad_rule_fails_v5(scenario):
    rule = _rule("firewall_rule", conditions=[])  # denies every grant_access, including benign ones
    decision = verifier.verify(rule, _witness(scenario, "P1"), scenario, [])
    assert decision["status"] == "rejected"
    assert decision["checks"]["V5"] is False
    assert decision["reason"].startswith("V5 failed: blocks benign action ")


def test_too_narrow_rule_fails_v4(scenario):
    witness = _witness(scenario, "P3")
    amount = witness["violation"]["args"]["amount"]
    rule = _rule("payment_control", conditions=[{"field": "amount", "op": "==", "value": amount}],
                 effect="deny", require_field=None)  # blocks only this exact amount
    decision = verifier.verify(rule, witness, scenario, [])
    assert decision["checks"]["V3"] is True
    assert decision["checks"]["V4"] is False
    assert decision["reason"].startswith("V4 failed: variant ")


def test_duplicate_of_installed_rule_fails_v6(scenario):
    installed = [EXAMPLE_RULES["firewall_rule"]]
    rule = _rule("firewall_rule", id="copy-of-p1")
    decision = verifier.verify(rule, _witness(scenario, "P1"), scenario, installed)
    assert decision["checks"]["V6"] is False
    assert decision["reason"] == "V6 failed: duplicates installed rule ex-firewall-p1"


def test_trace_field_fails_v2(scenario):
    rule = dict(EXAMPLE_RULES["firewall_rule"], trace=["step 1"])
    decision = verifier.verify(rule, _witness(scenario, "P1"), scenario, [])
    assert decision["checks"]["V2"] is False
    assert decision["status"] == "rejected"


def test_secret_in_rule_fails_v2_and_reason_does_not_echo_it(scenario):
    secret = scenario["secrets"][0]
    rule = _rule("firewall_rule", rationale=f"leak {secret}")
    decision = verifier.verify(rule, _witness(scenario, "P1"), scenario, [])
    assert decision["checks"]["V2"] is False
    assert secret not in decision["reason"]


def test_malformed_rule_fails_v1(scenario):
    rule = dict(EXAMPLE_RULES["firewall_rule"], kind="made_up_kind")
    decision = verifier.verify(rule, _witness(scenario, "P1"), scenario, [])
    assert decision["checks"]["V1"] is False
    assert decision["status"] == "rejected"
    assert decision["reason"].startswith("V1 failed")


def test_reason_names_action_and_rule_ids_only(scenario):
    rule = _rule("firewall_rule", conditions=[])
    decision = verifier.verify(rule, _witness(scenario, "P1"), scenario, [])
    for value in (scenario["secrets"] + [str(v) for v in scenario["world"]["files"].values()]):
        assert value not in decision["reason"]


def test_verify_does_not_mutate_inputs(scenario):
    before = copy.deepcopy(scenario)
    rule_before = copy.deepcopy(EXAMPLE_RULES["firewall_rule"])
    verifier.verify(EXAMPLE_RULES["firewall_rule"], _witness(scenario, "P1"), scenario, [])
    assert scenario == before
    assert EXAMPLE_RULES["firewall_rule"] == rule_before


def test_make_variants_are_violations_of_the_same_policy(scenario):
    violation = _witness(scenario, "P2")["violation"]
    variants = verifier.make_variants(violation, scenario["world"])
    assert variants, "expected at least one variant from the world's entities"
    for action in variants:
        assert "P2" in policies.check(scenario["world"], action)
    assert len(variants) <= verifier.MAX_VARIANTS


# ---------------------------------------------------------------- gate


def _approved(rule_id):
    return GateDecision(rule_id=rule_id, status="approved", checks={}, reason="", rounds=1)


def test_export_allows_briefing_none_and_empty_rules():
    assert gate.export([], [], None) == {"rules": [], "briefing": None}


def test_export_is_repeatable_with_the_same_rules():
    rule = EXAMPLE_RULES["firewall_rule"]
    decisions = [_approved(rule["id"])]
    first = gate.export(decisions, [rule], None)
    second = gate.export(decisions, [rule], "written briefing")
    assert first["rules"] == second["rules"] == [rule]
    assert second["briefing"] == "written briefing"


def test_export_ignores_rejected_and_escalated_decisions():
    rejected = GateDecision(rule_id="unresolved-P1-grant_access", status="rejected",
                            checks={}, reason="", rounds=3)
    escalated = GateDecision(rule_id="other", status="escalated", checks={}, reason="", rounds=3)
    out = gate.export([rejected, escalated], [], "risks: P1 unresolved")
    assert out == {"rules": [], "briefing": "risks: P1 unresolved"}


def test_export_rejects_rule_without_approved_decision():
    rule = EXAMPLE_RULES["firewall_rule"]
    with pytest.raises(GateViolation):
        gate.export([], [rule], None)


def test_export_rejects_non_schema_rule():
    rule = dict(EXAMPLE_RULES["firewall_rule"], action_id="grant_access")
    with pytest.raises(GateViolation):
        gate.export([_approved(rule["id"])], [rule], None)


def test_export_rejects_trace_in_rule():
    rule = dict(EXAMPLE_RULES["firewall_rule"])
    rule["conditions"] = [{"field": "folder.label", "op": "==", "value": "x", "trace": ["step"]}]
    with pytest.raises(GateViolation):
        gate.export([_approved(rule["id"])], [rule], None)


def test_export_rejects_canary_in_briefing():
    with pytest.raises(GateViolation):
        gate.export([], [], "the password is CANARY-abc123", canaries=["CANARY-abc123"])


def test_export_rejects_non_string_briefing():
    with pytest.raises(GateViolation):
        gate.export([], [], {"text": "x"})  # type: ignore[arg-type]


def test_export_clean_passes_with_canaries_present():
    rule = EXAMPLE_RULES["firewall_rule"]
    out = gate.export([_approved(rule["id"])], [rule], "clean briefing", canaries=["CANARY-abc123"])
    assert out["rules"] == [rule]


def test_evaluate_only_matches_enforce_and_does_not_mutate(scenario):
    rule = EXAMPLE_RULES["firewall_rule"]
    violation = _witness(scenario, "P1")["violation"]
    action = {"action_id": violation["action_id"], "tool": "grant_access", "args": violation["args"]}
    world = copy.deepcopy(scenario["world"])
    assert gate.evaluate_only([rule], action, world) == enforce([rule], action, world) == "deny"
    assert world == scenario["world"]
