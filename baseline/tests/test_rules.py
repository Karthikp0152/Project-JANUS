"""Tests for rules: never-raise validation, domain rule, action validation, H3 handling."""
from __future__ import annotations

import copy
import math

import pytest

from janus import policies, verifier, world_gen
from janus.rules import EXAMPLE_RULES, enforce, validate_schema


@pytest.fixture(scope="module")
def seen():
    return world_gen.generate("seen", 1)[0]


@pytest.fixture(scope="module")
def heldout():
    return world_gen.generate("heldout", 1)[0]


def _act(tool, action_id="a", **args):
    return {"action_id": action_id, "tool": tool, "args": args}


# ------------------------------------------------- 2: never raise


@pytest.mark.parametrize("bad", [
    None, "rule", 42, [], {},
    {**EXAMPLE_RULES["firewall_rule"], "id": 7},
    {**EXAMPLE_RULES["firewall_rule"], "rationale": None},
    {**EXAMPLE_RULES["firewall_rule"], "addresses_policy": "P9"},
    {**EXAMPLE_RULES["firewall_rule"], "applies_to": ["grant_access"]},
    {**EXAMPLE_RULES["firewall_rule"], "conditions": "not a list"},
    {**EXAMPLE_RULES["firewall_rule"], "conditions": [{"field": ["folder.label"], "op": "==", "value": 1}]},
    {**EXAMPLE_RULES["firewall_rule"], "conditions": [{"field": "folder.label", "op": ["=="], "value": 1}]},
    {**EXAMPLE_RULES["payment_control"], "applies_to": "close_ticket"},      # dual_approved is not an arg of close_ticket
    {**EXAMPLE_RULES["payment_control"], "require_field": ["dual_approved"]},  # unhashable
    {**EXAMPLE_RULES["firewall_rule"], "require_field": "dual_approved"},     # deny rule with a require_field
    {**EXAMPLE_RULES["payment_control"], "conditions": [{"field": "amount", "op": ">", "value": "2000"}]},
    {**EXAMPLE_RULES["payment_control"], "conditions": [{"field": "amount", "op": ">", "value": True}]},
    {**EXAMPLE_RULES["payment_control"], "conditions": [{"field": "amount", "op": "in", "value": 5}]},
])
def test_validate_schema_never_raises_and_rejects(bad):
    ok, reason = validate_schema(bad)
    assert ok is False
    assert isinstance(reason, str)


def test_validate_schema_accepts_every_example():
    for rule in EXAMPLE_RULES.values():
        assert validate_schema(rule) == (True, "ok")


def test_verify_rejects_missing_world_instead_of_raising(seen):
    witness = {"violation": {"policy_id": "P1", "action_id": "grant_access", "args": {}, "step": 0}, "prefix": []}
    decision = verifier.verify(EXAMPLE_RULES["firewall_rule"], witness, {"secrets": []}, [])
    assert decision["status"] == "rejected"
    assert decision["rule_id"] == "ex-firewall-p1"


def test_verify_ignores_non_str_secrets_and_still_catches_a_real_one(seen):
    witness = next(v for v in policies.reachable_violations(seen, 3) if v["policy_id"] == "P1")
    rule = copy.deepcopy(EXAMPLE_RULES["firewall_rule"])
    # None and 123 are skipped by the secrets filter; the string id is a real secret in the rule text.
    scenario = dict(seen, secrets=[None, 123, rule["id"]])
    decision = verifier.verify(rule, {"violation": witness, "prefix": []}, scenario, [])
    assert decision["checks"]["V1"] is True
    assert decision["checks"]["V2"] is False
    assert decision["status"] == "rejected"
    assert "secret" in decision["reason"]
    assert rule["id"] not in decision["reason"]  # the reason omits the id when a secret is involved


def test_verify_returns_rejected_for_unusable_rule_and_witness(seen):
    decision = verifier.verify(None, None, seen, None)
    assert decision["status"] == "rejected"
    assert decision["rule_id"] == "unknown"
    assert set(decision["checks"]) == {f"V{i}" for i in range(1, 7)}


def test_verify_secrets_not_a_list_is_rejected(seen):
    decision = verifier.verify(EXAMPLE_RULES["firewall_rule"], {"violation": {}, "prefix": []},
                               dict(seen, secrets="CANARY-real-1"), [])
    assert decision["status"] == "rejected"


# ------------------------------------------------- 4: domain rule (oracle-aligned)


def test_unknown_address_on_internal_domain_is_internal(seen):
    world = copy.deepcopy(seen["world"])
    world["users"]["ops"] = {"role": "employee", "external": False, "email": "Ops@ACME.example"}
    act = _act("send_email", to="new.hire@acme.example", attachment=None)
    assert policies._external(world, "new.hire@acme.example") is False
    assert _is_external(world, act) is False


def test_unknown_address_on_other_domain_is_external(seen):
    world = copy.deepcopy(seen["world"])
    act = _act("send_email", to="someone@elsewhere.example", attachment=None)
    assert _is_external(world, act) is True


def test_email_match_is_case_insensitive(seen):
    world = copy.deepcopy(seen["world"])
    world["users"]["partner"] = {"role": "contractor", "external": True, "email": "Jane@Vendor.Example"}
    act = _act("send_email", to="jane@vendor.example", attachment=None)
    assert _is_external(world, act) is True


def _is_external(world, action):
    from janus.rules import FIELDS
    return FIELDS["to.external"](action, world)


def test_rule_and_oracle_agree_on_every_scenario_address(seen):
    for split in ("seen", "heldout", "benign"):
        for sc in world_gen.generate(split, 2):
            addresses = {u["email"] for u in sc["world"]["users"].values()} | {"x@acme.example", "y@other.example"}
            for address in addresses:
                act = _act("send_email", to=address, attachment=None)
                assert _is_external(sc["world"], act) == policies._external(sc["world"], address)


# ------------------------------------------------- 5: enforce validates the action


@pytest.mark.parametrize("action", [
    _act("made_up_tool", x=1),                                   # unknown tool
    _act("create_payment", amount=math.nan, payee="x", dual_approved=True),
    _act("create_payment", amount=math.inf, payee="x", dual_approved=True),
    _act("create_payment", amount=True, payee="x", dual_approved=True),  # bool is not an amount
    _act("create_payment", amount=-5, payee="x", dual_approved=True),    # negative payment
    _act("create_payment", amount=900, payee="x"),                       # missing arg
])
def test_enforce_denies_invalid_actions(seen, action):
    assert enforce([], action, seen["world"]) == "deny"


def test_enforce_skips_malformed_rule_for_another_tool(seen):
    broken = {"id": "broken", "applies_to": "close_ticket"}
    act = _act("delete_audit", entry_id="x")
    assert enforce([broken], act, seen["world"]) == "allow"


def test_enforce_fails_closed_for_malformed_rule_on_same_tool(seen):
    broken = dict(EXAMPLE_RULES["workflow_rule"], kind="made_up_kind")
    act = _act("close_ticket", ticket_id=next(iter(seen["world"]["tickets"])))
    assert enforce([broken], act, seen["world"]) == "deny"


def test_enforce_does_not_mutate_world_or_rules(seen):
    world = copy.deepcopy(seen["world"])
    rules = [copy.deepcopy(EXAMPLE_RULES["payment_control"])]
    enforce(rules, _act("create_payment", amount=5000, payee="x", dual_approved=False), world)
    assert world == seen["world"]
    assert rules == [EXAMPLE_RULES["payment_control"]]


# ------------------------------------------------- H3: null and unknown ticket ids


def _h3_action(ticket, world):
    return _act("update_vendor_bank", "h3", vendor="vendor-001", bank="SYNTHETIC-BANK-A", verification_ticket=ticket)


def test_h3_null_and_unknown_ticket_are_denied_by_is_false_rule(heldout):
    world = heldout["world"]
    rule = EXAMPLE_RULES["vendor_rule"]
    assert enforce([rule], _h3_action(None, world), world) == "deny"
    assert enforce([rule], _h3_action("T-NOT-IN-WORLD", world), world) == "deny"


def test_h3_require_rule_blocks_unknown_ticket_via_resolved_value(heldout):
    world = heldout["world"]
    rule = copy.deepcopy(EXAMPLE_RULES["vendor_rule"])
    rule.update(id="h3-require", effect="require", require_field="verification_ticket", conditions=[])
    known = next(iter(world["tickets"]))
    assert enforce([rule], _h3_action(None, world), world) == "deny"
    assert enforce([rule], _h3_action("T-NOT-IN-WORLD", world), world) == "deny"
    assert enforce([rule], _h3_action(known, world), world) == "allow"


def test_h3_variants_include_an_unknown_ticket_id(heldout):
    witness = next(v for v in policies.reachable_violations(heldout, 3) if v["policy_id"] == "H3")
    variants = verifier.make_variants(witness, heldout["world"])
    assert any(v["args"]["verification_ticket"] not in heldout["world"]["tickets"]
               and v["args"]["verification_ticket"] is not None for v in variants)


def test_h3_narrow_rule_fails_v4(heldout):
    witness = next(v for v in policies.reachable_violations(heldout, 3) if v["policy_id"] == "H3")
    narrow = copy.deepcopy(EXAMPLE_RULES["vendor_rule"])
    narrow.update(id="h3-narrow", conditions=[{"field": "bank", "op": "==", "value": witness["args"]["bank"]}])
    decision = verifier.verify(narrow, {"violation": witness, "prefix": []}, heldout, [])
    assert decision["checks"]["V4"] is False
    assert decision["status"] == "rejected"


def test_p3_threshold_is_stated_in_v3_reason(seen):
    witness = next(v for v in policies.reachable_violations(seen, 3) if v["policy_id"] == "P3")
    narrow = copy.deepcopy(EXAMPLE_RULES["payment_control"])
    narrow.update(id="p3-off", conditions=[{"field": "amount", "op": "==", "value": -1}])
    decision = verifier.verify(narrow, {"violation": witness, "prefix": []}, seen, [])
    threshold = seen["world"]["thresholds"]["payment_dual_approval"]
    assert decision["checks"]["V3"] is False
    assert f"world dual-approval threshold is {threshold}" in decision["reason"]


# ------------------------------------------------- unknown ids: no over-blocking (oracle agrees)


@pytest.mark.parametrize("tool,args,rule_key,policy", [
    ("grant_access", {"folder": "no-such-folder", "principal": "ghost"}, "firewall_rule", "P1"),
    ("grant_access", {"folder": "no-such-folder", "principal": "ghost@elsewhere.example"}, "firewall_rule", "P1"),
    ("send_email", {"to": "x@elsewhere.example", "attachment": "no-such-file"}, "dlp_signature", "P2"),
    ("close_ticket", {"ticket_id": "T-NOT-IN-WORLD"}, "workflow_rule", "P4"),
    ("share_link", {"file": "no-such-file", "public": True}, "sharing_rule", "H1"),
])
def test_unknown_ids_are_allowed_like_the_oracle(seen, tool, args, rule_key, policy):
    action = _act(tool, **args)
    assert policy not in policies.check(seen["world"], action)
    assert enforce([EXAMPLE_RULES[rule_key]], action, seen["world"]) == "allow"


def test_ordering_op_on_unresolved_value_does_not_deny(seen):
    rule = {**EXAMPLE_RULES["workflow_rule"], "applies_to": "close_ticket",
            "conditions": [{"field": "ticket.comment_count", "op": ">", "value": 0}]}
    assert enforce([rule], _act("close_ticket", ticket_id="T-NOT-IN-WORLD"), seen["world"]) == "allow"
