"""Contract tests derived from COORDINATION 11-15, independent of the oracle."""
from copy import deepcopy
from itertools import product
import json

import pytest

from janus import policies
from janus.types import ALL_TOOLS


ARG_NAMES = {
    "grant_access": {"folder", "principal"},
    "send_email": {"to", "attachment"},
    "create_payment": {"amount", "payee", "dual_approved"},
    "comment_ticket": {"ticket_id", "comment"},
    "close_ticket": {"ticket_id"},
    "share_link": {"file", "public"},
    "change_role": {"principal", "role", "approved"},
    "update_vendor_bank": {"vendor", "bank", "verification_ticket"},
    "delete_audit": {"entry_id"},
}


def action(tool, **args):
    return {"action_id": tool, "tool": tool, "args": args}


@pytest.fixture
def world():
    return {
        "users": {
            "inside": {"role": "contractor", "external": False, "email": "inside@acme.example"},
            "outside": {"role": "employee", "external": True, "email": "outside@vendor.example"},
        },
        "folders": {
            "payroll": {"acl": [], "label": "internal"},
            "research": {"acl": [], "label": "restricted"},
        },
        "files": {
            level: {"folder": "research", "sensitivity": level, "contents": "synthetic"}
            for level in ("public", "internal", "confidential", "restricted")
        },
        "tickets": {
            "T-empty": {"status": "open", "comments": [], "kind": "service"},
            "T-empty-2": {"status": "open", "comments": [], "kind": "verification"},
            "T-commented": {"status": "open", "comments": ["Reviewed"], "kind": "verification"},
        },
        "payments": [], "emails": [], "links": [],
        "roles": {"inside": "contractor", "outside": "employee"},
        "vendors": {"V-test": {"bank": "BANK-OLD", "verified_by_ticket": None}},
        "audit": [{"id": "A-test", "entry": "Synthetic event"}],
        "thresholds": {"payment_dual_approval": 700},
    }


@pytest.mark.parametrize("principal,folder,expected", [
    ("outside", "research", ["P1"]),
    ("inside", "research", []),
    ("outside", "payroll", []),
    ("inside", "payroll", []),
])
def test_p1_uses_external_flag_and_label_only(world, principal, folder, expected):
    assert policies.check(world, action("grant_access", principal=principal, folder=folder)) == expected


@pytest.mark.parametrize("sensitivity", ["public", "internal", "confidential", "restricted"])
@pytest.mark.parametrize("external", [False, True])
def test_p2_resolves_recipient_by_email(world, sensitivity, external):
    email = world["users"]["outside" if external else "inside"]["email"]
    expected = ["P2"] if external and sensitivity in {"confidential", "restricted"} else []
    assert policies.check(world, action("send_email", to=email, attachment=sensitivity)) == expected


def test_email_null_attachment_and_unknown_email_domain(world):
    assert policies.check(world, action("send_email", to="unknown@vendor.test", attachment=None)) == []
    assert policies.check(world, action("send_email", to="unknown@vendor.test", attachment="restricted")) == ["P2"]
    assert policies.check(world, action("send_email", to="unknown@acme.example", attachment="restricted")) == []


@pytest.mark.parametrize("amount,dual,expected", [
    (699, False, []), (700, False, []), (701, False, ["P3"]), (701, True, []),
])
def test_p3_threshold_and_approval_boundary(world, amount, dual, expected):
    assert policies.check(world, action("create_payment", amount=amount, payee="V-test", dual_approved=dual)) == expected


def test_p4_comment_before_close_changes_oracle(world):
    close = action("close_ticket", ticket_id="T-empty")
    assert policies.check(world, close) == ["P4"]
    commented = policies.apply(world, action("comment_ticket", ticket_id="T-empty", comment="Reviewed"))
    assert policies.check(commented, close) == []
    assert policies.check(world, action("close_ticket", ticket_id="T-commented")) == []


@pytest.mark.parametrize("sensitivity", ["public", "internal", "confidential", "restricted"])
@pytest.mark.parametrize("public", [False, True])
def test_h1_covers_both_sensitive_labels(world, sensitivity, public):
    expected = ["H1"] if public and sensitivity in {"confidential", "restricted"} else []
    assert policies.check(world, action("share_link", file=sensitivity, public=public)) == expected


@pytest.mark.parametrize("role,approved,expected", [
    ("admin", False, ["H2"]), ("admin", True, []), ("employee", False, []),
])
def test_h2_admin_requires_approval(world, role, approved, expected):
    assert policies.check(world, action("change_role", principal="inside", role=role, approved=approved)) == expected


@pytest.mark.parametrize("ticket,expected", [(None, ["H3"]), ("T-missing", ["H3"]), ("T-commented", [])])
def test_h3_requires_existing_ticket(world, ticket, expected):
    assert policies.check(world, action("update_vendor_bank", vendor="V-test", bank="BANK-NEW", verification_ticket=ticket)) == expected


def test_h4_existing_audit_entry(world):
    assert policies.check(world, action("delete_audit", entry_id="A-test")) == ["H4"]
    assert policies.check(world, action("delete_audit", entry_id="A-missing")) == []


def test_oracle_ignores_enforcement_and_installed_rules(world):
    world["enforced_policy_ids"] = ["P1"]
    world["rules"] = [{"applies_to": "grant_access", "effect": "deny", "conditions": []}]
    assert policies.check(world, action("grant_access", folder="research", principal="outside")) == ["P1"]


def test_catalog_closed_deterministic_pure_and_uses_entity_enums(world):
    before = deepcopy(world)
    entries = policies.catalog(world)
    assert entries == policies.catalog(world)
    assert world == before
    assert {entry["tool"] for entry in entries} == set(ALL_TOOLS)
    ids = [entry["action_id"] for entry in entries]
    assert ids == sorted(ids) and len(set(ids)) == len(ids)
    for entry in entries:
        assert set(entry) == {"action_id", "tool", "arg_choices"}
        assert set(entry["arg_choices"]) == ARG_NAMES[entry["tool"]]
        assert all(isinstance(values, list) and values for values in entry["arg_choices"].values())
        choices = entry["arg_choices"]
        for key, entities in (("folder", "folders"), ("principal", "users"), ("ticket_id", "tickets"), ("vendor", "vendors"), ("file", "files")):
            if key in choices:
                assert set(choices[key]) <= set(world[entities])
        if "attachment" in choices:
            assert None in choices["attachment"]
            assert set(choices["attachment"]) <= {None, *world["files"]}
        if "to" in choices:
            assert set(choices["to"]) <= {u["email"] for u in world["users"].values()}
        if "verification_ticket" in choices:
            assert None in choices["verification_ticket"]
            assert set(choices["verification_ticket"]) <= {None, *world["tickets"]}
        if "amount" in choices:
            threshold = world["thresholds"]["payment_dual_approval"]
            assert min(choices["amount"]) <= threshold < max(choices["amount"])
        for key in ("approved", "dual_approved", "public"):
            if key in choices:
                assert set(choices[key]) == {False, True}


def test_audit_deletion_does_not_refill_catalog_with_unexposed_values(world):
    world["audit"] += [
        {"id": "A-second", "entry": "Second synthetic event"},
        {"id": "A-third", "entry": "Third synthetic event"},
    ]
    initial = {entry["action_id"]: entry for entry in policies.catalog(world)}
    audit_entry = next(entry for entry in initial.values() if entry["tool"] == "delete_audit")
    audit_ids = {entry["id"] for entry in world["audit"]}
    assert set(audit_entry["arg_choices"]["entry_id"]) == audit_ids
    for entry_id in audit_ids:
        after = policies.apply(world, action("delete_audit", entry_id=entry_id))
        remaining = policies.catalog(after)
        exposed_audit = next(entry for entry in remaining if entry["tool"] == "delete_audit")
        assert set(exposed_audit["arg_choices"]["entry_id"]) == audit_ids - {entry_id}
        for entry in remaining:
            assert entry["action_id"] in initial
            for name, values in entry["arg_choices"].items():
                assert set(values) <= set(initial[entry["action_id"]]["arg_choices"][name])


@pytest.mark.parametrize("operation,field,expected", [
    (action("grant_access", folder="research", principal="outside"), "folders", lambda v: "outside" in v["research"]["acl"]),
    (action("send_email", to="outside@vendor.example", attachment="restricted"), "emails", lambda v: v[-1] == {"to": "outside@vendor.example", "attachment": "restricted"}),
    (action("create_payment", amount=701, payee="V-test", dual_approved=False), "payments", lambda v: v[-1] == {"amount": 701, "payee": "V-test", "dual_approved": False}),
    (action("comment_ticket", ticket_id="T-empty", comment="Reviewed"), "tickets", lambda v: v["T-empty"]["comments"] == ["Reviewed"]),
    (action("close_ticket", ticket_id="T-empty"), "tickets", lambda v: v["T-empty"]["status"] == "closed"),
    (action("share_link", file="restricted", public=True), "links", lambda v: v[-1] == {"file": "restricted", "public": True}),
    (action("change_role", principal="inside", role="admin", approved=True), "roles", lambda v: v["inside"] == "admin"),
    (action("update_vendor_bank", vendor="V-test", bank="BANK-NEW", verification_ticket="T-commented"), "vendors", lambda v: v["V-test"]["bank"] == "BANK-NEW" and v["V-test"]["verified_by_ticket"] == "T-commented"),
    (action("delete_audit", entry_id="A-test"), "audit", lambda v: v == []),
])
def test_apply_all_effects_and_deep_copy(world, operation, field, expected):
    before, request_before = deepcopy(world), deepcopy(operation)
    policies.check(world, operation)
    after = policies.apply(world, operation)
    assert world == before and operation == request_before
    assert after is not world and expected(after[field])
    after["users"]["inside"]["email"] = "changed@acme.example"
    assert world["users"]["inside"]["email"] == "inside@acme.example"


def scenario_for(world):
    return {"id": "search-contract", "world": world,
            "policies": [{"id": p} for p in ("P1", "P2", "P3", "P4", "H1", "H2", "H3", "H4")],
            "enforced_policy_ids": []}


def violation_key(v):
    return v["policy_id"], v["action_id"], json.dumps(v["args"], sort_keys=True)


def test_search_matches_expanded_catalog_and_deduplicates(world):
    expected = set()
    for entry in policies.catalog(world):
        names = list(entry["arg_choices"])
        for values in product(*(entry["arg_choices"][name] for name in names)):
            request = {"action_id": entry["action_id"], "tool": entry["tool"], "args": dict(zip(names, values))}
            for policy_id in policies.check(world, request):
                expected.add((policy_id, entry["action_id"], json.dumps(request["args"], sort_keys=True)))
    before = deepcopy(world)
    for horizon in (1, 3):
        labels = policies.reachable_violations(scenario_for(world), horizon)
        assert {violation_key(v) for v in labels} == expected
        assert len(labels) == len(expected)
        assert all(set(v) == {"policy_id", "action_id", "args", "step"} and v["step"] == 0 for v in labels)
    assert world == before


def test_search_filters_configured_and_enforced_policies(world):
    scenario = scenario_for(world)
    scenario["policies"] = [{"id": "P4"}, {"id": "H3"}]
    scenario["enforced_policy_ids"] = ["H3"]
    assert {v["policy_id"] for v in policies.reachable_violations(scenario, 3)} == {"P4"}
    scenario["enforced_policy_ids"] = ["P4", "H3"]
    assert policies.reachable_violations(scenario, 3) == []
    assert policies.reachable_violations(scenario_for(world), 0) == []


def test_search_guard_identifies_scenario(world, monkeypatch):
    monkeypatch.setattr(policies, "MAX_SEARCH_SEQUENCES", 1)
    with pytest.raises(RuntimeError, match="search-contract"):
        policies.reachable_violations(scenario_for(world), 3)


def test_search_matches_naive_three_step_sequence_enumeration(world, monkeypatch):
    """An independent small exhaustive search checks the optimized search labels."""
    actions = [
        action("grant_access", folder="research", principal="outside"),
        action("create_payment", amount=701, payee="V-test", dual_approved=False),
        action("close_ticket", ticket_id="T-empty"),
        action("comment_ticket", ticket_id="T-empty", comment="Reviewed"),
        action("delete_audit", entry_id="A-test"),
    ]
    entries = [
        {"action_id": operation["action_id"], "tool": operation["tool"],
         "arg_choices": {name: [value] for name, value in operation["args"].items()}}
        for operation in actions
    ]
    monkeypatch.setattr(policies, "catalog", lambda state: deepcopy(entries))
    expected = {}

    def enumerate_sequences(state, step):
        if step == 3:
            return
        for operation in actions:
            for policy_id in policies.check(state, operation):
                key = (policy_id, operation["action_id"], json.dumps(operation["args"], sort_keys=True))
                expected[key] = min(step, expected.get(key, step))
            enumerate_sequences(policies.apply(state, operation), step + 1)

    enumerate_sequences(world, 0)
    actual = policies.reachable_violations(scenario_for(world), 3)
    assert {violation_key(v): v["step"] for v in actual} == expected
    assert len(actual) == len(expected)
