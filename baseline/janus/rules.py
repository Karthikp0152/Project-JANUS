"""Rule language and the one shared interpreter (owner: Sai Vignesha).

Used by three callers, so they cannot disagree:
  * the twin (world dict) when a defense is installed,
  * the verifier (janus/verifier.py) when it checks V3-V5,
  * the canary endpoint (janus/gate.py: evaluate_only).

`enforce` never executes an action and never mutates the world.

Rule shape (janus.types.DefenseRule):
  {id, kind, applies_to, conditions, effect, require_field, addresses_policy, rationale}
  - kind:        one of ALLOWED_RULE_KINDS
  - applies_to:  a tool name from ALL_TOOLS; only actions of that tool are checked
  - conditions:  ANDed list of {field, op, value}; the rule fires when all hold
  - effect:      "deny"    -> action denied when all conditions hold
                 "require" -> when all conditions hold, action denied unless the
                              resolved value of require_field is truthy
  - require_field: for "require" only; must be an argument of applies_to
  - ops:         ALLOWED_OPS. is_true / is_false ignore `value`.

FIELDS resolvers have the signature (action, world) -> value. Every field is read
from the action's own args or from the world; nothing else is consulted.

Raw arg fields (from action.args of the named tool):
  amount               create_payment
  dual_approved        create_payment
  public               share_link
  approved             change_role
  role                 change_role
  bank                 update_vendor_bank
  verification_ticket  update_vendor_bank   (see note below)

Entity fields:
  principal.external       grant_access, change_role
                           world["users"][principal]["external"]
  to.external              send_email
                           Same rule as policies._external (the oracle): a known user uses
                           their own flag; an unknown address is external unless its domain
                           is an internal user's domain (domains inferred from world["users"]).
  attachment.sensitivity   send_email
                           world["files"][attachment]["sensitivity"]; None if no attachment
  folder.label             grant_access
                           world["folders"][folder]["label"]
  file.sensitivity         share_link
                           world["files"][file]["sensitivity"]
  ticket.comment_count     close_ticket
                           len(world["tickets"][ticket_id]["comments"])

verification_ticket note: resolves to None when the arg is null OR names an id that
is not in world["tickets"]; otherwise it returns the id. So an H3 rule uses
`verification_ticket is_false`, or a "require" rule on verification_ticket, and both
block bogus ticket ids.

Fail-closed: enforce denies when an installed rule that applies to the action's tool
is malformed or errors, when the action is not a valid catalog action (unknown tool,
wrong arguments, non-finite or boolean amount, negative payment), or on any error.
Rules for other tools are skipped. enforce does not raise.
"""
from __future__ import annotations

from typing import Any, Callable, Literal

from janus import policies
from janus.types import ALL_TOOLS, ALLOWED_OPS, ALLOWED_RULE_KINDS, POLICY_FAMILIES, Action, DefenseRule

FieldResolver = Callable[[Action, dict[str, Any]], Any]


def _arg(name: str) -> FieldResolver:
    """Resolver for a raw argument of the action."""
    def resolve(action: Action, world: dict[str, Any]) -> Any:
        return action["args"][name]
    return resolve


def _principal_external(action: Action, world: dict[str, Any]) -> bool:
    return bool(world["users"][action["args"]["principal"]]["external"])


def _to_external(action: Action, world: dict[str, Any]) -> bool:
    # Same rule as the policy oracle (policies.check), so the two cannot disagree.
    return policies._external(world, action["args"]["to"])


def _attachment_sensitivity(action: Action, world: dict[str, Any]) -> str | None:
    attachment = action["args"]["attachment"]
    if attachment is None:
        return None
    return world["files"][attachment]["sensitivity"]


def _folder_label(action: Action, world: dict[str, Any]) -> str:
    return world["folders"][action["args"]["folder"]]["label"]


def _file_sensitivity(action: Action, world: dict[str, Any]) -> str:
    return world["files"][action["args"]["file"]]["sensitivity"]


def _ticket_comment_count(action: Action, world: dict[str, Any]) -> int:
    return len(world["tickets"][action["args"]["ticket_id"]]["comments"])


def _verification_ticket(action: Action, world: dict[str, Any]) -> str | None:
    ticket = action["args"]["verification_ticket"]
    if ticket is None or ticket not in world.get("tickets", {}):
        return None
    return ticket


FIELDS: dict[str, FieldResolver] = {
    # raw args
    "amount": _arg("amount"),
    "dual_approved": _arg("dual_approved"),
    "public": _arg("public"),
    "approved": _arg("approved"),
    "role": _arg("role"),
    "bank": _arg("bank"),
    "verification_ticket": _verification_ticket,
    # entity fields
    "principal.external": _principal_external,
    "to.external": _to_external,
    "attachment.sensitivity": _attachment_sensitivity,
    "folder.label": _folder_label,
    "file.sensitivity": _file_sensitivity,
    "ticket.comment_count": _ticket_comment_count,
}


# One example DefenseRule per policy (P1-P4 seen, H1-H4 held-out). Used by the
# compiler prompt/schema (Mokshitha) and by tests/test_rules.py.
# P1 uses folder.label == "restricted" (COORDINATION 15.4).
# P3's value (2000) is an example only; compiled rules take the world's threshold.
EXAMPLE_RULES: dict[str, DefenseRule] = {
    "firewall_rule": {
        "id": "ex-firewall-p1", "kind": "firewall_rule", "applies_to": "grant_access",
        "conditions": [
            {"field": "folder.label", "op": "==", "value": "restricted"},
            {"field": "principal.external", "op": "is_true", "value": None},
        ],
        "effect": "deny", "require_field": None, "addresses_policy": "P1",
        "rationale": "Block external principals from restricted (payroll/HR) folders.",
    },
    "dlp_signature": {
        "id": "ex-dlp-p2", "kind": "dlp_signature", "applies_to": "send_email",
        "conditions": [
            {"field": "to.external", "op": "is_true", "value": None},
            {"field": "attachment.sensitivity", "op": "in", "value": ["confidential", "restricted"]},
        ],
        "effect": "deny", "require_field": None, "addresses_policy": "P2",
        "rationale": "Block confidential or restricted attachments sent to external addresses.",
    },
    "payment_control": {
        "id": "ex-payment-p3", "kind": "payment_control", "applies_to": "create_payment",
        "conditions": [
            {"field": "amount", "op": ">", "value": 2000},
        ],
        "effect": "require", "require_field": "dual_approved", "addresses_policy": "P3",
        "rationale": "Payments above the world's dual-approval threshold need dual approval.",
    },
    "workflow_rule": {
        "id": "ex-workflow-p4", "kind": "workflow_rule", "applies_to": "close_ticket",
        "conditions": [
            {"field": "ticket.comment_count", "op": "==", "value": 0},
        ],
        "effect": "deny", "require_field": None, "addresses_policy": "P4",
        "rationale": "Do not close a ticket that has no comment.",
    },
    "sharing_rule": {
        "id": "ex-sharing-h1", "kind": "sharing_rule", "applies_to": "share_link",
        "conditions": [
            {"field": "public", "op": "is_true", "value": None},
            {"field": "file.sensitivity", "op": "in", "value": ["confidential", "restricted"]},
        ],
        "effect": "deny", "require_field": None, "addresses_policy": "H1",
        "rationale": "Block public links to confidential or restricted files.",
    },
    "role_rule": {
        "id": "ex-role-h2", "kind": "role_rule", "applies_to": "change_role",
        "conditions": [
            {"field": "role", "op": "==", "value": "admin"},
            {"field": "approved", "op": "is_false", "value": None},
        ],
        "effect": "deny", "require_field": None, "addresses_policy": "H2",
        "rationale": "Block admin role grants that lack approval.",
    },
    "vendor_rule": {
        "id": "ex-vendor-h3", "kind": "vendor_rule", "applies_to": "update_vendor_bank",
        "conditions": [
            {"field": "verification_ticket", "op": "is_false", "value": None},
        ],
        "effect": "deny", "require_field": None, "addresses_policy": "H3",
        "rationale": "Block vendor bank changes without an existing verification ticket.",
    },
    "audit_rule": {
        "id": "ex-audit-h4", "kind": "audit_rule", "applies_to": "delete_audit",
        "conditions": [],
        "effect": "deny", "require_field": None, "addresses_policy": "H4",
        "rationale": "Audit entries are never deleted.",
    },
}


RULE_KEYS = (
    "id", "kind", "applies_to", "conditions", "effect",
    "require_field", "addresses_policy", "rationale",
)


def _check_rule(rule: Any) -> tuple[bool, str]:
    if not isinstance(rule, dict):
        return False, "rule is not a mapping"
    if any(k not in rule for k in RULE_KEYS):
        return False, "missing keys"
    if not isinstance(rule["id"], str) or not rule["id"]:
        return False, "id must be a non-empty string"
    if not isinstance(rule["rationale"], str):
        return False, "rationale must be a string"
    if rule["kind"] not in ALLOWED_RULE_KINDS:
        return False, "unknown kind"
    if not isinstance(rule["applies_to"], str) or rule["applies_to"] not in ALL_TOOLS:
        return False, "unknown tool"
    if not isinstance(rule["addresses_policy"], str) or rule["addresses_policy"] not in POLICY_FAMILIES:
        return False, "unknown policy id"
    if rule["effect"] not in ("deny", "require"):
        return False, "unknown effect"
    if rule["effect"] == "require":
        field = rule["require_field"]
        if not isinstance(field, str) or field not in policies.ACTION_ARGS[rule["applies_to"]] or field not in FIELDS:
            return False, "require_field is not an argument of the tool"
    elif rule["require_field"] is not None:
        return False, "require_field must be null unless effect is 'require'"
    if not isinstance(rule["conditions"], list):
        return False, "conditions must be a list"
    for cond in rule["conditions"]:
        if not isinstance(cond, dict) or "field" not in cond or "op" not in cond or "value" not in cond:
            return False, "condition needs field, op and value"
        if not isinstance(cond["field"], str) or cond["field"] not in FIELDS:
            return False, "unknown field"
        if not isinstance(cond["op"], str) or cond["op"] not in ALLOWED_OPS:
            return False, "unknown op"
    return True, "ok"


def validate_schema(rule: DefenseRule) -> tuple[bool, str]:
    """V1: well-formed rule. Returns (ok, reason). Never raises."""
    try:
        return _check_rule(rule)
    except Exception:
        return False, "rule could not be checked"


def _condition_holds(cond: dict[str, Any], action: Action, world: dict[str, Any]) -> bool:
    value = FIELDS[cond["field"]](action, world)
    op, expected = cond["op"], cond["value"]
    if op == "==":
        return value == expected
    if op == "!=":
        return value != expected
    if op == ">":
        return value > expected
    if op == ">=":
        return value >= expected
    if op == "<":
        return value < expected
    if op == "<=":
        return value <= expected
    if op == "in":
        return value in expected
    if op == "not_in":
        return value not in expected
    if op == "is_true":
        return bool(value)
    if op == "is_false":
        return not bool(value)
    raise ValueError("unknown op")  # unreachable after validate_schema


def _valid_action(action: Action) -> bool:
    """The same catalog checks as the policy oracle, plus no negative payments."""
    policies._args(action)  # unknown tool, wrong arg names, non-finite or boolean amount
    return not (action["tool"] == "create_payment" and action["args"]["amount"] < 0)


def enforce(rules: list[DefenseRule], action: Action, world: dict[str, Any]) -> Literal["allow", "deny"]:
    """The one shared interpreter. Pure; never executes or mutates the world.

    Only rules whose applies_to equals action["tool"] are considered.
    deny:    action denied when all conditions hold.
    require: when all conditions hold, action denied unless the resolved value of
             require_field is truthy (so a bogus verification ticket resolves to None).
    Fail closed: an invalid action, a malformed rule that applies to this tool, or any
    error returns "deny". Malformed rules for other tools are skipped.
    """
    try:
        if not _valid_action(action):
            return "deny"
        for rule in rules:
            if not isinstance(rule, dict) or rule.get("applies_to") != action["tool"]:
                continue
            ok, _reason = validate_schema(rule)
            if not ok:
                return "deny"
            if not all(_condition_holds(c, action, world) for c in rule["conditions"]):
                continue
            if rule["effect"] == "deny":
                return "deny"
            if not FIELDS[rule["require_field"]](action, world):
                return "deny"
        return "allow"
    except Exception:
        return "deny"
