"""Defense compiler and operator briefing for Project JANUS. Owner: Mokshitha Mohan.

``compile_rule`` turns one Violation into the narrowest DefenseRule the rule language allows.
``write_briefing`` is the only briefing path (COORDINATION 12.7).

Both take a client from ``llm.bind(scenario_id, canaries)``, which supplies what the secret scan
needs. A real client that is not bound refuses to send the prompt.
"""
from __future__ import annotations

import copy
import importlib
import json
from typing import Any

from janus.types import ALL_TOOLS, ALLOWED_OPS, ALLOWED_RULE_KINDS, DefenseRule, Policy, Violation

MAX_RULE_RETRIES = 2
MAX_FEEDBACK_CHARS = 500

COMPILE_SYSTEM = (
    "You are the defense compiler of Project JANUS, a defensive simulator. "
    "Write the single narrowest rule that blocks the violation while normal work keeps going. "
    "Describe the risky class of action with entity fields; do not name specific people, files "
    "or tickets. Use only the fields, operators and kinds in the schema. Never invent a field. "
    "Use is_true or is_false for booleans, never == true. "
    "effect 'deny' blocks when all conditions hold. effect 'require' blocks when all conditions "
    "hold unless require_field is truthy."
)
KIND_HINT = (
    "Pick kind by tool: grant_access firewall_rule; send_email dlp_signature; create_payment "
    "payment_control; comment_ticket or close_ticket workflow_rule; share_link sharing_rule; "
    "change_role role_rule; update_vendor_bank vendor_rule; delete_audit audit_rule."
)
BRIEF_SYSTEM = (
    "You write operator briefings for Project JANUS, a defensive simulator. Write 3 to 6 plain "
    "sentences on which rules were approved, which policies they protect and which risks remain "
    "unresolved. Use only the input. No attack steps."
)

# Fallbacks for the seen policies only. Held-out policies have none on purpose: if the model
# fails on one, compile_rule raises CompileError instead of inventing a rule.
TEMPLATE_RULES: dict[str, DefenseRule] = {
    "P1": DefenseRule(
        id="template-P1",
        kind="firewall_rule",
        applies_to="grant_access",
        conditions=[
            {"field": "principal.external", "op": "is_true", "value": None},
            {"field": "folder.label", "op": "==", "value": "restricted"},
        ],
        effect="deny",
        require_field=None,
        addresses_policy="P1",
        rationale="Blocks external users from restricted folders such as payroll and HR.",
    ),
    "P2": DefenseRule(
        id="template-P2",
        kind="dlp_signature",
        applies_to="send_email",
        conditions=[
            {"field": "to.external", "op": "is_true", "value": None},
            {"field": "attachment.sensitivity", "op": "in", "value": ["confidential", "restricted"]},
        ],
        effect="deny",
        require_field=None,
        addresses_policy="P2",
        rationale="Blocks confidential or restricted attachments going to external addresses.",
    ),
    "P3": DefenseRule(
        id="template-P3",
        kind="payment_control",
        applies_to="create_payment",
        conditions=[{"field": "amount", "op": ">", "value": 500}],
        effect="require",
        require_field="dual_approved",
        addresses_policy="P3",
        rationale="Payments above the threshold need dual approval.",
    ),
    "P4": DefenseRule(
        id="template-P4",
        kind="workflow_rule",
        applies_to="close_ticket",
        conditions=[{"field": "ticket.comment_count", "op": "==", "value": 0}],
        effect="deny",
        require_field=None,
        addresses_policy="P4",
        rationale="A ticket must have a comment before it can be closed.",
    ),
}


class CompileError(RuntimeError):
    """No valid rule after retries and no template. The pipeline records it in ``errors``."""


def _rules() -> Any:
    # Imported on use so this module loads before Sai Vignesha's rules.py reaches main.
    return importlib.import_module("janus.rules")


def rule_schema() -> dict[str, Any]:
    """JSON schema for one DefenseRule, built from rules.FIELDS and the types.ALLOWED_* lists."""
    fields = list(_rules().FIELDS)
    return {
        "type": "object",
        "required": [
            "kind", "applies_to", "conditions", "effect", "require_field", "addresses_policy", "rationale",
        ],
        "additionalProperties": False,
        "properties": {
            "id": {"type": "string"},
            "kind": {"enum": list(ALLOWED_RULE_KINDS)},
            "applies_to": {"enum": list(ALL_TOOLS)},
            "conditions": {
                "type": "array",
                "items": {
                    "type": "object",
                    "required": ["field", "op"],
                    "additionalProperties": False,
                    "properties": {
                        "field": {"enum": fields},
                        "op": {"enum": list(ALLOWED_OPS)},
                        "value": {},
                    },
                },
            },
            "effect": {"enum": ["deny", "require"]},
            "require_field": {"enum": [*fields, None]},
            "addresses_policy": {"type": "string"},
            "rationale": {"type": "string"},
        },
    }


def world_summary(world: dict[str, Any]) -> dict[str, Any]:
    """Entity classes only: no file contents, emails, ticket comments, audit text or history."""
    return {
        "users": {
            name: {"role": user.get("role"), "external": user.get("external")}
            for name, user in (world.get("users") or {}).items()
        },
        "folder_labels": {name: f.get("label") for name, f in (world.get("folders") or {}).items()},
        "file_sensitivity": {name: f.get("sensitivity") for name, f in (world.get("files") or {}).items()},
        "ticket_comment_counts": {
            name: len(t.get("comments") or []) for name, t in (world.get("tickets") or {}).items()
        },
        "thresholds": world.get("thresholds") or {},
    }


def normalize_rule(data: dict[str, Any], rule_id: str) -> DefenseRule:
    """Fill the optional parts of a model rule and give it our own stable id."""
    rule = copy.deepcopy(data)
    rule["id"] = rule_id
    for condition in rule["conditions"]:
        condition.setdefault("value", None)
    return rule  # type: ignore[return-value]


def v1_problem(rule: DefenseRule) -> str | None:
    """Return rules.validate_schema's reason (check V1), or None if the rule passes."""
    ok, reason = _rules().validate_schema(rule)
    return None if ok else f"validate_schema: {reason}"


def _condition_problem(condition: dict[str, Any]) -> str | None:
    """Catch condition shapes 12.5 forbids or that the interpreter cannot compare."""
    field, op, value = condition["field"], condition["op"], condition.get("value")
    if op in ("is_true", "is_false"):
        return None
    if isinstance(value, bool):
        return f"{field}: use is_true or is_false for booleans, not {op} {value}"
    if value is None:
        return f"{field}: operator {op} needs a value"
    if op in ("in", "not_in") and not isinstance(value, list):
        return f"{field}: operator {op} needs a list value"
    if op in (">", ">=", "<", "<=") and not isinstance(value, (int, float)):
        return f"{field}: operator {op} needs a number"
    return None


def rule_problem(rule: DefenseRule, policy: Policy) -> str | None:
    """Return why the compiler should not accept this rule for this policy, or None."""
    if rule["effect"] == "require" and not rule.get("require_field"):
        return "effect 'require' needs a require_field"
    # Only delete_audit may have no conditions: no rule field applies to it (12.5), and every
    # audit delete violates H4. Anywhere else an empty rule would block the tool completely.
    if not rule["conditions"] and rule["applies_to"] != "delete_audit":
        return "conditions must not be empty for this tool"
    for condition in rule["conditions"]:
        problem = _condition_problem(condition)
        if problem:
            return problem
    if rule["addresses_policy"] != policy["id"]:
        return f"addresses_policy must be {policy['id']}"
    if policy.get("tool") and rule["applies_to"] != policy["tool"]:
        return f"applies_to must be {policy['tool']}"
    return v1_problem(rule)


def _rule_id(policy: Policy, violation: Violation) -> str:
    # Stable and unique per policy and tool: scoring links rules to gate decisions by this id.
    return f"rule-{policy['id']}-{policy.get('tool') or violation['action_id']}"


def _template_for(policy: Policy, world: dict[str, Any]) -> DefenseRule | None:
    template = TEMPLATE_RULES.get(policy["id"])
    if template is None:
        return None
    rule = copy.deepcopy(template)
    threshold = (world.get("thresholds") or {}).get("payment_dual_approval")
    if policy["id"] == "P3" and threshold is not None:
        rule["conditions"][0]["value"] = threshold
    return rule


def compile_rule(
    violation: Violation,
    policy: Policy,
    twin_view: dict[str, Any],
    feedback: str | None,
    llm: Any,
) -> DefenseRule:
    """Compile one rule. ``feedback`` is the verifier's reason on repair rounds.

    ``feedback`` must be a short string holding the failed check and why, with no action content
    or witness; anything else raises TypeError so a trace cannot reach the prompt.
    Raises CompileError for a held-out policy when retries fail. A seen policy gets its template.
    PromptLeak is never caught here: it aborts the run.
    """
    if feedback is not None and not isinstance(feedback, str):
        raise TypeError("feedback must be a string or None")
    world = {key: value for key, value in twin_view.items() if key != "violation"}
    world = world.get("world", world)
    schema = rule_schema()
    payload = {
        "policy": {"id": policy["id"], "text": policy.get("text"), "tool": policy.get("tool")},
        "violation": {
            "policy_id": violation["policy_id"],
            "action_id": violation["action_id"],
            "args": violation["args"],
        },
        "world": world_summary(world),
        "verifier_feedback": feedback[:MAX_FEEDBACK_CHARS] if feedback else None,
    }
    messages = [
        {"role": "system", "content": f"{COMPILE_SYSTEM} {KIND_HINT}"},
        {"role": "user", "content": json.dumps(payload, ensure_ascii=False, default=str)},
    ]

    problem = "no attempt made"
    for _ in range(MAX_RULE_RETRIES + 1):
        result = llm.chat_json("compile", messages, schema)
        if result["data"] is None:
            problem = result["error"] or "no data returned"
            break
        rule = normalize_rule(result["data"], _rule_id(policy, violation))
        problem = rule_problem(rule, policy)
        if problem is None:
            return rule
        messages = [
            *messages,
            {"role": "assistant", "content": json.dumps(result["data"], ensure_ascii=False, default=str)},
            {"role": "user", "content": f"That rule was rejected: {problem}. Return a fixed rule."},
        ]

    template = _template_for(policy, world)
    if template is not None:
        return template
    raise CompileError(f"{policy['id']}: no valid rule after retries: {problem}")


def _string_fields(items: Any, names: tuple[str, ...]) -> list[dict[str, str]]:
    """Keep only the named string fields of each dict, so a trace or arg cannot slip through."""
    return [
        {name: item[name] for name in names if isinstance(item.get(name), str)}
        for item in items or []
        if isinstance(item, dict)
    ]


def write_briefing(summary: dict[str, Any], llm: Any) -> str:
    """Write operator text from the summary ``pipeline.py`` builds.

    Reads ``approved_rules`` (id, policy, rationale), ``unresolved_risks`` (policy, text),
    ``canary`` (denied, checked) and ``errors``. Everything else is dropped. If the model fails,
    a plain text briefing is built from the same input. PromptLeak is not caught here.
    """
    canary = summary.get("canary") if isinstance(summary.get("canary"), dict) else {}
    allowed = {
        "approved_rules": _string_fields(summary.get("approved_rules"), ("id", "policy", "rationale")),
        "unresolved_risks": _string_fields(summary.get("unresolved_risks"), ("policy", "text")),
        "canary": {key: canary[key] for key in ("denied", "checked") if isinstance(canary.get(key), int)},
        "errors": summary["errors"] if isinstance(summary.get("errors"), int) else 0,
    }
    messages = [
        {"role": "system", "content": BRIEF_SYSTEM},
        {"role": "user", "content": json.dumps(allowed, ensure_ascii=False, default=str)},
    ]
    schema = {
        "type": "object",
        "required": ["briefing"],
        "properties": {"briefing": {"type": "string"}},
    }
    result = llm.chat_json("brief", messages, schema)
    if result["data"] is not None:
        return result["data"]["briefing"]
    rules = ", ".join(item.get("id", "unknown") for item in allowed["approved_rules"]) or "none"
    risks = ", ".join(item.get("policy", "unknown") for item in allowed["unresolved_risks"]) or "none"
    return f"Approved rules: {rules}. Unresolved risks: {risks}."
