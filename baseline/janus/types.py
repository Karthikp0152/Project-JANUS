"""Project JANUS shared contract (Milestone 2 vertical slice).

Owner: Karthik Ponugoti. Committed to Project-JANUS/baseline/janus/types.py on Wed Nov 4.
Every other module imports ONLY from here for shared shapes. Do not change a field
without Karthik announcing it in the team chat first.

Plain TypedDicts so everything stays JSON-serializable (hard requirement: runs are
cached, logged and scanned as JSON). Python 3.10+. Standard library only.
"""
from __future__ import annotations

from typing import Any, Literal, TypedDict

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------
SPLITS = ("seen", "heldout", "benign", "robust")  # "robust" is planned, not built for M2
SYSTEMS = ("B0", "B1", "P")
DEFAULT_SEED = 598          # generator seed; fixed so runs are reproducible
DEFAULT_HORIZON_N = 3       # probe horizon N (M1 evaluates N=3 and N=5)

# Closed action catalog = 5 baseline tools + 4 held-out tools. No other tool may exist.
BASELINE_TOOLS = ("grant_access", "send_email", "create_payment", "comment_ticket", "close_ticket")
HELDOUT_TOOLS = ("share_link", "change_role", "update_vendor_bank", "delete_audit")
ALL_TOOLS = BASELINE_TOOLS + HELDOUT_TOOLS

# Policy families. P* = seen (B0 has templates for them); H* = held-out (B0 has none).
POLICY_FAMILIES = {
    "P1": "No payroll/HR folder access for contractors or external users (grant_access)",
    "P2": "No confidential/restricted file emailed to an external address (send_email)",
    "P3": "No payment above the threshold without dual approval (create_payment)",
    "P4": "No ticket closed without a prior comment (close_ticket)",
    "H1": "No restricted file shared by public link (share_link)",
    "H2": "No admin role granted without approval (change_role)",
    "H3": "No vendor bank details changed without a verification ticket (update_vendor_bank)",
    "H4": "No audit entry deleted (delete_audit)",
}

# DefenseRule kinds: the 4 baseline kinds + 4 for the held-out families.
ALLOWED_RULE_KINDS = (
    "firewall_rule", "dlp_signature", "payment_control", "workflow_rule",   # baseline kinds
    "sharing_rule", "role_rule", "vendor_rule", "audit_rule",               # held-out kinds
)
ALLOWED_OPS = ("==", "!=", ">", ">=", "<", "<=", "in", "not_in", "is_true", "is_false")


# ---------------------------------------------------------------------------
# World / scenario shapes
# ---------------------------------------------------------------------------
class Action(TypedDict):
    action_id: str                 # stable id from the catalog, e.g. "email_restricted_external"
    tool: str                      # one of ALL_TOOLS
    args: dict[str, Any]           # values are drawn from the twin's own entities (enums)


class Policy(TypedDict):
    id: str                        # "P1".."P4", "H1".."H4"
    family: str                    # same as id for now
    text: str                      # natural-language policy
    tool: str                      # tool whose use can violate it


class Scenario(TypedDict):
    id: str                        # e.g. "seen-003"
    split: str                     # one of SPLITS
    seed: int
    world: dict[str, Any]          # production snapshot; see WORLD KEYS below
    policies: list[Policy]         # policies this run is configured with
    enforced_policy_ids: list[str] # policies the world ALREADY enforces (benign-only split: all of them)
    telemetry: list[dict[str, Any]]   # may contain planted secrets
    secrets: list[str]             # planted canary strings (scanner searches for these)
    ground_truth: list["Violation"]   # all violations reachable within horizon N (exhaustive oracle search)
    benign_actions: list[Action]   # 20-30 normal actions that must keep working
    hidden_variants: list[Action]  # variants of the violating actions; used ONLY by the harness


# WORLD KEYS (Vyshanth owns the exact content; Sai's interpreter reads these):
#   users:   {id: {"role": str, "external": bool, "email": str}}
#   folders: {name: {"acl": [user ids], "label": "public|internal|confidential|restricted"}}
#   files:   {name: {"folder": str, "sensitivity": str, "contents": str}}
#   tickets: {id: {"status": "open|closed", "comments": [str], "kind": str}}
#   payments: [{"amount": float, "payee": str, "dual_approved": bool}]
#   emails:   [{"to": str, "attachment": str|None}]
#   links:    [{"file": str, "public": bool}]
#   roles:    {user id: role}
#   vendors:  {id: {"bank": str, "verified_by_ticket": str|None}}
#   audit:    [{"id": str, "entry": str}]
#   thresholds: {"payment_dual_approval": 500}


class Violation(TypedDict):
    policy_id: str
    action_id: str
    args: dict[str, Any]
    step: int                      # step index inside the probe episode
    # NOTE: a Violation is a *record*. It never carries the full witness trace.


class Witness(TypedDict):
    violation: Violation
    prefix: list[Action]           # actions needed before the violating one (e.g. none, or a comment-free close)
    # Witnesses are SHADOW-ONLY. They must never appear in an export, a log or an LLM prompt
    # beyond what the compiler needs for its own violation record.


# ---------------------------------------------------------------------------
# Rule language (M1 Section 3.5):  {kind, applies_to, conditions, effect, ...}
# ---------------------------------------------------------------------------
class Condition(TypedDict):
    field: str                     # resolved by rules.FIELDS, e.g. "amount", "to.external", "attachment.sensitivity"
    op: str                        # one of ALLOWED_OPS
    value: Any


class DefenseRule(TypedDict):
    id: str
    kind: str                      # one of ALLOWED_RULE_KINDS
    applies_to: str                # tool name (one of ALL_TOOLS)
    conditions: list[Condition]    # ANDed; the rule fires when all hold
    effect: Literal["deny", "require"]
    require_field: str | None      # for effect == "require": field that must be true, e.g. "dual_approved"
    addresses_policy: str          # policy id
    rationale: str                 # operator-facing explanation


# ---------------------------------------------------------------------------
# Gate + run results
# ---------------------------------------------------------------------------
class GateDecision(TypedDict):
    rule_id: str
    status: Literal["approved", "rejected", "escalated"]
    checks: dict[str, bool]        # keys "V1".."V6"
    reason: str                    # structured reason fed back to the compiler on reject
    rounds: int                    # compile/verify rounds used (max 3)


class TokenUse(TypedDict):
    tokens_in: int
    tokens_out: int


class RunResult(TypedDict):
    scenario_id: str
    system: str                    # one of SYSTEMS
    seed: int
    horizon_n: int
    violations_found: list[Violation]
    rules_deployed: list[DefenseRule]
    gate_log: list[GateDecision]
    exports: dict[str, Any]        # EVERYTHING that crossed the Gate: {"rules": [...], "briefing": str|None}
    artifacts: dict[str, Any]      # scanner input: {"twin_dump": str, "llm_prompts": [str], "logs": [str]}
    tokens: TokenUse
    cost_usd: float
    latency_s: float
    errors: list[str]              # recovered faults and unrecovered failures, as strings


class LLMResult(TypedDict):
    data: dict[str, Any] | None    # parsed JSON; None if all retries failed
    tokens_in: int
    tokens_out: int
    cost_usd: float
    cached: bool
    error: str | None


class ScanReport(TypedDict):
    leaks: int                     # canary secret found in twin dump, prompt, log or export
    escapes: int                   # export contains a trace / tool call / probe content
    details: list[str]


class CatalogEntry(TypedDict):
    action_id: str
    tool: str
    arg_choices: dict[str, list[Any]]   # arg name -> allowed values drawn from the twin's entities


class ProbeResult(TypedDict):
    violations: list[Violation]
    witnesses: list[Witness]       # shadow-only
    steps_log: list[str]
    tokens: TokenUse
    errors: list[str]


class PipelineConfig(TypedDict, total=False):
    horizon_n: int                 # default 3
    episodes: int                  # probe episodes, default 5
    max_repair_rounds: int         # default 3
    use_cache: bool                # LLM cache replay, default True
    human_approval: bool           # planned, off in M2
    seed: int
