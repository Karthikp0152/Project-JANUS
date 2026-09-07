from __future__ import annotations

from typing import Any

SCENARIO_CATALOG: list[dict[str, str]] = [
    {
        "id": "safe_ticket",
        "title": "Safe IT ticket",
        "risk": "safe",
        "blurb": "Normal helpdesk work: leave a comment on a VPN ticket.",
    },
    {
        "id": "unsafe_contractor",
        "title": "Contractor payroll access",
        "risk": "unsafe",
        "blurb": "Outside vendor gets payroll folder access and a salary spreadsheet email.",
    },
    {
        "id": "salary_leak",
        "title": "Salary file leak",
        "risk": "unsafe",
        "blurb": "Someone tries to email the restricted Q4 salary file outside the company.",
    },
    {
        "id": "wire_fraud",
        "title": "Big wire without approval",
        "risk": "unsafe",
        "blurb": "A large payment is created with no dual approval.",
    },
    {
        "id": "vendor_invoice_trap",
        "title": "Fake vendor invoice",
        "risk": "unsafe",
        "blurb": "Payment + external email combo that looks like invoice fraud.",
    },
    {
        "id": "messy_ticket_close",
        "title": "Close ticket with no note",
        "risk": "unsafe",
        "blurb": "An agent closes a ticket without writing a comment first.",
    },
    {
        "id": "outsider_hr_keys",
        "title": "Outsider on HR folder",
        "risk": "unsafe",
        "blurb": "An external address is added to a sensitive HR/payroll ACL.",
    },
    {
        "id": "internal_status_ok",
        "title": "Internal status email",
        "risk": "safe",
        "blurb": "A normal internal status email with no secret attachment.",
    },
]


def _try_grant(state, folder: str, principal: str) -> dict[str, Any]:
    blocked = state.defense_blocks("grant_access", folder=folder, principal=principal)
    if blocked:
        state.emit("defense_blocked", action="grant_access", rule=blocked)
        return {"action": "grant_access", "ok": False, "blocked": blocked}
    if principal not in state.folders[folder]["acl"]:
        state.folders[folder]["acl"].append(principal)
    state.emit(
        "identity_seen",
        principal=principal,
        role="contractor" if state.is_external(principal) else "employee",
        external=state.is_external(principal),
        folder=folder,
    )
    return {"action": "grant_access", "ok": True, "acl": list(state.folders[folder]["acl"])}


def _try_email(state, to: str, body: str, attachment: str | None) -> dict[str, Any]:
    blocked = state.defense_blocks("send_email", to=to, attachment=attachment)
    if blocked:
        state.emit("defense_blocked", action="send_email", rule=blocked)
        return {"action": "send_email", "ok": False, "blocked": blocked}
    if attachment:
        state.emit("file_touch", file=attachment, user="api")
    state.emails.append({"to": to, "body": body, "attachment": attachment})
    state.emit("email_sent", to=to, attachment=attachment)
    return {"action": "send_email", "ok": True}


def _try_payment(state, amount: float, payee: str, dual: bool = False) -> dict[str, Any]:
    blocked = state.defense_blocks("create_payment", amount=amount, dual_approved=dual)
    if blocked:
        state.emit("defense_blocked", action="create_payment", rule=blocked)
        return {"action": "create_payment", "ok": False, "blocked": blocked}
    state.payments.append({"amount": amount, "payee": payee, "dual_approved": dual})
    state.emit("payment_created", amount=amount, payee=payee)
    return {"action": "create_payment", "ok": True, "amount": amount}


def _try_close(state, ticket_id: str) -> dict[str, Any]:
    ticket = state.tickets.get(ticket_id)
    if not ticket:
        return {"action": "close_ticket", "ok": False, "error": "missing ticket"}
    blocked = state.defense_blocks("close_ticket", ticket_id=ticket_id)
    if blocked:
        state.emit("defense_blocked", action="close_ticket", rule=blocked)
        return {"action": "close_ticket", "ok": False, "blocked": blocked}
    ticket["status"] = "closed"
    state.emit("ticket_update", ticket_id=ticket_id, status="closed")
    return {"action": "close_ticket", "ok": True}


def run_scenario(state, scenario_id: str) -> list[dict[str, Any]]:
    if scenario_id == "safe_ticket":
        state.tickets["T-104"]["comments"].append("VPN block lifted for alex")
        state.emit("ticket_update", ticket_id="T-104", comment="VPN block lifted for alex")
        return [{"action": "comment_ticket", "ok": True}]

    if scenario_id == "unsafe_contractor":
        return [
            _try_grant(state, "payroll", "jane@vendor.com"),
            _try_email(state, "jane@vendor.com", "Q4 salary packet", "q4_salary.xlsx"),
        ]

    if scenario_id == "salary_leak":
        state.emit("file_touch", file="q4_salary.xlsx", user="unknown")
        return [_try_email(state, "rival@outside.example", "salary dump", "q4_salary.xlsx")]

    if scenario_id == "wire_fraud":
        state.emit("identity_seen", principal="payme@vendor-evil.example", role="vendor", external=True)
        return [_try_payment(state, 12500, "payme@vendor-evil.example", dual=False)]

    if scenario_id == "vendor_invoice_trap":
        return [
            _try_payment(state, 4800, "billing@quickpay-vendor.example", dual=False),
            _try_email(
                state,
                "billing@quickpay-vendor.example",
                "Invoice copy + employee roster",
                "q4_salary.xlsx",
            ),
        ]

    if scenario_id == "messy_ticket_close":
        state.tickets["T-104"]["comments"] = []
        state.tickets["T-104"]["status"] = "open"
        state.emit("ticket_update", ticket_id="T-104", status="open", comment="")
        return [_try_close(state, "T-104")]

    if scenario_id == "outsider_hr_keys":
        return [_try_grant(state, "payroll", "temp.hire@contractor.net")]

    if scenario_id == "internal_status_ok":
        return [_try_email(state, "alex@acme.example", "Daily ops status — no attachments", None)]

    raise KeyError(scenario_id)
