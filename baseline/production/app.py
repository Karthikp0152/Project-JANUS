from __future__ import annotations

import secrets
import time
from dataclasses import dataclass, field
from threading import Lock
from typing import Any

from fastapi import FastAPI, Header, HTTPException
from pydantic import BaseModel, Field


@dataclass
class ProductionState:
    tickets: dict[str, dict[str, Any]] = field(default_factory=dict)
    folders: dict[str, dict[str, Any]] = field(default_factory=dict)
    files: dict[str, dict[str, Any]] = field(default_factory=dict)
    users: dict[str, dict[str, Any]] = field(default_factory=dict)
    emails: list[dict[str, Any]] = field(default_factory=list)
    payments: list[dict[str, Any]] = field(default_factory=list)
    defenses: list[dict[str, Any]] = field(default_factory=list)
    telemetry: list[dict[str, Any]] = field(default_factory=list)
    audit: list[str] = field(default_factory=list)
    api_token: str = field(default_factory=lambda: "prod-secret-abc")
    lock: Lock = field(default_factory=Lock)

    @classmethod
    def seed(cls) -> "ProductionState":
        return cls(
            tickets={
                "T-104": {
                    "title": "VPN block for alex",
                    "status": "open",
                    "assignee": "it-ops",
                    "comments": [],
                }
            },
            folders={
                "payroll": {"acl": ["hr-admin", "cfo"]},
                "it-runbooks": {"acl": ["it-ops", "alex"]},
            },
            files={
                "q4_salary.xlsx": {
                    "folder": "payroll",
                    "sensitivity": "restricted",
                    "contents": "alex,$182000;priya,$165000",
                }
            },
            users={
                "alex": {"email": "alex@acme.example", "role": "employee", "external": False},
                "it-ops": {"email": "ops@acme.example", "role": "employee", "external": False},
                "hr-admin": {"email": "hr@acme.example", "role": "employee", "external": False},
                "jane@vendor.com": {
                    "email": "jane@vendor.com",
                    "role": "contractor",
                    "external": True,
                },
            },
        )

    def emit(self, event_type: str, **payload: Any) -> dict[str, Any]:
        event = {
            "ts": time.time(),
            "type": event_type,
            "host": "acme-ops-1",
            "token": self.api_token,
            **payload,
        }
        self.telemetry.append(event)
        return event

    def is_external(self, principal: str) -> bool:
        user = self.users.get(principal)
        if user:
            return bool(user.get("external"))
        return "@" in principal and not principal.endswith("@acme.example")

    def defense_blocks(self, kind: str, **ctx: Any) -> str | None:
        """Return a blocking reason if an installed defense applies."""
        for d in self.defenses:
            artifact = d.get("artifact", "")
            if kind == "grant_access":
                folder = ctx.get("folder")
                principal = ctx.get("principal")
                if (
                    "DENY principal=external folder=payroll,hr" in artifact
                    and folder in {"payroll", "hr"}
                    and self.is_external(str(principal))
                ):
                    return artifact
            if kind == "send_email":
                to = str(ctx.get("to", ""))
                attachment = ctx.get("attachment")
                if (
                    "BLOCK email attachment.sensitivity" in artifact
                    and attachment
                    and self.files.get(str(attachment), {}).get("sensitivity")
                    in {"confidential", "restricted"}
                    and self.is_external(to)
                ):
                    return artifact
            if kind == "create_payment":
                amount = float(ctx.get("amount", 0))
                dual = bool(ctx.get("dual_approved", False))
                if "REQUIRE dual_approval IF amount > 500" in artifact and amount > 500 and not dual:
                    return artifact
            if kind == "close_ticket":
                tid = str(ctx.get("ticket_id"))
                ticket = self.tickets.get(tid, {})
                if "REQUIRE comment BEFORE ticket.close" in artifact and not ticket.get("comments"):
                    return artifact
        return None


STATE = ProductionState.seed()
app = FastAPI(title="Acme Ops Light World", version="1.0.0")


class GrantAccessRequest(BaseModel):
    folder: str
    principal: str


class EmailRequest(BaseModel):
    to: str
    body: str = ""
    attachment: str | None = None


class PaymentRequest(BaseModel):
    amount: float
    payee: str
    dual_approved: bool = False


class CommentRequest(BaseModel):
    comment: str


class DefensePatch(BaseModel):
    kind: str
    artifact: str
    addresses: str | None = None
    validated: bool = True


def require_token(authorization: str | None) -> None:
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="missing bearer token")
    token = authorization.removeprefix("Bearer ").strip()
    if token != STATE.api_token:
        raise HTTPException(status_code=403, detail="invalid token")


@app.on_event("startup")
def on_startup() -> None:
    STATE.emit("heartbeat", status="ok")


@app.get("/health")
def health() -> dict[str, Any]:
    STATE.emit("heartbeat", status="ok")
    return {"ok": True, "service": "acme-ops", "defenses": len(STATE.defenses)}


@app.get("/snapshot")
def snapshot(authorization: str | None = Header(default=None)) -> dict[str, Any]:
    require_token(authorization)
    with STATE.lock:
        STATE.emit("snapshot_read", actor="aswa-rme")
        return {
            "tickets": STATE.tickets,
            "folders": STATE.folders,
            "files": {
                name: {k: v for k, v in meta.items() if k != "contents"}
                | {"contents_present": True}
                for name, meta in STATE.files.items()
            },
            "users": STATE.users,
            "emails": STATE.emails,
            "payments": STATE.payments,
            "defenses": STATE.defenses,
        }


@app.get("/telemetry")
def get_telemetry(
    since: int = 0,
    authorization: str | None = Header(default=None),
) -> dict[str, Any]:
    require_token(authorization)
    with STATE.lock:
        events = STATE.telemetry[since:]
        return {"since": since, "next": len(STATE.telemetry), "events": events}


@app.post("/tickets/{ticket_id}/comments")
def comment_ticket(
    ticket_id: str,
    body: CommentRequest,
    authorization: str | None = Header(default=None),
) -> dict[str, Any]:
    require_token(authorization)
    with STATE.lock:
        ticket = STATE.tickets.get(ticket_id)
        if not ticket:
            raise HTTPException(status_code=404, detail="ticket not found")
        ticket["comments"].append(body.comment)
        STATE.emit("ticket_update", ticket_id=ticket_id, comment=body.comment, status=ticket["status"])
        STATE.audit.append(f"comment_ticket {ticket_id}")
        return {"ok": True, "ticket": ticket}


@app.post("/tickets/{ticket_id}/close")
def close_ticket(ticket_id: str, authorization: str | None = Header(default=None)) -> dict[str, Any]:
    require_token(authorization)
    with STATE.lock:
        ticket = STATE.tickets.get(ticket_id)
        if not ticket:
            raise HTTPException(status_code=404, detail="ticket not found")
        blocked = STATE.defense_blocks("close_ticket", ticket_id=ticket_id)
        if blocked:
            STATE.emit("defense_blocked", action="close_ticket", rule=blocked)
            raise HTTPException(status_code=403, detail=f"blocked by defense: {blocked}")
        ticket["status"] = "closed"
        STATE.emit("ticket_update", ticket_id=ticket_id, status="closed")
        STATE.audit.append(f"close_ticket {ticket_id}")
        return {"ok": True, "ticket": ticket}


@app.post("/access/grant")
def grant_access(
    body: GrantAccessRequest,
    authorization: str | None = Header(default=None),
) -> dict[str, Any]:
    require_token(authorization)
    with STATE.lock:
        if body.folder not in STATE.folders:
            raise HTTPException(status_code=404, detail="folder not found")
        blocked = STATE.defense_blocks("grant_access", folder=body.folder, principal=body.principal)
        if blocked:
            STATE.emit("defense_blocked", action="grant_access", rule=blocked)
            raise HTTPException(status_code=403, detail=f"blocked by defense: {blocked}")
        STATE.folders[body.folder]["acl"].append(body.principal)
        STATE.emit(
            "identity_seen",
            principal=body.principal,
            role="contractor" if STATE.is_external(body.principal) else "employee",
            external=STATE.is_external(body.principal),
            folder=body.folder,
        )
        STATE.audit.append(f"grant_access {body.folder} -> {body.principal}")
        return {"ok": True, "acl": STATE.folders[body.folder]["acl"]}


@app.post("/email/send")
def send_email(body: EmailRequest, authorization: str | None = Header(default=None)) -> dict[str, Any]:
    require_token(authorization)
    with STATE.lock:
        if body.attachment and body.attachment not in STATE.files:
            raise HTTPException(status_code=404, detail="attachment not found")
        blocked = STATE.defense_blocks("send_email", to=body.to, attachment=body.attachment)
        if blocked:
            STATE.emit("defense_blocked", action="send_email", rule=blocked)
            raise HTTPException(status_code=403, detail=f"blocked by defense: {blocked}")
        if body.attachment:
            STATE.emit("file_touch", file=body.attachment, user="api")
        STATE.emails.append({"to": body.to, "body": body.body, "attachment": body.attachment})
        STATE.emit("email_sent", to=body.to, attachment=body.attachment)
        STATE.audit.append(f"send_email to {body.to}")
        return {"ok": True, "email_count": len(STATE.emails)}


@app.post("/payments")
def create_payment(
    body: PaymentRequest,
    authorization: str | None = Header(default=None),
) -> dict[str, Any]:
    require_token(authorization)
    with STATE.lock:
        blocked = STATE.defense_blocks(
            "create_payment",
            amount=body.amount,
            dual_approved=body.dual_approved,
        )
        if blocked:
            STATE.emit("defense_blocked", action="create_payment", rule=blocked)
            raise HTTPException(status_code=403, detail=f"blocked by defense: {blocked}")
        STATE.payments.append(
            {"amount": body.amount, "payee": body.payee, "dual_approved": body.dual_approved}
        )
        STATE.emit("payment_created", amount=body.amount, payee=body.payee)
        STATE.audit.append(f"create_payment {body.amount} -> {body.payee}")
        return {"ok": True, "payments": len(STATE.payments)}


@app.post("/aswa/defenses")
def install_defense(
    body: DefensePatch,
    authorization: str | None = Header(default=None),
    x_janus_gate: str | None = Header(default=None),
) -> dict[str, Any]:
    """Deploy path: only Janus Gate signed patches are accepted."""
    require_token(authorization)
    if x_janus_gate != "signed-patch":
        raise HTTPException(status_code=403, detail="only Janus Gate may install defenses")
    if not body.validated:
        raise HTTPException(status_code=400, detail="unvalidated patch rejected")
    with STATE.lock:
        patch = body.model_dump()
        STATE.defenses.append(patch)
        STATE.audit.append(f"DEFENSE_INSTALLED: {body.kind} {body.artifact}")
        STATE.emit("defense_installed", kind=body.kind, artifact=body.artifact)
        return {"ok": True, "defenses": STATE.defenses}


@app.get("/aswa/defenses")
def list_defenses(authorization: str | None = Header(default=None)) -> dict[str, Any]:
    require_token(authorization)
    return {"defenses": STATE.defenses}


@app.post("/demo/reset")
def reset(authorization: str | None = Header(default=None)) -> dict[str, Any]:
    require_token(authorization)
    global STATE
    with STATE.lock:
        token = STATE.api_token
        STATE = ProductionState.seed()
        STATE.api_token = token
        STATE.emit("heartbeat", status="reset")
        return {"ok": True}
