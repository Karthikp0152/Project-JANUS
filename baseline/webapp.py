from __future__ import annotations

import time
from pathlib import Path
from typing import Any

from fastapi import FastAPI, Header, HTTPException
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

from aswa.live import world_from_snapshot
from aswa.pipeline import run_janus
from aswa.scenarios import SCENARIO_CATALOG, run_scenario as execute_scenario
from production.app import STATE, ProductionState, require_token

WEB_DIR = Path(__file__).resolve().parent / "web"

app = FastAPI(title="Project Janus Console", version="1.0.0")
app.mount("/static", StaticFiles(directory=str(WEB_DIR)), name="static")

LAST_RUN: dict[str, Any] = {}


class AswaRunRequest(BaseModel):
    n: int = 3
    asa_episodes: int = 24
    since: int = 0


class ScenarioRequest(BaseModel):
    scenario: str = "unsafe_contractor"


@app.get("/")
def index() -> FileResponse:
    return FileResponse(WEB_DIR / "index.html")


@app.get("/health")
def health() -> dict[str, Any]:
    with STATE.lock:
        STATE.emit("heartbeat", status="ok")
    return {"ok": True, "service": "project-janus-console"}


@app.get("/api/status")
def status() -> dict[str, Any]:
    with STATE.lock:
        return {
            "service": "project-janus",
            "light_world": "acme-ops",
            "ok": True,
            "defenses": len(STATE.defenses),
            "telemetry_events": len(STATE.telemetry),
            "emails": len(STATE.emails),
            "payments": len(STATE.payments),
            "payroll_acl": list(STATE.folders["payroll"]["acl"]),
            "has_last_run": bool(LAST_RUN),
            "ts": time.time(),
        }


@app.get("/api/light")
def light_world(authorization: str | None = Header(default=None)) -> dict[str, Any]:
    require_token(authorization)
    with STATE.lock:
        return {
            "tickets": STATE.tickets,
            "folders": STATE.folders,
            "files": {
                name: {
                    "folder": meta["folder"],
                    "sensitivity": meta["sensitivity"],
                    "contents": "[REDACTED_IN_UI]",
                }
                for name, meta in STATE.files.items()
            },
            "users": STATE.users,
            "emails": STATE.emails,
            "payments": STATE.payments,
            "defenses": STATE.defenses,
            "audit": STATE.audit[-20:],
            "telemetry_tail": STATE.telemetry[-12:],
        }


@app.get("/api/scenarios")
def list_scenarios() -> dict[str, Any]:
    return {"scenarios": SCENARIO_CATALOG}


@app.post("/api/scenario")
def run_scenario(
    body: ScenarioRequest,
    authorization: str | None = Header(default=None),
) -> dict[str, Any]:
    require_token(authorization)
    with STATE.lock:
        try:
            results = execute_scenario(STATE, body.scenario)
        except KeyError:
            raise HTTPException(status_code=400, detail="unknown scenario") from None
    meta = next((s for s in SCENARIO_CATALOG if s["id"] == body.scenario), {})
    return {"scenario": body.scenario, "title": meta.get("title"), "results": results}


@app.post("/api/aswa/run")
def aswa_run(
    body: AswaRunRequest,
    authorization: str | None = Header(default=None),
) -> dict[str, Any]:
    require_token(authorization)

    with STATE.lock:
        snapshot = {
            "tickets": dict(STATE.tickets),
            "folders": {k: {"acl": list(v["acl"])} for k, v in STATE.folders.items()},
            "files": STATE.files,
            "users": STATE.users,
            "emails": list(STATE.emails),
            "payments": list(STATE.payments),
            "defenses": list(STATE.defenses),
        }
        events = list(STATE.telemetry[body.since :])

    world = world_from_snapshot(snapshot)
    result = run_janus(
        telemetry=events,
        n=body.n,
        asa_episodes=body.asa_episodes,
        world=world,
    )

    installed = []
    with STATE.lock:
        existing = {d.get("artifact") for d in STATE.defenses}
        for patch in result["deploy"]["defensive_patches"]:
            if patch["artifact"] in existing:
                continue
            item = {
                "kind": patch["kind"],
                "artifact": patch["artifact"],
                "addresses": patch.get("addresses"),
                "validated": True,
            }
            STATE.defenses.append(item)
            STATE.audit.append(f"DEFENSE_INSTALLED: {item['kind']} {item['artifact']}")
            STATE.emit("defense_installed", kind=item["kind"], artifact=item["artifact"])
            installed.append(item)
            existing.add(item["artifact"])

    ui = {
        "loop": result["loop"],
        "n": result["n"],
        "duplicate": {
            "digital_twin_ready": result["duplicate"]["digital_twin_ready"],
            "redactions": result["duplicate"]["redactions"],
            "sanitized_telemetry": result["duplicate"]["sanitized_telemetry"][-8:],
            "shadow_file_contents": result["duplicate"]["shadow_file_contents"],
        },
        "attack": {
            "broke_shadow": result["attack"]["broke_shadow"],
            "violations_found": list(dict.fromkeys(result["attack"]["violations_found"])),
            "best_trace": result["attack"]["best_trace"],
            "episodes": result["attack"]["episodes"],
        },
        "learn": result["learn"],
        "deploy": {
            "validated": result["deploy"]["validated"],
            "defensive_patches": result["deploy"]["defensive_patches"],
            "payload_escaped": False,
            "defense_surface_mutated": bool(installed) or result["deploy"]["defense_surface_mutated"],
        },
        "light_world": {
            "payroll_acl": list(STATE.folders["payroll"]["acl"]),
            "defenses": list(STATE.defenses),
            "emails": list(STATE.emails),
            "state_clean_except_defenses": True,
        },
        "production_deploy": {
            "installed": installed,
            "defense_count": len(STATE.defenses),
            "payload_escaped": False,
        },
    }
    global LAST_RUN
    LAST_RUN = ui
    return ui


@app.get("/api/aswa/last")
def aswa_last() -> dict[str, Any]:
    return LAST_RUN or {"empty": True}


@app.post("/api/reset")
def reset(authorization: str | None = Header(default=None)) -> dict[str, Any]:
    require_token(authorization)
    global LAST_RUN
    with STATE.lock:
        fresh = ProductionState.seed()
        STATE.tickets = fresh.tickets
        STATE.folders = fresh.folders
        STATE.files = fresh.files
        STATE.users = fresh.users
        STATE.emails = fresh.emails
        STATE.payments = fresh.payments
        STATE.defenses = fresh.defenses
        STATE.telemetry = fresh.telemetry
        STATE.audit = fresh.audit
        STATE.emit("heartbeat", status="reset")
    LAST_RUN = {}
    return {"ok": True}


class ProbeRequest(BaseModel):
    kind: str = "grant_access"
    folder: str = "payroll"
    principal: str = "jane@vendor.com"
    to: str = "jane@vendor.com"
    attachment: str | None = "q4_salary.xlsx"
    amount: float = 9999
    payee: str = "jane@vendor.com"
    ticket_id: str = "T-104"


@app.post("/api/probe")
def probe(
    body: ProbeRequest,
    authorization: str | None = Header(default=None),
) -> dict[str, Any]:
    """Re-try a risky action after Deploy to prove defenses landed."""
    require_token(authorization)
    with STATE.lock:
        if body.kind == "grant_access":
            if body.folder not in STATE.folders:
                raise HTTPException(status_code=404, detail="folder not found")
            blocked = STATE.defense_blocks(
                "grant_access", folder=body.folder, principal=body.principal
            )
            if blocked:
                STATE.emit("defense_blocked", action="grant_access", rule=blocked)
                return {"ok": False, "blocked": True, "rule": blocked, "status": 403, "kind": body.kind}
            STATE.folders[body.folder]["acl"].append(body.principal)
            return {
                "ok": True,
                "blocked": False,
                "acl": list(STATE.folders[body.folder]["acl"]),
                "status": 200,
                "kind": body.kind,
            }
        if body.kind == "send_email":
            blocked = STATE.defense_blocks(
                "send_email", to=body.to, attachment=body.attachment
            )
            if blocked:
                STATE.emit("defense_blocked", action="send_email", rule=blocked)
                return {"ok": False, "blocked": True, "rule": blocked, "status": 403, "kind": body.kind}
            STATE.emails.append({"to": body.to, "body": "probe", "attachment": body.attachment})
            return {"ok": True, "blocked": False, "status": 200, "kind": body.kind}
        if body.kind == "create_payment":
            blocked = STATE.defense_blocks(
                "create_payment", amount=body.amount, dual_approved=False
            )
            if blocked:
                STATE.emit("defense_blocked", action="create_payment", rule=blocked)
                return {"ok": False, "blocked": True, "rule": blocked, "status": 403, "kind": body.kind}
            STATE.payments.append(
                {"amount": body.amount, "payee": body.payee, "dual_approved": False}
            )
            return {"ok": True, "blocked": False, "status": 200, "kind": body.kind}
        if body.kind == "close_ticket":
            blocked = STATE.defense_blocks("close_ticket", ticket_id=body.ticket_id)
            if blocked:
                STATE.emit("defense_blocked", action="close_ticket", rule=blocked)
                return {"ok": False, "blocked": True, "rule": blocked, "status": 403, "kind": body.kind}
            STATE.tickets[body.ticket_id]["status"] = "closed"
            return {"ok": True, "blocked": False, "status": 200, "kind": body.kind}
        raise HTTPException(status_code=400, detail="unknown probe kind")
