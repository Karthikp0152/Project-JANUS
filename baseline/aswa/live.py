from __future__ import annotations

from typing import Any

import httpx

from aswa.pipeline import run_janus
from aswa.world import EnterpriseWorld


class AcmeProductionClient:
    def __init__(self, base_url: str, token: str = "prod-secret-abc") -> None:
        self.base_url = base_url.rstrip("/")
        self.headers = {"Authorization": f"Bearer {token}"}

    def health(self) -> dict[str, Any]:
        return httpx.get(f"{self.base_url}/health", timeout=10.0).json()

    def snapshot(self) -> dict[str, Any]:
        r = httpx.get(f"{self.base_url}/snapshot", headers=self.headers, timeout=10.0)
        r.raise_for_status()
        return r.json()

    def telemetry(self, since: int = 0) -> dict[str, Any]:
        r = httpx.get(
            f"{self.base_url}/telemetry",
            params={"since": since},
            headers=self.headers,
            timeout=10.0,
        )
        r.raise_for_status()
        return r.json()

    def install_defense(self, defense: dict[str, Any]) -> dict[str, Any]:
        headers = {**self.headers, "X-Janus-Gate": "signed-patch"}
        r = httpx.post(
            f"{self.base_url}/aswa/defenses",
            headers=headers,
            json=defense,
            timeout=10.0,
        )
        r.raise_for_status()
        return r.json()

    def grant_access(self, folder: str, principal: str) -> httpx.Response:
        return httpx.post(
            f"{self.base_url}/access/grant",
            headers=self.headers,
            json={"folder": folder, "principal": principal},
            timeout=10.0,
        )

    def send_email(self, to: str, body: str = "", attachment: str | None = None) -> httpx.Response:
        return httpx.post(
            f"{self.base_url}/email/send",
            headers=self.headers,
            json={"to": to, "body": body, "attachment": attachment},
            timeout=10.0,
        )

    def create_payment(self, amount: float, payee: str, dual_approved: bool = False) -> httpx.Response:
        return httpx.post(
            f"{self.base_url}/payments",
            headers=self.headers,
            json={"amount": amount, "payee": payee, "dual_approved": dual_approved},
            timeout=10.0,
        )

    def comment(self, ticket_id: str, comment: str) -> httpx.Response:
        return httpx.post(
            f"{self.base_url}/tickets/{ticket_id}/comments",
            headers=self.headers,
            json={"comment": comment},
            timeout=10.0,
        )

    def reset(self) -> dict[str, Any]:
        r = httpx.post(f"{self.base_url}/demo/reset", headers=self.headers, timeout=10.0)
        r.raise_for_status()
        return r.json()


def world_from_snapshot(snapshot: dict[str, Any]) -> EnterpriseWorld:
    files = {}
    for name, meta in snapshot.get("files", {}).items():
        files[name] = {
            "folder": meta.get("folder", "unknown"),
            "sensitivity": meta.get("sensitivity", "internal"),
            "contents": "[LIVE_CONTENTS_OMITTED]",
        }
    if "q4_salary.xlsx" in files:
        files["q4_salary.xlsx"]["contents"] = "alex,$182000;priya,$165000"
        files["q4_salary.xlsx"]["sensitivity"] = "restricted"

    return EnterpriseWorld(
        tickets=snapshot.get("tickets", {}),
        folders=snapshot.get("folders", {}),
        files=files,
        users=snapshot.get("users", {}),
        emails=list(snapshot.get("emails", [])),
        payments=list(snapshot.get("payments", [])),
        defenses=list(snapshot.get("defenses", [])),
    )


def run_aswa_against_production(
    base_url: str,
    token: str = "prod-secret-abc",
    n: int = 3,
    asa_episodes: int = 20,
    since: int = 0,
) -> dict[str, Any]:
    """
    Blueprint pipeline against live Acme API:
    Ingest & Sanitize → Hydrate & Clone → Synthesize & Attack → Compile & Patch
    """
    client = AcmeProductionClient(base_url, token=token)
    snap = client.snapshot()
    tel = client.telemetry(since=since)
    world = world_from_snapshot(snap)

    result = run_janus(
        telemetry=tel["events"],
        n=n,
        asa_episodes=asa_episodes,
        world=world,
    )

    deployed = []
    for patch in result["deploy"]["defensive_patches"]:
        payload = {
            "kind": patch["kind"],
            "artifact": patch["artifact"],
            "addresses": patch.get("addresses"),
            "validated": True,
        }
        resp = client.install_defense(payload)
        deployed.append(resp)

    result["production"] = {
        "base_url": base_url,
        "telemetry_events_ingested": len(tel["events"]),
        "telemetry_next_index": tel["next"],
        "patches_pushed": deployed,
        "defenses_now": client.snapshot().get("defenses", []),
    }
    return result
