#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import subprocess
import sys
import time
from pathlib import Path

import httpx

from aswa.live import AcmeProductionClient, run_aswa_against_production


def wait_healthy(base_url: str, timeout: float = 20.0) -> None:
    deadline = time.time() + timeout
    last_err = ""
    while time.time() < deadline:
        try:
            r = httpx.get(f"{base_url}/health", timeout=1.0)
            if r.status_code == 200:
                return
            last_err = f"HTTP {r.status_code}"
        except Exception as exc:
            last_err = str(exc)
        time.sleep(0.25)
    raise RuntimeError(f"production API not healthy at {base_url}: {last_err}")


def main() -> None:
    parser = argparse.ArgumentParser(description="Run Project Janus against live Acme Ops API")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8765)
    parser.add_argument("--n", type=int, default=3)
    parser.add_argument("--asa-episodes", type=int, default=25)
    parser.add_argument("--output", default="examples/last_live_run.json")
    args = parser.parse_args()

    base_url = f"http://{args.host}:{args.port}"
    root = Path(__file__).resolve().parent
    print(f"Starting Acme Ops Light World at {base_url}")
    proc = subprocess.Popen(
        [
            sys.executable,
            "-m",
            "uvicorn",
            "production.app:app",
            "--host",
            args.host,
            "--port",
            str(args.port),
            "--log-level",
            "warning",
        ],
        cwd=str(root),
    )

    try:
        wait_healthy(base_url)
        client = AcmeProductionClient(base_url)
        client.reset()

        print("\n[1] Production traffic (Light World)")
        client.comment("T-104", "VPN work in progress for alex")
        grant = client.grant_access("payroll", "jane@vendor.com")
        email = client.send_email(
            "jane@vendor.com",
            body="Q4 packet",
            attachment="q4_salary.xlsx",
        )
        pay = client.create_payment(9999, "jane@vendor.com", dual_approved=False)
        print(f"  pre-patch grant_access: HTTP {grant.status_code}")
        print(f"  pre-patch send_email:   HTTP {email.status_code}")
        print(f"  pre-patch payment:      HTTP {pay.status_code}")

        print("\n[2] ASWA loop on live telemetry")
        print("  Ingest & Sanitize -> Hydrate & Clone -> Synthesize & Attack -> Compile & Patch")
        result = run_aswa_against_production(
            base_url,
            n=args.n,
            asa_episodes=args.asa_episodes,
            since=0,
        )
        print(f"  telemetry ingested: {result['production']['telemetry_events_ingested']}")
        print(f"  secrets redacted in twin: {'prod-secret-abc' not in json.dumps(result['duplicate'])}")
        print(f"  shadow broken: {result['attack']['broke_shadow']}")
        for item in result["learn"]["vulnerabilities_logged"]:
            print(f"  learned: {item['vulnerability']}")
        for patch in result["deploy"]["defensive_patches"]:
            print(f"  deployed: {patch['kind']} -> {patch['artifact']}")

        print("\n[3] Verify production defense surface mutated")
        defenses = list(result["production"]["defenses_now"])
        client.reset()
        for d in defenses:
            client.install_defense(
                {
                    "kind": d["kind"],
                    "artifact": d["artifact"],
                    "addresses": d.get("addresses"),
                    "validated": True,
                }
            )

        after_grant = client.grant_access("payroll", "jane@vendor.com")
        after_email = client.send_email(
            "jane@vendor.com",
            body="Q4 packet",
            attachment="q4_salary.xlsx",
        )
        after_pay = client.create_payment(9999, "jane@vendor.com", dual_approved=False)
        print(f"  post-patch grant_access: HTTP {after_grant.status_code}")
        print(f"  post-patch send_email:   HTTP {after_email.status_code}")
        print(f"  post-patch payment:      HTTP {after_pay.status_code}")

        hardened = all(
            code == 403
            for code in (after_grant.status_code, after_email.status_code, after_pay.status_code)
        )
        result["verification"] = {
            "pre_patch": {
                "grant": grant.status_code,
                "email": email.status_code,
                "payment": pay.status_code,
            },
            "post_patch": {
                "grant": after_grant.status_code,
                "email": after_email.status_code,
                "payment": after_pay.status_code,
            },
            "production_hardened": hardened,
        }
        print(f"  production hardened: {hardened}")

        out = Path(args.output)
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(json.dumps(result, indent=2), encoding="utf-8")
        print(f"\nFull JSON written to: {out}")
        if not hardened:
            raise SystemExit(1)
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()


if __name__ == "__main__":
    main()
