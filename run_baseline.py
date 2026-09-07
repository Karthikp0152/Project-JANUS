#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
from pathlib import Path

from aswa.pipeline import run_janus


def main() -> None:
    parser = argparse.ArgumentParser(description="Run the Project Janus baseline on one telemetry case.")
    parser.add_argument(
        "--input",
        default="examples/test_unsafe.json",
        help="JSON with telemetry, n, and optional asa_episodes",
    )
    parser.add_argument("--output", default="examples/last_run.json")
    args = parser.parse_args()

    payload = json.loads(Path(args.input).read_text(encoding="utf-8"))
    result = run_janus(
        telemetry=payload["telemetry"],
        n=int(payload.get("n", 3)),
        asa_episodes=int(payload.get("asa_episodes", 20)),
    )
    secrets_ok = "prod-secret-abc" not in json.dumps(result["duplicate"])
    result["checks"] = {
        "light_world_clean": result["light_world"]["state_clean_except_defenses"],
        "payload_escaped": result["light_world"]["payload_escaped"],
        "secrets_absent_from_shadow": secrets_ok,
        "defenses_exported": bool(result["deploy"]["defensive_patches"]),
    }

    Path(args.output).parent.mkdir(parents=True, exist_ok=True)
    Path(args.output).write_text(json.dumps(result, indent=2), encoding="utf-8")

    print(f"Input file: {args.input}")
    print(f"Loop: {' -> '.join(result['loop'])}")
    print(f"Horizon N (Attack steps in Shadow World): {result['n']}")
    print()
    print("[1] DUPLICATE — Reality Mirroring Engine")
    for event in result["duplicate"]["sanitized_telemetry"]:
        print(f"  telemetry: {event}")
    print(f"  redactions: {result['duplicate']['redactions']}")
    print(f"  digital twin ready: {result['duplicate']['digital_twin_ready']}")
    print()
    print("[2] ATTACK — Adversarial Agents vs Shadow-World Sandbox")
    print(f"  broke shadow: {result['attack']['broke_shadow']}")
    print(f"  violations: {result['attack']['violations_found'] or 'none'}")
    print()
    print("[3] LEARN — log vulnerability and design countermeasure")
    print(f"  attack succeeded: {result['learn']['attack_succeeded']}")
    for item in result["learn"]["vulnerabilities_logged"]:
        print(f"  vulnerability: {item['vulnerability']}")
    for item in result["learn"]["countermeasures_designed"]:
        print(f"  designed: {item['kind']} -> {item['artifact']}")
    if not result["learn"]["countermeasures_designed"]:
        print("  designed: none")
    print()
    print("[4] DEPLOY — Janus Gate validates and pushes defensive patches")
    print(f"  validated: {result['deploy']['validated']}")
    if result["deploy"]["defensive_patches"]:
        for defense in result["deploy"]["defensive_patches"]:
            print(f"  patch: {defense['kind']}: {defense['artifact']}")
    else:
        print("  patch: none")
    print(f"  payload escaped: {result['deploy']['payload_escaped']}")
    print(f"  defense surface mutated: {result['deploy']['defense_surface_mutated']}")
    print(f"  Light World clean except defenses: {result['light_world']['state_clean_except_defenses']}")
    print(f"  payroll ACL unchanged: {result['light_world']['payroll_acl']}")
    print(f"  secrets absent from twin: {secrets_ok}")
    print(f"Full JSON written to: {args.output}")


if __name__ == "__main__":
    main()
