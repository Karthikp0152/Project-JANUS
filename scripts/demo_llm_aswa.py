#!/usr/bin/env python3
from __future__ import annotations



import argparse

import json

from pathlib import Path



from aswa.agents_llm import propose_shadow_attack_plan, write_operator_briefing

from aswa.llm import llm_enabled

from aswa.pipeline import run_janus

from aswa.world import EnterpriseWorld





def main() -> None:

    parser = argparse.ArgumentParser(description="OpenAI LLM enhanced Project Janus demo")

    parser.add_argument("--input", default="examples/test_unsafe.json")

    parser.add_argument("--output", default="examples/last_llm_run.json")

    parser.add_argument("--n", type=int, default=3)

    args = parser.parse_args()



    if not llm_enabled():

        raise SystemExit("No OPENAI_API_KEY in .env")



    payload = json.loads(Path(args.input).read_text(encoding="utf-8"))

    telemetry = payload["telemetry"]

    n = int(payload.get("n", args.n))



    print("=== OpenAI LLM Adversary (catalog-bounded shadow plan) ===")

    llm_attack = propose_shadow_attack_plan(telemetry, n=n)

    print(json.dumps({k: v for k, v in llm_attack.items() if k != "raw"}, indent=2)[:1200])



    print("\n=== Full ASWA loop with OpenAI LLM Learn rationales + briefing ===")

    result = run_janus(telemetry=telemetry, n=n, asa_episodes=24)



    shadow = EnterpriseWorld.demo().snapshot()

    for meta in shadow.files.values():

        meta["contents"] = "[SANITIZED]"

    llm_trace = []

    if llm_attack.get("plan"):

        for step, action in enumerate(llm_attack["plan"], start=1):

            shadow.execute(action)

            llm_trace.append({"step": step, "action": action, "violations_so_far": list(shadow.violations)})



    briefing = write_operator_briefing(result)



    out = {

        "openai_llm": {

            "adversary": "Propose N-step policy probes from telemetry using only ACTION_CATALOG ids.",

            "learn": "Attach operator-facing rationales to each designed countermeasure.",

            "briefing": "Summarize the ASWA loop for a security engineer.",

        },

        "llm_adversary": llm_attack,

        "llm_adversary_shadow_trace": llm_trace,

        "llm_adversary_violations": shadow.violations,

        "aswa": {

            "learn": result.get("learn"),

            "deploy": result.get("deploy"),

            "attack": {

                "broke_shadow": result.get("attack", {}).get("broke_shadow"),

                "violations_found": result.get("attack", {}).get("violations_found"),

            },

        },

        "operator_briefing": briefing,

        "baseline_q_learning_still_used": True,

        "note": "Q-learning ASA remains the graded baseline. OpenAI LLM roles are additive upgrades.",

    }

    Path(args.output).write_text(json.dumps(out, indent=2), encoding="utf-8")



    print("\n--- Learn countermeasure sample ---")

    for item in result.get("learn", {}).get("countermeasures_designed", [])[:2]:

        print(f"* {item['kind']}: {item['artifact']}")

        if item.get("llm"):

            print(f"  rationale: {item['llm'].get('rationale', '')[:300]}")



    print("\n--- Operator briefing ---")

    print(briefing.get("briefing", ""))

    print(f"\nWrote {args.output}")





if __name__ == "__main__":

    main()


