from __future__ import annotations

import json
import re
from typing import Any

from .asa import ACTION_CATALOG
from .llm import chat, get_model, llm_enabled


def _extract_json(text: str) -> Any:
    text = text.strip()
    if text.startswith("```"):
        text = re.sub(r"^```(?:json)?\s*", "", text)
        text = re.sub(r"\s*```$", "", text)
    return json.loads(text)


def propose_shadow_attack_plan(
    telemetry: list[dict[str, Any]],
    n: int = 3,
) -> dict[str, Any]:
    catalog = [{"id": a["id"], "tool": a["tool"], "args": a["args"]} for a in ACTION_CATALOG]
    by_id = {a["id"]: a for a in ACTION_CATALOG}

    if not llm_enabled():
        return {"llm_used": False, "plan": [], "reason": "no API key"}

    prompt = {
        "task": (
            "You are an Adversarial Synthesis Agent inside Project Janus. "
            "You operate ONLY in a Shadow-World simulator. "
            "Choose exactly N action ids from the catalog to stress enterprise policy. "
            "Prefer multi-step policy breaks relevant to the telemetry. "
            "Return JSON only."
        ),
        "n": n,
        "telemetry": telemetry[-12:],
        "catalog": catalog,
        "output_schema": {"action_ids": ["catalog_id_1", "catalog_id_2", "catalog_id_3"]},
    }
    raw = chat(
        [
            {
                "role": "system",
                "content": (
                    "Return strict JSON. Use only provided catalog ids. "
                    "Do not invent tools, payloads, exploits, or network attacks."
                ),
            },
            {"role": "user", "content": json.dumps(prompt)},
        ],
        temperature=0.3,
    )
    try:
        data = _extract_json(raw)
        ids = list(data.get("action_ids") or [])[:n]
    except Exception as exc:
        return {"llm_used": True, "plan": [], "error": str(exc), "raw": raw, "model": get_model()}

    plan = []
    for action_id in ids:
        if action_id in by_id:
            item = dict(by_id[action_id])
            item["role"] = "llm_adversary"
            plan.append(item)
    i = 0
    while len(plan) < n:
        item = dict(ACTION_CATALOG[i % len(ACTION_CATALOG)])
        item["role"] = "llm_adversary_pad"
        plan.append(item)
        i += 1

    return {"llm_used": True, "plan": plan[:n], "model": get_model(), "raw_ids": ids}


def write_operator_briefing(aswa_result: dict[str, Any]) -> dict[str, Any]:
    if not llm_enabled():
        return {"llm_used": False, "briefing": "OpenAI LLM disabled. See structured ASWA JSON result."}

    compact = {
        "loop": aswa_result.get("loop"),
        "duplicate": {
            "redactions": aswa_result.get("duplicate", {}).get("redactions"),
            "twin_ready": aswa_result.get("duplicate", {}).get("digital_twin_ready"),
        },
        "attack": {
            "broke_shadow": aswa_result.get("attack", {}).get("broke_shadow"),
            "violations": aswa_result.get("attack", {}).get("violations_found"),
        },
        "learn": {
            "countermeasures": [
                {
                    "kind": c.get("kind"),
                    "artifact": c.get("artifact"),
                    "addresses": c.get("addresses"),
                }
                for c in aswa_result.get("learn", {}).get("countermeasures_designed", [])
            ]
        },
        "deploy": {
            "validated": aswa_result.get("deploy", {}).get("validated"),
            "payload_escaped": aswa_result.get("deploy", {}).get("payload_escaped"),
            "patches": aswa_result.get("deploy", {}).get("defensive_patches"),
        },
    }
    text = chat(
        [
            {
                "role": "system",
                "content": (
                    "You are a defensive security analyst for Project Janus. "
                    "Write a clear 5-8 sentence operator briefing. "
                    "No offensive instructions. Focus on containment and deployed defenses."
                ),
            },
            {"role": "user", "content": json.dumps(compact)},
        ],
        temperature=0.2,
    )
    return {"llm_used": True, "briefing": text, "model": get_model()}
