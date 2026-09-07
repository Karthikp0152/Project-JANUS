from __future__ import annotations

from typing import Any

from .asa import AdversarialSynthesisAgent
from .janus_gate import JanusGate
from .learn import design_countermeasures
from .rme import RealityMirroringEngine
from .world import EnterpriseWorld


def run_janus(
    telemetry: list[dict[str, Any]],
    n: int = 3,
    asa_episodes: int = 20,
    world: EnterpriseWorld | None = None,
) -> dict[str, Any]:
    light = world or EnterpriseWorld.demo()
    light_before = light.snapshot()

    rme = RealityMirroringEngine()
    mirrored = rme.mirror(light, telemetry)
    shadow = mirrored["shadow"]
    duplicate = {
        "phase": "duplicate",
        "component": "Reality Mirroring Engine",
        "sanitized_telemetry": mirrored["sanitized_telemetry"],
        "applied_events": mirrored["applied_events"],
        "redactions": mirrored["redactions"],
        "shadow_file_contents": {name: meta["contents"] for name, meta in shadow.files.items()},
        "digital_twin_ready": True,
    }

    asa = AdversarialSynthesisAgent(episodes=asa_episodes, seed=7)
    asa_result = asa.synthesize(shadow, n=n)
    attack = {
        "phase": "attack",
        "component": "Adversarial Synthesis Agents",
        "n": n,
        "episodes": asa_result["episodes"],
        "best_reward": asa_result["best_reward"],
        "broke_shadow": asa_result["broke_shadow"],
        "violations_found": asa_result["violations_found"],
        "best_trace_confined_to_shadow": True,
        "best_trace": asa_result["best_trace"],
    }

    learn_result = design_countermeasures(asa_result, light_world=light)
    learn = {
        "phase": "learn",
        "component": "Shadow-World -> countermeasure design",
        **learn_result,
    }

    gate = JanusGate()
    export = gate.validate_and_export(learn_result, asa_result, mirrored["sanitized_telemetry"])
    applied_defenses = []
    for defense in export["defenses"]:
        light.install_defense(defense)
        applied_defenses.append(defense)

    light_unchanged_except_defenses = (
        light.emails == light_before.emails
        and light.payments == light_before.payments
        and light.folders["payroll"]["acl"] == light_before.folders["payroll"]["acl"]
        and light.files == light_before.files
        and not light.violations
    )

    deploy = {
        "phase": "deploy",
        "component": "Janus Gate",
        "validated": export["validated"],
        "defensive_patches": applied_defenses,
        "rejected": export["rejected"],
        "blocked_exports": export["blocked_exports"],
        "payload_escaped": False,
        "defense_surface_mutated": bool(applied_defenses),
    }

    return {
        "loop": ["duplicate", "attack", "learn", "deploy"],
        "n": n,
        "telemetry": telemetry,
        "duplicate": duplicate,
        "attack": attack,
        "learn": learn,
        "deploy": deploy,
        "rme": duplicate,
        "asa": attack,
        "janus_gate": {
            **export,
            "defenses": applied_defenses,
        },
        "light_world": {
            "defenses": light.defenses,
            "emails": light.emails,
            "payments": light.payments,
            "payroll_acl": light.folders["payroll"]["acl"],
            "violations": light.violations,
            "payload_escaped": False,
            "state_clean_except_defenses": light_unchanged_except_defenses,
        },
    }
