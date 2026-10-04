from aswa.janus_gate import JanusGate
from aswa.pipeline import run_janus
from aswa.world import EnterpriseWorld


UNSAFE_TELEMETRY = [
    {"type": "heartbeat", "host": "erp-1", "token": "prod-secret-abc", "status": "ok"},
    {
        "type": "identity_seen",
        "principal": "jane@vendor.com",
        "role": "contractor",
        "external": True,
    },
    {"type": "file_touch", "file": "q4_salary.xlsx", "user": "hr-admin"},
]

SAFE_TELEMETRY = [
    {"type": "heartbeat", "host": "it-ops-1", "token": "prod-secret-abc", "status": "ok"},
    {
        "type": "ticket_update",
        "ticket_id": "T-104",
        "status": "open",
        "comment": "VPN block lifted for alex",
    },
]


def test_duplicate_redacts_secrets_and_file_bodies():
    result = run_janus(UNSAFE_TELEMETRY, n=3)
    blob = str(result["duplicate"])
    assert "prod-secret-abc" not in blob
    assert "[REDACTED]" in blob
    assert result["duplicate"]["shadow_file_contents"]["q4_salary.xlsx"] == "[SANITIZED]"
    assert result["duplicate"]["digital_twin_ready"] is True


def test_attack_breaks_shadow_but_not_light_world():
    light = EnterpriseWorld.demo()
    result = run_janus(UNSAFE_TELEMETRY, n=3, world=light)
    assert result["attack"]["broke_shadow"] is True
    assert result["deploy"]["payload_escaped"] is False
    assert result["light_world"]["emails"] == []
    assert "jane@vendor.com" not in light.folders["payroll"]["acl"]
    assert light.violations == []


def test_learn_designs_countermeasures_when_attack_succeeds():
    result = run_janus(UNSAFE_TELEMETRY, n=3)
    assert result["learn"]["attack_succeeded"] is True
    assert result["learn"]["vulnerabilities_logged"]
    assert result["learn"]["countermeasures_designed"]


def test_deploy_validates_and_mutates_defense_surface_only():
    result = run_janus(UNSAFE_TELEMETRY, n=3)
    assert result["deploy"]["validated"] is True
    assert result["deploy"]["defensive_patches"]
    assert result["deploy"]["defense_surface_mutated"] is True
    assert JanusGate().would_allow_payload(result["attack"]["best_trace"]) is False
    assert result["light_world"]["defenses"] == result["deploy"]["defensive_patches"]
    assert result["light_world"]["state_clean_except_defenses"] is True


def test_loop_order():
    result = run_janus(SAFE_TELEMETRY, n=3)
    assert result["loop"] == ["duplicate", "attack", "learn", "deploy"]
    assert result["light_world"]["payload_escaped"] is False
