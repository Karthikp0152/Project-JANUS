"""Tests for janus/llm_client.py. No network: injected transports and FakeLLM only."""
import json

import pytest

from janus import llm_client
from janus.llm_client import FakeLLM, LLMClient, PromptLeak, extract_json, find_leak, validate_json

SCHEMA = {"type": "object", "required": ["ok"], "properties": {"ok": {"type": "boolean"}}}
MESSAGES = [{"role": "user", "content": "hello"}]


class RateLimitError(Exception):
    """Same name as the SDK's error; the client classifies errors by name."""


class Transport:
    def __init__(self, *replies):
        self.replies = list(replies)
        self.calls = []

    def __call__(self, role, model, messages, temperature):
        self.calls.append({"role": role, "model": model, "messages": messages, "temperature": temperature})
        reply = self.replies.pop(0) if len(self.replies) > 1 else self.replies[0]
        if isinstance(reply, Exception):
            raise reply
        return reply, 100, 50


@pytest.fixture(autouse=True)
def env(monkeypatch):
    monkeypatch.setattr(llm_client, "_load_env", lambda: None)
    monkeypatch.setenv("RC_MODEL_PROBE", "probe-model")
    monkeypatch.setenv("RC_MODEL_COMPILE", "compile-model")
    monkeypatch.delenv("RC_API_KEY", raising=False)
    monkeypatch.delenv("RC_BASE_URL", raising=False)
    monkeypatch.delenv("COST_PER_1K_IN", raising=False)
    monkeypatch.delenv("COST_PER_1K_OUT", raising=False)


def call(client, role="probe", messages=MESSAGES, schema=SCHEMA, canaries=()):
    return client.chat_json(role, messages, schema, scenario_id="s-1", canaries=list(canaries))


def make(tmp_path, *replies, **kwargs):
    transport = Transport(*replies)
    sleeps = []
    client = LLMClient(transport=transport, cache_dir=tmp_path, sleep=sleeps.append, **kwargs)
    return client, transport, sleeps


def test_valid_reply_returns_data_and_tokens(tmp_path):
    client, _, _ = make(tmp_path, '{"ok": true}')
    result = call(client)
    assert result == {
        "data": {"ok": True}, "tokens_in": 100, "tokens_out": 50, "cost_usd": 0.0, "cached": False, "error": None,
    }


def test_canary_raises_before_any_call_and_is_not_quoted(tmp_path):
    client, transport, _ = make(tmp_path, '{"ok": true}')
    messages = [{"role": "user", "content": "see CANARY-abc123"}]
    with pytest.raises(PromptLeak) as caught:
        call(client, messages=messages, canaries=["CANARY-abc123"])
    assert transport.calls == []
    assert client.prompt_log == []
    assert "CANARY-abc123" not in str(caught.value)


def test_canary_blocks_a_cache_hit_too(tmp_path):
    messages = [{"role": "user", "content": "see CANARY-abc123"}]
    client, _, _ = make(tmp_path, '{"ok": true}')
    call(client, messages=messages)
    with pytest.raises(PromptLeak):
        call(client, messages=messages, canaries=["CANARY-abc123"])


def test_secret_pattern_blocks_but_redacted_text_passes(tmp_path):
    client, transport, _ = make(tmp_path, '{"ok": true}')
    with pytest.raises(PromptLeak):
        call(client, messages=[{"role": "user", "content": "password=hunter2"}])
    assert transport.calls == []
    assert call(client, messages=[{"role": "user", "content": "password=[REDACTED]"}])["data"] == {"ok": True}


def test_rc_key_in_prompt_blocks_without_quoting_it(tmp_path, monkeypatch):
    monkeypatch.setenv("RC_API_KEY", "rc-private-value")
    client, transport, _ = make(tmp_path, '{"ok": true}')
    with pytest.raises(PromptLeak) as caught:
        call(client, messages=[{"role": "user", "content": "text rc-private-value"}])
    assert transport.calls == []
    assert "rc-private-value" not in str(caught.value)


@pytest.mark.parametrize(
    "text",
    ["https://rc.private.example/v1 is the url", "host='rc.private.example'", "https://rc.private.example/v1/"],
)
def test_base_url_is_found_with_or_without_slash_and_by_host(monkeypatch, text):
    monkeypatch.setenv("RC_BASE_URL", "https://rc.private.example/v1/")
    assert find_leak(text, []) == "RC_BASE_URL"


def test_json_shaped_secret_blocks_the_call(tmp_path):
    client, transport, _ = make(tmp_path, '{"ok": true}')
    content = json.dumps({"password": "hunter2"})
    with pytest.raises(PromptLeak):
        call(client, messages=[{"role": "user", "content": content}])
    assert transport.calls == []


def test_redacted_json_secret_passes(tmp_path):
    client, _, _ = make(tmp_path, '{"ok": true}')
    content = json.dumps({"token": "[REDACTED]", "tokens_in": 5})
    assert call(client, messages=[{"role": "user", "content": content}])["data"] == {"ok": True}


def test_schema_joins_the_first_system_message(tmp_path):
    client, transport, _ = make(tmp_path, '{"ok": true}')
    call(client, messages=[{"role": "system", "content": "Be brief."}, {"role": "user", "content": "hi"}])
    sent = transport.calls[0]["messages"]
    assert [m["role"] for m in sent] == ["system", "user"]
    assert "Be brief." in sent[0]["content"]
    assert "JSON Schema" in sent[0]["content"]


def test_schema_gets_its_own_system_message_when_there_is_none(tmp_path):
    client, transport, _ = make(tmp_path, '{"ok": true}')
    call(client)
    assert [m["role"] for m in transport.calls[0]["messages"]] == ["system", "user"]


def test_retry_shows_the_rejected_reply_and_alternates_roles(tmp_path):
    client, transport, _ = make(tmp_path, "oops", "", '{"ok": true}')
    call(client)
    sent = transport.calls[2]["messages"]
    assert [m["role"] for m in sent] == ["system", "user", "assistant", "user", "assistant", "user"]
    assert sent[2]["content"] == "oops"
    assert sent[4]["content"] == "(empty reply)"


def test_cache_write_failure_keeps_the_reply(tmp_path, monkeypatch):
    def locked(*_):
        raise PermissionError("file is locked")

    monkeypatch.setattr(llm_client.os, "replace", locked)
    client, _, _ = make(tmp_path, '{"ok": true}')
    assert call(client)["data"] == {"ok": True}


def test_cache_hit_is_identical_and_makes_no_call(tmp_path):
    client, transport, _ = make(tmp_path, '{"ok": true}')
    first = call(client)
    second = call(client)
    assert len(transport.calls) == 1
    assert second["cached"] is True
    assert second["data"] == first["data"]
    assert (second["tokens_in"], second["tokens_out"]) == (first["tokens_in"], first["tokens_out"])


def test_cache_survives_a_new_client(tmp_path):
    client, _, _ = make(tmp_path, '{"ok": true}')
    call(client)
    other, transport, _ = make(tmp_path, '{"ok": false}')
    assert call(other)["data"] == {"ok": True}
    assert transport.calls == []


@pytest.mark.parametrize(
    "change",
    [
        {"role": "compile"},
        {"messages": [{"role": "user", "content": "other"}]},
        {"schema": {"type": "object"}},
    ],
)
def test_cache_key_covers_role_messages_and_schema(tmp_path, change):
    client, transport, _ = make(tmp_path, '{"ok": true}')
    call(client)
    call(client, **change)
    assert len(transport.calls) == 2


def test_failed_results_are_not_cached(tmp_path):
    client, transport, _ = make(tmp_path, "bad", "bad", "bad", '{"ok": true}')
    assert call(client)["data"] is None
    assert call(client)["data"] == {"ok": True}
    assert len(transport.calls) == 4


def test_use_cache_false_always_calls(tmp_path):
    client, transport, _ = make(tmp_path, '{"ok": true}', use_cache=False)
    call(client)
    call(client)
    assert len(transport.calls) == 2
    assert list(tmp_path.iterdir()) == []


def test_schema_failure_feeds_the_error_back(tmp_path):
    client, transport, _ = make(tmp_path, '{"ok": "yes"}', '{"ok": true}')
    result = call(client)
    assert result["data"] == {"ok": True}
    assert "$.ok: expected boolean" in transport.calls[1]["messages"][-1]["content"]
    assert (result["tokens_in"], result["tokens_out"]) == (200, 100)


def test_gives_up_after_two_retries(tmp_path):
    client, transport, _ = make(tmp_path, "not json")
    result = call(client)
    assert len(transport.calls) == 3
    assert result["data"] is None
    assert "not valid JSON" in result["error"]
    assert result["tokens_in"] == 300


def test_rate_limit_backs_off_exponentially(tmp_path):
    client, transport, sleeps = make(tmp_path, RateLimitError(), RateLimitError(), '{"ok": true}')
    assert call(client)["data"] == {"ok": True}
    assert sleeps == [1.0, 2.0]
    assert len(transport.calls) == 3


def test_rate_limit_gives_up_with_an_error(tmp_path):
    client, transport, sleeps = make(tmp_path, RateLimitError("busy"))
    result = call(client)
    assert result["data"] is None
    assert "RateLimitError" in result["error"]
    assert sleeps == [1.0, 2.0, 4.0]
    assert len(transport.calls) == 4


def test_other_errors_are_not_retried(tmp_path):
    client, transport, sleeps = make(tmp_path, ValueError("nope"))
    assert "ValueError" in call(client)["error"]
    assert sleeps == []
    assert len(transport.calls) == 1


def test_errors_never_hold_the_key_or_base_url(tmp_path, monkeypatch):
    monkeypatch.setenv("RC_API_KEY", "rc-private-value")
    monkeypatch.setenv("RC_BASE_URL", "https://rc.private.example/v1/")
    message = "key rc-***alue rejected by host='rc.private.example' at https://rc.private.example/v1"
    client, _, _ = make(tmp_path, ValueError(message))
    assert call(client)["error"] == "s-1/probe: ValueError"


def test_status_408_is_retried(tmp_path):
    error = ValueError("timed out")
    error.status_code = 408
    client, transport, sleeps = make(tmp_path, error, '{"ok": true}')
    assert call(client)["data"] == {"ok": True}
    assert sleeps == [1.0]
    assert len(transport.calls) == 2


def test_errors_report_the_status_code(tmp_path):
    error = ValueError("details")
    error.status_code = 400
    client, _, _ = make(tmp_path, error)
    assert call(client)["error"] == "s-1/probe: ValueError (status 400)"


def test_missing_credentials_report_an_error_and_never_call_out(tmp_path):
    client = LLMClient(cache_dir=tmp_path)
    result = call(client)
    assert result["data"] is None
    assert "must be set" in result["error"]


def test_missing_model_reports_the_variable_name(tmp_path, monkeypatch):
    monkeypatch.delenv("RC_MODEL_COMPILE")
    client, transport, _ = make(tmp_path, '{"ok": true}')
    assert "RC_MODEL_COMPILE" in call(client, role="compile")["error"]
    assert transport.calls == []


def test_cost_comes_from_env_rates(tmp_path, monkeypatch):
    monkeypatch.setenv("COST_PER_1K_IN", "0.01")
    monkeypatch.setenv("COST_PER_1K_OUT", "0.02")
    client, _, _ = make(tmp_path, '{"ok": true}')
    assert call(client)["cost_usd"] == pytest.approx(0.002)
    assert client.usage["cost_usd"] == pytest.approx(0.002)


@pytest.mark.parametrize(
    "role,model,temperature",
    [
        ("probe", "probe-model", 0.3),
        ("brief", "probe-model", 0.2),
        ("compile", "compile-model", 0.0),
        ("b1", "compile-model", 0.0),
    ],
)
def test_role_picks_model_and_temperature(tmp_path, role, model, temperature):
    client, transport, _ = make(tmp_path, '{"ok": true}')
    call(client, role=role)
    assert transport.calls[0]["model"] == model
    assert transport.calls[0]["temperature"] == temperature


def test_unknown_role_is_rejected(tmp_path):
    client, _, _ = make(tmp_path, '{"ok": true}')
    with pytest.raises(ValueError):
        call(client, role="attacker")


def test_prompt_log_records_every_send_and_replay(tmp_path):
    client, _, _ = make(tmp_path, "bad", '{"ok": true}')
    call(client)
    call(client)
    assert len(client.prompt_log) == 3
    assert all("hello" in prompt for prompt in client.prompt_log)


def test_usage_adds_up_across_calls(tmp_path):
    client, _, _ = make(tmp_path, '{"ok": true}')
    call(client)
    call(client, role="compile")
    assert client.usage["tokens_in"] == 200
    assert client.usage["tokens_out"] == 100


@pytest.mark.parametrize(
    "text",
    [
        '{"a": 1}',
        '```json\n{"a": 1}\n```',
        '<think>reason {x}</think>{"a": 1}',
        'Here you go: {"a": 1} done',
    ],
)
def test_extract_json_handles_model_wrapping(text):
    assert extract_json(text) == {"a": 1}


@pytest.mark.parametrize(
    "data,schema,fragment",
    [
        (1, {"type": "string"}, "expected string"),
        (True, {"type": "integer"}, "expected integer"),
        ("x", {"enum": ["y"]}, "not allowed"),
        ("x", {"const": "y"}, "must equal"),
        ({}, {"required": ["a"]}, "missing required"),
        ({"b": 1}, {"properties": {}, "additionalProperties": False}, "unexpected key"),
        ([], {"minItems": 1}, "at least"),
        ([1], {"items": {"type": "string"}}, "$[0]"),
        (5, {"maximum": 4}, "above"),
        (1, {"anyOf": [{"type": "string"}, {"type": "null"}]}, "any allowed"),
    ],
)
def test_validate_json_catches_problems(data, schema, fragment):
    assert fragment in validate_json(data, schema)


@pytest.mark.parametrize(
    "data,schema",
    [
        (None, {"type": ["string", "null"]}),
        ({"a": [1]}, {"properties": {"a": {"items": {"type": "integer"}}}}),
        ("x", {"anyOf": [{"type": "string"}, {"type": "null"}]}),
        (None, {"enum": ["a", None]}),
    ],
)
def test_validate_json_accepts_valid_data(data, schema):
    assert validate_json(data, schema) is None


def test_fake_llm_records_prompts_and_needs_no_env(monkeypatch):
    monkeypatch.delenv("RC_MODEL_PROBE")
    fake = FakeLLM({"probe": {"ok": True}})
    assert call(fake)["data"] == {"ok": True}
    assert fake.calls == ["probe"]
    assert "hello" in fake.prompt_log[0]


def test_fake_llm_replies_in_order_and_repeats_the_last():
    fake = FakeLLM({"probe": [{"ok": True}, {"ok": False}]})
    assert [call(fake)["data"]["ok"] for _ in range(3)] == [True, False, False]


def test_fake_llm_accepts_a_callable_and_raw_text():
    assert call(FakeLLM({"probe": lambda messages: {"ok": len(messages) > 0}}))["data"] == {"ok": True}
    assert call(FakeLLM({"probe": "bad"}))["data"] is None


def test_fake_llm_scans_for_canaries_like_the_real_client():
    fake = FakeLLM()
    with pytest.raises(PromptLeak):
        call(fake, messages=[{"role": "user", "content": "CANARY-1"}], canaries=["CANARY-1"])
    assert fake.calls == []


def test_fake_llm_default_probe_walks_the_prompt_catalog():
    catalog = [
        {"action_id": "a", "tool": "close_ticket", "arg_choices": {"ticket_id": ["T-1"]}},
        {"action_id": "b", "tool": "delete_audit", "arg_choices": {"entry_id": ["e-1"]}},
    ]
    messages = [{"role": "user", "content": json.dumps({"catalog": catalog})}]
    fake = FakeLLM()
    schema = {"type": "object"}
    assert call(fake, messages=messages, schema=schema)["data"] == {"action_id": "a", "args": {"ticket_id": "T-1"}}
    assert call(fake, messages=messages, schema=schema)["data"] == {"action_id": "b", "args": {"entry_id": "e-1"}}
