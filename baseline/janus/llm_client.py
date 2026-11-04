"""RC LLM client for Project JANUS. Owner: Mokshitha Mohan.

Every model call goes through ``LLMClient.chat_json``:
secret scan -> cache -> call (with backoff) -> parse -> schema check -> retry.

Secrets rule: the RC key and base URL stay in ``.env``. They are never printed, logged,
cached or copied into an error message. ``PromptLeak`` never quotes the secret it found.

Usage for other modules:
    client = LLMClient()                  # real RC client, reads .env
    fake = FakeLLM()                      # offline, canned JSON per role
    fake = FakeLLM({"compile": {...}})    # dict, raw str, list (one per call) or callable(messages)
    client.prompt_log                     # every prompt sent or replayed
    client.usage                          # running tokens_in, tokens_out, cost_usd
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import time
from pathlib import Path
from typing import Any, Callable
from urllib.parse import urlparse

from aswa.rme import SECRET_RE
from janus.types import LLMResult

ROLES = ("probe", "compile", "brief", "b1")
ROLE_MODEL_ENV = {
    "probe": "RC_MODEL_PROBE",
    "brief": "RC_MODEL_PROBE",
    "compile": "RC_MODEL_COMPILE",
    "b1": "RC_MODEL_COMPILE",
}
ROLE_TEMPERATURE = {"probe": 0.3, "compile": 0.0, "brief": 0.2, "b1": 0.0}

MAX_SCHEMA_RETRIES = 2      # re-asks after bad JSON or a schema failure
MAX_NETWORK_TRIES = 4       # total tries on a rate limit or timeout: waits 1s, 2s, 4s
REQUEST_TIMEOUT_S = 120

BASELINE_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_CACHE_DIR = BASELINE_ROOT / "results" / "cache"

RETRYABLE_ERRORS = {"RateLimitError", "APITimeoutError", "APIConnectionError", "InternalServerError"}

# SECRET_RE needs ":" or "=" right after the word, so it misses JSON keys like "password": "x".
# Prompts are JSON (escaped once more when scanned), so this catches that form too.
JSON_SECRET_RE = re.compile(r'(?i)(token|password|secret|api[_-]?key|authorization)\\*"\s*:\s*\S+')
MAX_REPLY_ECHO = 2000       # characters of a rejected reply shown back to the model

# (role, model, messages, temperature) -> (text, tokens_in, tokens_out)
Transport = Callable[[str, str, list[dict[str, str]], float], tuple[str, int, int]]


class PromptLeak(RuntimeError):
    """A prompt held a canary or secret. Raised before any call; the run must abort."""


class LLMConfigError(RuntimeError):
    """A required setting is missing. Its message names the setting, never a value."""


def _load_env() -> None:
    try:
        from dotenv import load_dotenv
    except ImportError:
        return
    load_dotenv(BASELINE_ROOT / ".env", override=False)


def _cost_rate(name: str) -> float:
    try:
        return float(os.getenv(name) or 0)
    except ValueError:
        return 0.0


def find_leak(text: str, canaries: list[str]) -> str | None:
    """Say what kind of secret is in ``text``, without ever quoting the secret."""
    for index, canary in enumerate(canaries or []):
        if canary and canary in text:
            return f"canary #{index}"
    key = os.getenv("RC_API_KEY")
    if key and key in text:
        return "RC_API_KEY"
    url = (os.getenv("RC_BASE_URL") or "").rstrip("/")
    if url and (url in text or (urlparse(url).hostname or url) in text):
        return "RC_BASE_URL"
    for pattern in (SECRET_RE, JSON_SECRET_RE):
        for match in pattern.finditer(text):
            if "[REDACTED]" not in match.group(0):  # already-sanitized telemetry is fine
                return "secret pattern"
    return None


def extract_json(text: str) -> Any:
    """Parse model output, tolerating think blocks, code fences and text around the JSON."""
    text = re.sub(r"<think>.*?</think>", "", text or "", flags=re.S).strip()
    text = re.sub(r"^```(?:json)?\s*|\s*```$", "", text).strip()
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        start = text.find("{")
        if start < 0:
            raise
        return json.JSONDecoder().raw_decode(text[start:])[0]


_JSON_TYPES: dict[str, tuple[type, ...]] = {
    "object": (dict,),
    "array": (list,),
    "string": (str,),
    "number": (int, float),
    "integer": (int,),
    "boolean": (bool,),
    "null": (type(None),),
}


def _is_type(value: Any, name: str) -> bool:
    if isinstance(value, bool):
        return name == "boolean"  # bool is a subclass of int in Python
    return isinstance(value, _JSON_TYPES[name])


def validate_json(data: Any, schema: dict[str, Any], path: str = "$") -> str | None:
    """Check ``data`` against a JSON Schema subset. Returns the first problem, or None.

    Handwritten to avoid a new dependency. Supports type, enum, const, required, properties,
    additionalProperties, items, minItems, minimum, maximum and anyOf. Other keywords are ignored.
    """
    if "anyOf" in schema and all(validate_json(data, option, path) for option in schema["anyOf"]):
        return f"{path}: does not match any allowed form"
    if "type" in schema:
        names = schema["type"] if isinstance(schema["type"], list) else [schema["type"]]
        if not any(_is_type(data, name) for name in names):
            return f"{path}: expected {'/'.join(names)}, got {type(data).__name__}"
    if "const" in schema and data != schema["const"]:
        return f"{path}: must equal {schema['const']!r}"
    if "enum" in schema and data not in schema["enum"]:
        return f"{path}: value not allowed, must be one of {schema['enum']}"
    if isinstance(data, (int, float)) and not isinstance(data, bool):
        if "minimum" in schema and data < schema["minimum"]:
            return f"{path}: below minimum {schema['minimum']}"
        if "maximum" in schema and data > schema["maximum"]:
            return f"{path}: above maximum {schema['maximum']}"
    if isinstance(data, list):
        if len(data) < schema.get("minItems", 0):
            return f"{path}: needs at least {schema['minItems']} item(s)"
        if "items" in schema:
            for index, item in enumerate(data):
                problem = validate_json(item, schema["items"], f"{path}[{index}]")
                if problem:
                    return problem
    if isinstance(data, dict):
        for key in schema.get("required", []):
            if key not in data:
                return f"{path}: missing required key '{key}'"
        properties = schema.get("properties", {})
        extra = schema.get("additionalProperties", True)
        for key, value in data.items():
            if key in properties:
                problem = validate_json(value, properties[key], f"{path}.{key}")
                if problem:
                    return problem
            elif extra is False:
                return f"{path}: unexpected key '{key}'"
            elif isinstance(extra, dict):
                problem = validate_json(value, extra, f"{path}.{key}")
                if problem:
                    return problem
    return None


def _cache_key(role: str, model: str, messages: list[dict[str, str]], schema: dict[str, Any]) -> str:
    blob = json.dumps([role, model, messages, schema], sort_keys=True, ensure_ascii=False)
    return hashlib.sha256(blob.encode("utf-8")).hexdigest()


class LLMClient:
    """Exposes ``chat_json`` and ``prompt_log``, as agreed in COORDINATION 11.2."""

    def __init__(
        self,
        *,
        transport: Transport | None = None,
        cache_dir: str | Path | None = None,
        use_cache: bool = True,
        sleep: Callable[[float], None] = time.sleep,
    ) -> None:
        _load_env()
        self._transport = transport or self._openai_transport
        self._cache_dir = Path(cache_dir) if cache_dir else DEFAULT_CACHE_DIR
        self._use_cache = use_cache
        self._sleep = sleep
        self._openai: Any = None
        self.prompt_log: list[str] = []
        self.usage: dict[str, float] = {"tokens_in": 0, "tokens_out": 0, "cost_usd": 0.0}

    def chat_json(
        self,
        role: str,
        messages: list[dict[str, str]],
        schema: dict[str, Any],
        *,
        scenario_id: str,
        canaries: list[str],
    ) -> LLMResult:
        """Return validated JSON in ``data``; on failure ``data`` is None and ``error`` is set.

        Raises PromptLeak before any call, and on a cache hit too. Cache hits report the tokens
        and cost recorded by the original call, so a replayed run gives the same numbers.
        """
        if role not in ROLES:
            raise ValueError(f"unknown LLM role: {role}")
        self._scan(messages, canaries, scenario_id, role)

        model = self._model_for(role)
        if not model:
            return self._result(None, 0, 0, error=f"{ROLE_MODEL_ENV[role]} is not set")

        key = _cache_key(role, model, messages, schema)
        hit = self._cache_read(key)
        if hit is not None:
            self.prompt_log.append(json.dumps(messages, ensure_ascii=False))
            self._add_usage(hit["tokens_in"], hit["tokens_out"], hit["cost_usd"])
            return LLMResult(
                data=hit["data"],
                tokens_in=hit["tokens_in"],
                tokens_out=hit["tokens_out"],
                cost_usd=hit["cost_usd"],
                cached=True,
                error=None,
            )

        conversation = self._with_schema(messages, schema)
        tokens_in = tokens_out = 0
        problem = "no attempt made"
        for _ in range(MAX_SCHEMA_RETRIES + 1):
            self._scan(conversation, canaries, scenario_id, role)
            self.prompt_log.append(json.dumps(conversation, ensure_ascii=False))
            text, used_in, used_out, send_error = self._send(role, model, conversation)
            if send_error:
                return self._result(None, tokens_in, tokens_out, error=f"{scenario_id}/{role}: {send_error}")
            tokens_in += used_in
            tokens_out += used_out
            data, problem = self._parse(text, schema)
            if problem is None:
                result = self._result(data, tokens_in, tokens_out)
                self._cache_write(key, result)
                return result
            conversation = [
                *conversation,
                {"role": "assistant", "content": text[:MAX_REPLY_ECHO] or "(empty reply)"},
                {
                    "role": "user",
                    "content": f"Your last reply was rejected: {problem}. Fix it and return only the JSON.",
                },
            ]
        return self._result(None, tokens_in, tokens_out, error=f"{scenario_id}/{role}: {problem}")

    @staticmethod
    def _with_schema(messages: list[dict[str, str]], schema: dict[str, Any]) -> list[dict[str, str]]:
        """Add the schema to the first system message; some model templates allow only one."""
        note = "Return only one JSON object matching this JSON Schema, with no other text: " + json.dumps(
            schema, ensure_ascii=False
        )
        if messages and messages[0]["role"] == "system":
            return [{"role": "system", "content": f"{messages[0]['content']}\n\n{note}"}, *messages[1:]]
        return [{"role": "system", "content": note}, *messages]

    def _scan(self, messages: list[dict[str, str]], canaries: list[str], scenario_id: str, role: str) -> None:
        leak = find_leak(json.dumps(messages, ensure_ascii=False), canaries)
        if leak:
            raise PromptLeak(f"{scenario_id}/{role}: {leak} found in prompt; call blocked")

    def _parse(self, text: str, schema: dict[str, Any]) -> tuple[Any, str | None]:
        try:
            data = extract_json(text)
        except json.JSONDecodeError as exc:
            return None, f"not valid JSON ({exc.msg})"
        if not isinstance(data, dict):
            return None, f"expected a JSON object, got {type(data).__name__}"
        return data, validate_json(data, schema)

    def _send(
        self, role: str, model: str, messages: list[dict[str, str]]
    ) -> tuple[str, int, int, str | None]:
        """Call the transport, backing off on rate limits and timeouts."""
        delay = 1.0
        for attempt in range(MAX_NETWORK_TRIES):
            try:
                text, used_in, used_out = self._transport(role, model, messages, ROLE_TEMPERATURE[role])
                return text, used_in, used_out, None
            except LLMConfigError as exc:
                return "", 0, 0, str(exc)
            except Exception as exc:  # the SDK raises many types
                name = type(exc).__name__
                if name not in RETRYABLE_ERRORS or attempt == MAX_NETWORK_TRIES - 1:
                    # Class and status only: SDK messages can echo the host or part of the key.
                    status = getattr(exc, "status_code", None)
                    return "", 0, 0, f"{name} (status {status})" if status else name
                self._sleep(delay)
                delay *= 2
        return "", 0, 0, "no network attempt made"

    def _openai_transport(
        self, role: str, model: str, messages: list[dict[str, str]], temperature: float
    ) -> tuple[str, int, int]:
        if self._openai is None:
            key, url = os.getenv("RC_API_KEY"), os.getenv("RC_BASE_URL")
            if not key or not url:
                raise LLMConfigError("RC_API_KEY and RC_BASE_URL must be set in .env")
            from openai import OpenAI

            # max_retries=0: backoff lives in _send, so tries are counted in one place.
            self._openai = OpenAI(api_key=key, base_url=url, max_retries=0, timeout=REQUEST_TIMEOUT_S)
        response = self._openai.chat.completions.create(model=model, messages=messages, temperature=temperature)
        usage = response.usage
        return (
            response.choices[0].message.content or "",
            usage.prompt_tokens if usage else 0,
            usage.completion_tokens if usage else 0,
        )

    def _model_for(self, role: str) -> str | None:
        return os.getenv(ROLE_MODEL_ENV[role])

    def _result(self, data: Any, tokens_in: int, tokens_out: int, error: str | None = None) -> LLMResult:
        cost = (
            tokens_in / 1000 * _cost_rate("COST_PER_1K_IN")
            + tokens_out / 1000 * _cost_rate("COST_PER_1K_OUT")
        )
        self._add_usage(tokens_in, tokens_out, cost)
        return LLMResult(
            data=data, tokens_in=tokens_in, tokens_out=tokens_out, cost_usd=cost, cached=False, error=error
        )

    def _add_usage(self, tokens_in: int, tokens_out: int, cost: float) -> None:
        self.usage["tokens_in"] += tokens_in
        self.usage["tokens_out"] += tokens_out
        self.usage["cost_usd"] += cost

    def _cache_read(self, key: str) -> dict[str, Any] | None:
        if not self._use_cache:
            return None
        try:
            return json.loads((self._cache_dir / f"{key}.json").read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return None

    def _cache_write(self, key: str, result: LLMResult) -> None:
        if not self._use_cache:
            return
        entry = {
            "data": result["data"],
            "tokens_in": result["tokens_in"],
            "tokens_out": result["tokens_out"],
            "cost_usd": result["cost_usd"],
        }
        # A failed write must not lose a paid reply (OneDrive can lock files, for example).
        try:
            self._cache_dir.mkdir(parents=True, exist_ok=True)
            temp = self._cache_dir / f"{key}.tmp"
            temp.write_text(json.dumps(entry), encoding="utf-8")
            os.replace(temp, self._cache_dir / f"{key}.json")
        except OSError:
            return


# Canned rules for FakeLLM's compile role. Tests only; real fallbacks are compiler.TEMPLATE_RULES.
_FAKE_RULES: dict[str, dict[str, Any]] = {
    "P1": {
        "kind": "firewall_rule",
        "applies_to": "grant_access",
        "conditions": [
            {"field": "principal.external", "op": "is_true", "value": None},
            {"field": "folder.label", "op": "==", "value": "restricted"},
        ],
        "effect": "deny",
    },
    "P2": {
        "kind": "dlp_signature",
        "applies_to": "send_email",
        "conditions": [
            {"field": "to.external", "op": "is_true", "value": None},
            {"field": "attachment.sensitivity", "op": "in", "value": ["confidential", "restricted"]},
        ],
        "effect": "deny",
    },
    "P3": {
        "kind": "payment_control",
        "applies_to": "create_payment",
        "conditions": [{"field": "amount", "op": ">", "value": 500}],
        "effect": "require",
        "require_field": "dual_approved",
    },
    "P4": {
        "kind": "workflow_rule",
        "applies_to": "close_ticket",
        "conditions": [{"field": "ticket.comment_count", "op": "==", "value": 0}],
        "effect": "deny",
    },
    "H1": {
        "kind": "sharing_rule",
        "applies_to": "share_link",
        "conditions": [
            {"field": "public", "op": "is_true", "value": None},
            {"field": "file.sensitivity", "op": "in", "value": ["confidential", "restricted"]},
        ],
        "effect": "deny",
    },
    "H2": {
        "kind": "role_rule",
        "applies_to": "change_role",
        "conditions": [
            {"field": "role", "op": "==", "value": "admin"},
            {"field": "approved", "op": "is_false", "value": None},
        ],
        "effect": "deny",
    },
    "H3": {
        "kind": "vendor_rule",
        "applies_to": "update_vendor_bank",
        "conditions": [{"field": "verification_ticket", "op": "is_false", "value": None}],
        "effect": "deny",
    },
    "H4": {
        "kind": "audit_rule",
        "applies_to": "delete_audit",
        "conditions": [],
        "effect": "deny",
    },
}


def _prompt_payload(messages: list[dict[str, str]], key: str) -> dict[str, Any] | None:
    for message in messages:
        try:
            payload = json.loads(message["content"])
        except (json.JSONDecodeError, TypeError):
            continue
        if isinstance(payload, dict) and key in payload:
            return payload
    return None


class FakeLLM(LLMClient):
    """Offline client with the real scan, parse, schema and retry path; no cache, no network.

    With no ``responses`` it answers every role with valid JSON:
    probe walks the catalog in the prompt, compile returns a rule for the violated policy,
    brief returns fixed text and b1 returns an empty rule list.
    """

    def __init__(self, responses: dict[str, Any] | None = None) -> None:
        super().__init__(transport=self._fake_transport, use_cache=False, sleep=lambda _: None)
        self._responses = {role: self._as_queue(value) for role, value in (responses or {}).items()}
        self._probe_step = 0
        self.calls: list[str] = []

    @staticmethod
    def _as_queue(value: Any) -> Any:
        return list(value) if isinstance(value, list) else value

    def _model_for(self, role: str) -> str:
        return f"fake-{role}"

    def _fake_transport(
        self, role: str, model: str, messages: list[dict[str, str]], temperature: float
    ) -> tuple[str, int, int]:
        self.calls.append(role)
        reply = self._next_reply(role, messages)
        if isinstance(reply, Exception):
            raise reply
        text = reply if isinstance(reply, str) else json.dumps(reply)
        return text, sum(len(m["content"]) for m in messages) // 4, len(text) // 4

    def _next_reply(self, role: str, messages: list[dict[str, str]]) -> Any:
        if role not in self._responses:
            return self._default_reply(role, messages)
        canned = self._responses[role]
        if callable(canned):
            return canned(messages)
        if isinstance(canned, list):
            return canned.pop(0) if len(canned) > 1 else canned[0]  # the last reply repeats
        return canned

    def _default_reply(self, role: str, messages: list[dict[str, str]]) -> dict[str, Any]:
        if role == "probe":
            catalog = (_prompt_payload(messages, "catalog") or {}).get("catalog") or [{}]
            entry = catalog[self._probe_step % len(catalog)]
            self._probe_step += 1
            return {
                "action_id": entry.get("action_id", "none"),
                "args": {name: values[0] for name, values in entry.get("arg_choices", {}).items() if values},
            }
        if role == "compile":
            return self._fake_rule(messages)
        if role == "brief":
            return {"briefing": "Fake briefing: approved rules are listed for the operator."}
        return {"rules": []}

    def _fake_rule(self, messages: list[dict[str, str]]) -> dict[str, Any]:
        payload = _prompt_payload(messages, "policy") or {}
        policy_id = (payload.get("policy") or {}).get("id", "P4")
        return {
            "id": f"fake-{policy_id}",
            "require_field": None,
            **_FAKE_RULES.get(policy_id, _FAKE_RULES["P4"]),
            "addresses_policy": policy_id,
            "rationale": f"Fake rule for {policy_id}.",
        }
