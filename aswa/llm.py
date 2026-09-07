from __future__ import annotations

import os
from functools import lru_cache
from typing import Any


DEFAULT_BASE_URL = "https://api.openai.com/v1"
DEFAULT_MODEL = "gpt-4o-mini"


def _load_dotenv() -> None:
    try:
        from dotenv import load_dotenv
    except ImportError:
        return
    root = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
    load_dotenv(os.path.join(root, ".env"), override=False)


def get_api_key() -> str | None:
    _load_dotenv()
    return os.getenv("OPENAI_API_KEY") or None


def get_base_url() -> str:
    _load_dotenv()
    return os.getenv("OPENAI_BASE_URL", DEFAULT_BASE_URL).rstrip("/")


def get_model() -> str:
    _load_dotenv()
    return os.getenv("OPENAI_MODEL", DEFAULT_MODEL)


def llm_enabled() -> bool:
    return bool(get_api_key())


@lru_cache(maxsize=1)
def get_client():
    api_key = get_api_key()
    if not api_key:
        return None
    from openai import OpenAI

    return OpenAI(base_url=get_base_url(), api_key=api_key)


def chat(messages: list[dict[str, str]], *, temperature: float = 0.2) -> str:
    client = get_client()
    if client is None:
        raise RuntimeError("No API key found. Set OPENAI_API_KEY in .env or your environment.")
    response = client.chat.completions.create(
        model=get_model(),
        messages=messages,
        temperature=temperature,
    )
    content = response.choices[0].message.content
    return (content or "").strip()


def explain_countermeasure(violation: str, artifact: str, kind: str) -> dict[str, Any]:
    if not llm_enabled():
        return {
            "llm_used": False,
            "rationale": f"Template defense for policy: {violation}",
        }
    prompt = (
        "You are the Learn stage of Project Janus (ASWA). "
        "Given a Shadow-World policy violation and a defensive artifact, "
        "write a concise operator rationale (2-3 sentences). "
        "Do not invent exploits. Do not output attack steps. "
        "Only explain why this defense should be deployed through the Janus Gate.\n\n"
        f"Violation: {violation}\n"
        f"Defense kind: {kind}\n"
        f"Artifact: {artifact}\n"
    )
    try:
        text = chat(
            [
                {
                    "role": "system",
                    "content": "You help design defensive patches only. Never provide offensive guidance.",
                },
                {"role": "user", "content": prompt},
            ]
        )
        return {"llm_used": True, "rationale": text, "model": get_model()}
    except Exception as exc:
        return {
            "llm_used": False,
            "rationale": f"Template defense for policy: {violation}",
            "error": str(exc),
        }
