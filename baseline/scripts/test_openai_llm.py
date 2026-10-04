#!/usr/bin/env python3
from __future__ import annotations



from aswa.llm import chat, get_model, llm_enabled





def main() -> None:

    print(f"model:   {get_model()}")

    print(f"key set: {llm_enabled()}")

    if not llm_enabled():

        print("Paste your key into .env as OPENAI_API_KEY=...")

        raise SystemExit(1)

    reply = chat([{"role": "user", "content": "Reply with exactly: Janus LLM OK"}])

    print("reply:", reply)





if __name__ == "__main__":

    main()


