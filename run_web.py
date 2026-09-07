#!/usr/bin/env python3
from __future__ import annotations

import argparse

import uvicorn


def main() -> None:
    parser = argparse.ArgumentParser(description="Project Janus web console")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8765)
    args = parser.parse_args()
    print(f"Project Janus console: http://{args.host}:{args.port}")
    uvicorn.run("webapp:app", host=args.host, port=args.port, reload=False)


if __name__ == "__main__":
    main()
