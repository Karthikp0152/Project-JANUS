"""M0 stub. Owner: Pradeep Krishnamoorthy. Parses the agreed CLI but runs nothing yet."""
from __future__ import annotations

import argparse

from janus.types import DEFAULT_SEED


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Run the JanusBench evaluation.")
    parser.add_argument("--split", required=True, choices=["seen", "heldout", "benign"])
    parser.add_argument("--system", default="all", choices=["B0", "B1", "P", "all"])
    parser.add_argument("--n", type=int, default=12)
    parser.add_argument("--seed", type=int, default=DEFAULT_SEED)
    args = parser.parse_args(argv)
    print(f"run_eval stub: split={args.split} system={args.system} n={args.n} seed={args.seed}; nothing was run")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
