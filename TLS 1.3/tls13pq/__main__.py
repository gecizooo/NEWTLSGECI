"""Command line entry point.

    python3 -m tls13pq                 # run the demo
    python3 -m tls13pq demo            # run the demo
    python3 -m tls13pq validate FILE   # parse + validate a config
"""

from __future__ import annotations

import argparse
import json
import sys

from .config import ConfigError, format_duration, load_config
from .demo import run_demo


def _cmd_validate(path: str) -> int:
    try:
        cfg = load_config(path)
    except (OSError, json.JSONDecodeError, ConfigError) as exc:
        print(f"INVALID  {path}\n  {exc}", file=sys.stderr)
        return 1

    print(f"OK       {path}")
    print(f"  profile      {cfg.profile.value}")
    print(f"  groups       {', '.join(g.label for g in cfg.groups.offered)}")
    print(f"  early_data   {cfg.early_data.mode.value}, "
          f"max_lifetime={format_duration(cfg.early_data.max_lifetime)}")
    print(f"  replay       {cfg.replay.ownership.value}/{cfg.replay.filter.value}, "
          f"fail_mode={cfg.replay.fail_mode.value}")
    print(f"  commit       {cfg.commit.commit_point}, "
          f"linearizable={cfg.commit.linearizable}")
    print(f"  ech          {len(cfg.ech.keys)} configs, "
          f"key_ttl={format_duration(cfg.ech.key_ttl)}, "
          f"retry_grace={format_duration(cfg.ech.retry_grace)}")
    print(f"  padding      {cfg.padding.classes}")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="tls13pq",
        description="TLS13-PQ reference configuration and early-data model",
    )
    sub = parser.add_subparsers(dest="command")

    sub.add_parser("demo", help="run the 0-RTT replay demonstration")

    validate = sub.add_parser("validate", help="parse and validate a JSON config")
    validate.add_argument("path", nargs="?", default="example.json")

    args = parser.parse_args(argv)

    if args.command == "validate":
        return _cmd_validate(args.path)
    return run_demo()


if __name__ == "__main__":
    raise SystemExit(main())
