"""Command-line interface for nhi-scan.

    nhi-scan inventory <inventory>              # counts by type and risk tier
    nhi-scan scan      <inventory>              # full risk report (Markdown)
    nhi-scan scan      <inventory> --json       # machine-readable JSON
    nhi-scan diff      <before> <after>         # drift: what changed between two scans
"""

from __future__ import annotations

import argparse
import json
import sys

from . import __version__, report
from .diff import diff
from .ingest import load_fleet
from .scan import scan


def _cmd_inventory(args: argparse.Namespace) -> int:
    result = scan(load_fleet(args.inventory))
    print(f"{result.total} non-human identities\n")
    print("By type:")
    for typ, count in sorted(result.type_counts.items(), key=lambda kv: -kv[1]):
        print(f"  {count:>4}  {typ}")
    print("\nBy risk tier:")
    for tier, count in result.tier_counts.items():
        print(f"  {count:>4}  {tier.name} ({tier.label})")
    print(f"\n{result.orphaned} orphaned · {result.long_lived} long-lived secrets")
    return 0


def _cmd_scan(args: argparse.Namespace) -> int:
    result = scan(load_fleet(args.inventory))
    if args.json:
        print(json.dumps(report.to_json(result), indent=2))
    else:
        print(report.to_markdown(result))
    return 0


def _cmd_diff(args: argparse.Namespace) -> int:
    report_ = diff(load_fleet(args.before), load_fleet(args.after))
    if args.json:
        print(json.dumps(report.drift_to_json(report_), indent=2))
    else:
        print(report.drift_to_markdown(report_))
    return 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="nhi-scan", description="Non-human & agent identity risk scanner.")
    p.add_argument("--version", action="version", version=f"nhi-scan {__version__}")
    sub = p.add_subparsers(dest="command", required=True)

    inv = sub.add_parser("inventory", help="Summarize the fleet by type and risk tier.")
    inv.add_argument("inventory", help="Path to a JSON/YAML NHI inventory.")
    inv.set_defaults(func=_cmd_inventory)

    sc = sub.add_parser("scan", help="Assess risk tiers and OWASP NHI findings.")
    sc.add_argument("inventory", help="Path to a JSON/YAML NHI inventory.")
    sc.add_argument("--json", action="store_true", help="Emit JSON instead of Markdown.")
    sc.set_defaults(func=_cmd_scan)

    df = sub.add_parser("diff", help="Show drift between two inventories (reach growth, escalations).")
    df.add_argument("before", help="Earlier JSON/YAML inventory.")
    df.add_argument("after", help="Later JSON/YAML inventory.")
    df.add_argument("--json", action="store_true", help="Emit JSON instead of Markdown.")
    df.set_defaults(func=_cmd_diff)
    return p


def main(argv: list[str] | None = None) -> int:
    # Reports use Unicode tier badges; force UTF-8 so Windows consoles don't choke.
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8")  # type: ignore[attr-defined]
        except (AttributeError, ValueError):
            pass
    args = build_parser().parse_args(argv)
    try:
        return args.func(args)
    except (FileNotFoundError, ValueError, RuntimeError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
