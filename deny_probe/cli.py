"""Command-line interface for deny-probe."""

from __future__ import annotations

import argparse
import json
import os
import sys

from . import __version__
from .analyzer import HOLD, LEAK, META, audit, summarize
from .live import LiveError, run_live
from .recommend import GENERAL_NOTE, suggestions_for_leaks
from .routes import ROUTES, get_route
from .rules import DenyRule, parse_rules

DEFAULT_TARGET = "./.env"


def load_rules_from_settings(path: str) -> list[str]:
    """Read deny rules from a Claude Code settings.json (or a bare JSON list)."""
    with open(path, encoding="utf-8") as fh:
        data = json.load(fh)
    if isinstance(data, list):
        return [str(x) for x in data]
    if isinstance(data, dict):
        perms = data.get("permissions", {})
        if isinstance(perms, dict) and isinstance(perms.get("deny"), list):
            return [str(x) for x in perms["deny"]]
        if isinstance(data.get("deny"), list):
            return [str(x) for x in data["deny"]]
    raise ValueError(
        f"{path}: expected a JSON list of rules or an object with "
        "permissions.deny (Claude Code settings.json format)"
    )


def collect_rules(args) -> list[DenyRule]:
    texts: list[str] = []
    if args.settings:
        texts.extend(load_rules_from_settings(args.settings))
    if args.deny:
        texts.extend(args.deny)
    if not texts:
        raise ValueError("no deny rules given: use --settings PATH or --deny 'Tool(pattern)'")
    return parse_rules(texts)


def _norm_target(t: str) -> str:
    return t if t.startswith("./") or t.startswith("/") else "./" + t


def format_table(findings, rules, targets) -> str:
    lines: list[str] = []
    summary = summarize(findings)
    for target in targets:
        s = summary[target]
        lines.append(f"Target: {target}")
        lines.append(f"Deny rules ({len(rules)}):")
        for r in rules:
            lines.append(f"  {r.raw}")
        lines.append("")
        lines.append(f"{'ROUTE':<18}{'TOOL':<8}{'VERDICT':<9}BLOCKED BY")
        lines.append("-" * 70)
        for f in findings:
            if f.target != target:
                continue
            blocked = ", ".join(f.blocking_rules) if f.blocking_rules else "-"
            lines.append(f"{f.route.id:<18}{f.route.tool:<8}{f.verdict:<9}{blocked}")
        lines.append("")
        lines.append(
            f"Summary for {target}: {s['leak']}/{s['routes']} routes leak content, "
            f"{s['hold']} hold, {s['meta']} metadata-only."
        )
        recs = suggestions_for_leaks(findings, target)
        if recs:
            lines.append("")
            lines.append("Hardening suggestions:")
            for rec in recs:
                lines.append(f"  [{rec['route']}] {rec['route_name']}")
                for rule in rec["add_rules"]:
                    lines.append(f"    + {rule}")
            lines.append(f"  Note: {GENERAL_NOTE}")
        lines.append("")
    return "\n".join(lines).rstrip() + "\n"


def cmd_audit(args) -> int:
    try:
        rules = collect_rules(args)
    except (ValueError, OSError) as exc:
        print(f"deny-probe: error: {exc}", file=sys.stderr)
        return 2
    targets = [_norm_target(t) for t in (args.target or [DEFAULT_TARGET])]
    findings = audit(rules, targets)

    if args.format == "json":
        summary = summarize(findings)
        payload = {
            "targets": [
                {
                    "target": t,
                    "deny_rules": [r.raw for r in rules],
                    "summary": summary[t],
                    "findings": [
                        {
                            "route": f.route.id,
                            "route_name": f.route.name,
                            "tool": f.route.tool,
                            "verdict": f.verdict,
                            "leak_kind": f.route.leak_kind,
                            "blocking_rules": f.blocking_rules,
                            "precondition": f.route.precondition,
                        }
                        for f in findings
                        if f.target == t
                    ],
                    "recommendations": suggestions_for_leaks(findings, t),
                }
                for t in targets
            ],
            "general_note": GENERAL_NOTE,
        }
        print(json.dumps(payload, indent=2))
    else:
        sys.stdout.write(format_table(findings, rules, targets))

    return 1 if any(f.verdict == LEAK for f in findings) else 0


def cmd_live(args) -> int:
    target = _norm_target(args.target or DEFAULT_TARGET)
    route_ids = [r.id for r in ROUTES] if args.all else [args.route or "bash-cat"]
    reports = []
    for rid in route_ids:
        try:
            route = get_route(rid)
        except KeyError:
            print(f"deny-probe: error: unknown route {rid!r}", file=sys.stderr)
            print(f"available: {', '.join(r.id for r in ROUTES)}", file=sys.stderr)
            return 2
        try:
            reports.append(
                run_live(
                    target,
                    route,
                    canary=args.canary,
                    runs=args.runs,
                    transcript_path=args.transcript,
                )
            )
        except LiveError as exc:
            print(f"deny-probe: live probe failed: {exc}", file=sys.stderr)
            return 2

    if args.format == "json":
        print(json.dumps({"target": target, "reports": reports}, indent=2))
    else:
        print(f"Target: {target}   canary: {args.canary}")
        print(f"{'ROUTE':<18}{'RUNS':<8}{'LEAKED':<8}VERDICT")
        print("-" * 60)
        for rep in reports:
            print(f"{rep['route']:<18}{rep['runs']:<8}{rep['leaks']:<8}{rep['verdict']}")
        print()
        print("Note: " + reports[0]["note"])
    return 1 if any(r["verdict"] == LEAK for r in reports) else 0


def cmd_routes(args) -> int:
    if args.format == "json":
        print(
            json.dumps(
                [
                    {
                        "id": r.id,
                        "name": r.name,
                        "tool": r.tool,
                        "leak_kind": r.leak_kind,
                        "description": r.description,
                        "precondition": r.precondition,
                    }
                    for r in ROUTES
                ],
                indent=2,
            )
        )
    else:
        print(f"{'ID':<18}{'TOOL':<8}{'KIND':<9}NAME")
        print("-" * 70)
        for r in ROUTES:
            print(f"{r.id:<18}{r.tool:<8}{r.leak_kind:<9}{r.name}")
    return 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="deny-probe",
        description="Penetration tester for Claude Code permission deny rules.",
    )
    p.add_argument("--version", action="version", version=f"deny-probe {__version__}")
    sub = p.add_subparsers(dest="command", required=True)

    a = sub.add_parser("audit", help="Statically predict HOLD/LEAK per route (default).")
    a.add_argument("--settings", help="Path to Claude Code settings.json")
    a.add_argument("--deny", action="append", help="A deny rule like 'Read(./.env)' (repeatable)")
    a.add_argument("--target", action="append", help="File to protect (default: ./.env)")
    a.add_argument("--format", choices=["table", "json"], default="table")
    a.set_defaults(func=cmd_audit)

    l = sub.add_parser("live", help="Verify with real `claude -p` sessions (manual only).")
    l.add_argument("--target", help="File to protect (default: ./.env)")
    l.add_argument("--route", help="Route id to probe (default: bash-cat)")
    l.add_argument("--all", action="store_true", help="Probe every route in the library")
    l.add_argument("--runs", type=int, default=3, help="Sessions per route (default: 3)")
    l.add_argument(
        "--canary",
        default="deny-probe-canary-9f3a2c",
        help="Marker string written to the canary file",
    )
    l.add_argument("--transcript", help="Optional transcript file for the dual check")
    l.add_argument("--format", choices=["table", "json"], default="table")
    l.set_defaults(func=cmd_live)

    r = sub.add_parser("routes", help="List the built-in bypass route library.")
    r.add_argument("--format", choices=["table", "json"], default="table")
    r.set_defaults(func=cmd_routes)
    return p


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
