"""Static analysis: predict HOLD/LEAK for each deny rule x route x target."""

from __future__ import annotations

from dataclasses import dataclass, field

from .routes import ROUTES, Route
from .rules import DenyRule

HOLD = "HOLD"
LEAK = "LEAK"
META = "META"  # metadata-only leak (e.g. Glob reveals existence, not content)


@dataclass
class Finding:
    target: str
    route: Route
    verdict: str  # HOLD | LEAK | META
    blocking_rules: list[str] = field(default_factory=list)


def audit(
    rules: list[DenyRule],
    targets: list[str],
    routes: tuple[Route, ...] = ROUTES,
) -> list[Finding]:
    """Static prediction.

    For each (target, route): the route is HOLD iff at least one deny rule
    names the route's tool AND its pattern matches the route's argument.
    Deny rules are enforced per tool in Claude Code, so a Read(...) rule
    never blocks a Grep/Bash route -- that is exactly what we probe.
    """
    findings: list[Finding] = []
    for target in targets:
        for route in routes:
            argument = route.argument_for(target)
            blocking = [r.raw for r in rules if r.tool == route.tool and r.matches(argument)]
            if blocking:
                verdict = HOLD
            elif route.leak_kind == "metadata":
                verdict = META
            else:
                verdict = LEAK
            findings.append(
                Finding(target=target, route=route, verdict=verdict, blocking_rules=blocking)
            )
    return findings


def summarize(findings: list[Finding]) -> dict:
    """Aggregate counts per target: routes probed, content leaks, holds, metas."""
    summary: dict[str, dict[str, int]] = {}
    for f in findings:
        s = summary.setdefault(
            f.target, {"routes": 0, "leak": 0, "hold": 0, "meta": 0}
        )
        s["routes"] += 1
        if f.verdict == LEAK:
            s["leak"] += 1
        elif f.verdict == HOLD:
            s["hold"] += 1
        else:
            s["meta"] += 1
    return summary
