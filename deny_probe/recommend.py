"""Hardening suggestions: which deny rules to add for each leaked route."""

from __future__ import annotations

from .routes import Route

# Per-route rule templates. {target} is the denied file pattern.
_SUGGESTIONS: dict[str, list[str]] = {
    "read-direct": ["{target} is already covered for Read -- no change needed."],
    "grep-tool": ["Grep({target})"],
    "glob-tool": ["Glob({target})  (only needed if file existence itself is sensitive)"],
    "bash-cat": ["Bash(cat *)"],
    "bash-grep": ["Bash(grep *)"],
    "bash-sed": ["Bash(sed *)"],
    "bash-awk": ["Bash(awk *)"],
    "bash-head": ["Bash(head *)"],
    "bash-tail": ["Bash(tail *)"],
    "bash-python": ["Bash(python *)", "Bash(python3 *)"],
    "bash-perl": ["Bash(perl *)"],
    "claude-md-import": [
        "Read(./CLAUDE.md)",
        "or remove the @-import of the secret from CLAUDE.md",
    ],
    "claude-md-nested": ["Read(./**/CLAUDE.md)"],
    # Regression routes (Claude Code 2.1.287 / 2.1.289 fixes): exact-string
    # rules never match the mutated command line, so the suggestion is a
    # wildcard anchored on both sides of the dangerous command.
    "read-symlink": [
        "Read({target}*)  (an exact-path Read rule never matches the symlink path)"
    ],
    "bash-env-prefix": [
        "Bash(*cat {target}*)  (leading wildcard: env-var prefixes and bare "
        "assignments change where the command starts)"
    ],
    "bash-bare-assign": [
        "Bash(*cat {target}*)  (leading wildcard: env-var prefixes and bare "
        "assignments change where the command starts)"
    ],
    "bash-redirect-suffix": [
        "Bash(*cat {target}*)  (trailing wildcard: redirections change where "
        "the command ends)"
    ],
    "bash-compound-nested": [
        "Bash(*cat {target}*)  (leading wildcard covers the nested command)"
    ],
}

GENERAL_NOTE = (
    "Deny rules are enforced per tool: a Read(...) rule never blocks Grep or "
    "Bash. Secrets need matching rules on every tool family that can surface "
    "bytes (Read, Grep, Bash). Command-prefix blocklists (Bash(cat *)) are "
    "fragile -- new interpreters and flags appear constantly -- so prefer "
    "keeping secrets out of the working directory, or enforce with hooks."
)

EXPLOSIVE_NOTE = (
    "Explosive (trigger-based) injections are dormant by design: your deny "
    "rules never see the payload, only the actions it takes once triggered. "
    "Blocking every route below is the backstop. For the trigger half, use a "
    "PreToolUse hook that scans incoming context (pasted text, fetched pages, "
    "repo files) for trigger-shaped instructions -- deny rules cannot do that."
)


def suggest_explosive(finding, target: str) -> list[dict]:
    """Hardening suggestions for one EXPOSED explosive finding.

    One entry per open route, reusing the same rule templates as the main
    audit so the advice stays consistent.
    """
    from .routes import get_route

    recs = []
    for rid in finding.open_routes:
        route = get_route(rid)
        recs.append(
            {
                "route": rid,
                "route_name": route.name,
                "add_rules": suggest(route, target),
            }
        )
    return recs


def suggest(route: Route, target: str) -> list[str]:
    """Return concrete deny-rule suggestions that would HOLD this route."""
    templates = _SUGGESTIONS.get(route.id, [])
    return [t.replace("{target}", target) for t in templates]


def suggestions_for_leaks(findings, target: str) -> list[dict]:
    """Build a JSON-able recommendation list for LEAK findings on one target."""
    recs = []
    for f in findings:
        if f.target != target or f.verdict != "LEAK":
            continue
        recs.append(
            {
                "route": f.route.id,
                "route_name": f.route.name,
                "add_rules": suggest(f.route, target),
            }
        )
    return recs
