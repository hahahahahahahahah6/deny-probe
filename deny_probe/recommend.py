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
}

GENERAL_NOTE = (
    "Deny rules are enforced per tool: a Read(...) rule never blocks Grep or "
    "Bash. Secrets need matching rules on every tool family that can surface "
    "bytes (Read, Grep, Bash). Command-prefix blocklists (Bash(cat *)) are "
    "fragile -- new interpreters and flags appear constantly -- so prefer "
    "keeping secrets out of the working directory, or enforce with hooks."
)


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
