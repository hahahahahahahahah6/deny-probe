"""Parsing and matching of Claude Code permission deny rules.

A deny rule looks like ``Read(./.env)`` or ``Bash(cat *)``: a tool name,
then a glob-ish pattern in parentheses. This module parses those rules and
tests whether a given tool argument would be blocked by them.

The matcher is an approximation of Claude Code's own permission matching:
``*`` matches within a path segment, ``**`` crosses segment boundaries,
``?`` matches a single non-separator character. It is intentionally
conservative and documented as such (see README "Honest limitations").
"""

from __future__ import annotations

import re
from dataclasses import dataclass

_RULE_RE = re.compile(r"^\s*([A-Za-z][A-Za-z0-9]*)\((.*)\)\s*$")

# Tools whose argument is a file path (as opposed to a command line).
_PATH_TOOLS = {"Read", "Grep", "Glob", "Edit", "Write", "NotebookRead"}


def _strip_dot_slash(path: str) -> str:
    if path.startswith("./"):
        return path[2:]
    return path


def _glob_to_regex(pattern: str, path_like: bool) -> str:
    """Translate a deny-rule glob pattern into a regex string (unanchored).

    For path tools (Read/Grep/Glob/...), ``*`` stays within one path
    segment and ``**`` crosses segments. For command tools (Bash), the
    argument is a command line, not a path, so ``*`` matches anything
    (including slashes and spaces).
    """
    p = _strip_dot_slash(pattern) if path_like else pattern
    # A trailing "/**" also matches the base directory itself.
    base_also = False
    if path_like and p.endswith("/**"):
        base_also = True
        p = p[:-3]

    out: list[str] = []
    i, n = 0, len(p)
    while i < n:
        c = p[i]
        if c == "*":
            j = i
            while j < n and p[j] == "*":
                j += 1
            if path_like and j - i >= 2:
                # "**": crosses path segments
                if j < n and p[j] == "/":
                    # "**/" -> zero or more path segments
                    out.append("(.*/)?")
                    i = j + 1
                else:
                    out.append(".*")
                    i = j
            elif path_like:
                # single "*": within one path segment only
                out.append("[^/]*")
                i = j
            else:
                # command line: "*" matches anything
                out.append(".*")
                i = j
        elif c == "?":
            out.append("[^/]" if path_like else ".")
            i += 1
        elif c == "[":
            end = p.find("]", i + 1)
            if end < 0:
                out.append(r"\[")
                i += 1
                continue
            content = p[i + 1 : end]
            negate = content.startswith(("!", "^"))
            if negate:
                content = content[1:]
            if not content:
                out.append(r"\[\]")
            else:
                # Preserve ranges while escaping characters with special
                # meaning inside a regex character class.
                safe = content.replace("\\", r"\\").replace("]", r"\]")
                if path_like and "/" not in safe:
                    safe += "/" if negate else ""
                out.append("[" + ("^" if negate else "") + safe + "]")
            i = end + 1
        else:
            out.append(re.escape(c))
            i += 1
    body = "".join(out)
    if base_also:
        return "(?:" + body + "(?:/.*)?)"
    return body


@dataclass(frozen=True)
class DenyRule:
    """A single parsed deny rule, e.g. ``Read(./.env)``."""

    tool: str
    pattern: str
    raw: str

    @classmethod
    def parse(cls, text: str) -> "DenyRule":
        """Parse ``Tool(pattern)``. Raises ValueError on malformed input."""
        m = _RULE_RE.match(text)
        if not m:
            raise ValueError(f"malformed deny rule: {text!r} (expected Tool(pattern))")
        tool, pattern = m.group(1), m.group(2)
        if not pattern:
            raise ValueError(f"malformed deny rule: {text!r} (empty pattern)")
        return cls(tool=tool, pattern=pattern, raw=text.strip())

    def matches(self, argument: str) -> bool:
        """Return True if this rule would block a tool call with ``argument``."""
        path_like = self.tool in _PATH_TOOLS
        arg = _strip_dot_slash(argument) if path_like else argument
        regex = _glob_to_regex(self.pattern, path_like)
        return re.fullmatch(regex, arg) is not None


def parse_rules(texts) -> list[DenyRule]:
    """Parse an iterable of rule strings, skipping blanks."""
    rules = []
    for t in texts:
        t = t.strip()
        if t:
            rules.append(DenyRule.parse(t))
    return rules
