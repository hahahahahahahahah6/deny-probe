"""deny-probe: penetration tester for Claude Code permission deny rules."""

__version__ = "0.2.0"

from .analyzer import Finding, audit, summarize
from .routes import ROUTES, Route, get_route
from .rules import DenyRule, parse_rules

__all__ = [
    "__version__",
    "DenyRule",
    "Finding",
    "ROUTES",
    "Route",
    "audit",
    "get_route",
    "parse_rules",
    "summarize",
]
