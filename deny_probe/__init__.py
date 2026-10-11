"""deny-probe: penetration tester for Claude Code permission deny rules."""

__version__ = "0.4.0"

from .analyzer import Finding, audit, summarize
from .explosive import (
    EXPOSED,
    SAFE,
    EXPLOSIVE_PROBES,
    ExplosiveFinding,
    ExplosiveProbe,
    audit_explosive,
    get_probe,
    summarize_explosive,
)
from .routes import ROUTES, Route, get_route
from .rules import DenyRule, parse_rules

__all__ = [
    "__version__",
    "DenyRule",
    "EXPOSED",
    "EXPLOSIVE_PROBES",
    "ExplosiveFinding",
    "ExplosiveProbe",
    "Finding",
    "ROUTES",
    "Route",
    "SAFE",
    "audit",
    "audit_explosive",
    "get_probe",
    "get_route",
    "parse_rules",
    "summarize",
    "summarize_explosive",
]
