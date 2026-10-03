"""Fixture-based tests for the static HOLD/LEAK predictions.

These are the CI gate: given a fixed permission config, the predicted
verdict for every route must match the expected table. --live mode is
never exercised here (it shells out to `claude` and is nondeterministic).
"""

import pytest

from deny_probe.analyzer import HOLD, LEAK, META, audit, summarize
from deny_probe.routes import ROUTES
from deny_probe.rules import parse_rules

TARGET = "./.env"


def verdicts(rules, target=TARGET):
    findings = audit(parse_rules(rules), [target])
    return {f.route.id: f.verdict for f in findings}


# The classic misconfiguration: only Read is denied.
READ_ONLY = ["Read(./.env)"]

# A hardened config covering every tool family in the route library.
HARDENED = [
    "Read(./.env)",
    "Grep(./.env)",
    "Glob(./.env)",
    "Bash(cat *)",
    "Bash(grep *)",
    "Bash(sed *)",
    "Bash(awk *)",
    "Bash(head *)",
    "Bash(tail *)",
    "Bash(python *)",
    "Bash(python3 *)",
    "Bash(perl *)",
    "Read(./CLAUDE.md)",
    "Read(./**/CLAUDE.md)",
]


def test_read_only_deny_blocks_only_read():
    v = verdicts(READ_ONLY)
    assert v["read-direct"] == HOLD
    # Every content route through another tool leaks...
    for rid in (
        "grep-tool",
        "bash-cat",
        "bash-grep",
        "bash-sed",
        "bash-awk",
        "bash-head",
        "bash-tail",
        "bash-python",
        "bash-perl",
        "claude-md-import",
        "claude-md-nested",
    ):
        assert v[rid] == LEAK, rid
    # ...and Glob only leaks metadata.
    assert v["glob-tool"] == META


def test_read_only_summary_counts():
    findings = audit(parse_rules(READ_ONLY), [TARGET])
    s = summarize(findings)[TARGET]
    assert s["routes"] == len(ROUTES)
    assert s["leak"] == 11
    assert s["hold"] == 1
    assert s["meta"] == 1


def test_hardened_config_holds_everything():
    v = verdicts(HARDENED)
    assert set(v.values()) == {HOLD}


def test_blocking_rule_is_reported():
    findings = audit(parse_rules(READ_ONLY), [TARGET])
    f = next(x for x in findings if x.route.id == "read-direct")
    assert f.blocking_rules == ["Read(./.env)"]
    leaked = next(x for x in findings if x.route.id == "bash-cat")
    assert leaked.blocking_rules == []


def test_partial_hardening_still_leaks_python():
    # Blocking the classic readers but forgetting interpreters.
    v = verdicts(["Read(./.env)", "Bash(cat *)", "Bash(grep *)", "Bash(sed *)"])
    assert v["bash-cat"] == HOLD
    assert v["bash-grep"] == HOLD
    assert v["bash-sed"] == HOLD
    assert v["bash-python"] == LEAK
    assert v["bash-awk"] == LEAK


def test_recursive_pattern_covers_nested_target():
    v = verdicts(["Read(./secrets/**)"], target="./secrets/api.key")
    assert v["read-direct"] == HOLD
    assert v["grep-tool"] == LEAK  # Grep still uncovered


def test_recursive_pattern_does_not_cover_outside():
    v = verdicts(["Read(./secrets/**)"], target="./other.txt")
    assert v["read-direct"] == LEAK


def test_multiple_targets_are_independent():
    findings = audit(parse_rules(READ_ONLY), ["./.env", "./secrets/api.key"])
    by_target = {}
    for f in findings:
        by_target.setdefault(f.target, {})[f.route.id] = f.verdict
    assert by_target["./.env"]["read-direct"] == HOLD
    # ./secrets/api.key is not denied at all: even direct Read leaks.
    assert by_target["./secrets/api.key"]["read-direct"] == LEAK


def test_empty_rules_everything_leaks():
    v = verdicts([])
    assert v["read-direct"] == LEAK
    assert v["bash-cat"] == LEAK


def test_summarize_multiple_targets():
    findings = audit(parse_rules(HARDENED), ["./.env", "./other.txt"])
    s = summarize(findings)
    assert s["./.env"]["hold"] == len(ROUTES)
    # ./other.txt is not denied at all, but the CLAUDE.md import routes are
    # still covered (their argument doesn't depend on the target).
    assert s["./other.txt"]["leak"] == 2  # read-direct + grep-tool
    assert s["./other.txt"]["meta"] == 1
    assert s["./other.txt"]["hold"] == len(ROUTES) - 3
