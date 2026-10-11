"""Smoke tests for the explosive-prompts (trigger-based injection) probe pack.

Fixture strategy: the pack is a *static model* -- for each trigger-based
injection we assert both halves of the story against canned deny configs:

  1. a naive deny config (e.g. only ``Read(./.env)``) leaves the triggered
     action EXPOSED -- deny-probe reproduces the miss;
  2. a hardened deny config that blocks every route the triggered action
     would use makes the probe SAFE.

No live model calls; every assertion is a static fixture.
"""

import json

import pytest

from deny_probe import (
    EXPOSED,
    SAFE,
    EXPLOSIVE_PROBES,
    audit_explosive,
    get_probe,
    summarize_explosive,
)
from deny_probe.cli import main
from deny_probe.recommend import suggest_explosive
from deny_probe.routes import get_route
from deny_probe.rules import parse_rules

TARGET = "./.env"


def findings(rules, target=TARGET):
    return {f.probe.id: f for f in audit_explosive(parse_rules(rules), target)}


# --- pack integrity ------------------------------------------------------


def test_probe_ids_unique():
    ids = [p.id for p in EXPLOSIVE_PROBES]
    assert len(ids) == len(set(ids))
    assert len(ids) >= 8


def test_every_probe_references_valid_routes():
    from deny_probe.routes import ROUTES

    valid = {r.id for r in ROUTES}
    for p in EXPLOSIVE_PROBES:
        assert p.routes, p.id
        assert set(p.routes) <= valid, p.id
        # sanity: the route actually exists and is fetchable
        for rid in p.routes:
            assert get_route(rid).id == rid


def test_every_probe_has_trigger_and_payload_fixture():
    kinds = set()
    for p in EXPLOSIVE_PROBES:
        assert p.trigger.strip(), p.id
        assert p.trigger_kind.strip(), p.id
        assert p.action.strip(), p.id
        assert p.description.strip(), p.id
        assert p.precondition.strip(), p.id
        assert "{target}" in p.dormant_text, p.id
        kinds.add(p.trigger_kind)
    # the pack should cover several distinct trigger shapes
    assert len(kinds) >= 5


def test_get_probe_lookup_and_unknown():
    assert get_probe("xp-keyword").name == "Keyword sleeper"
    with pytest.raises(KeyError):
        get_probe("no-such-probe")


def test_dormant_payload_substitution():
    p = get_probe("xp-keyword")
    payload = p.payload_for("./config/keys.json")
    assert "./config/keys.json" in payload
    assert "{target}" not in payload


# --- blocked fixtures: probe is SAFE --------------------------------------


def test_keyword_sleeper_blocked_by_bash_cat_rule():
    f = findings(["Bash(cat *)"])["xp-keyword"]
    assert f.verdict == SAFE
    assert f.open_routes == []
    assert f.route_verdicts == {"bash-cat": "HOLD"}


def test_file_presence_tripwire_blocked_by_read_rule():
    f = findings(["Read(./.env)"])["xp-file-presence"]
    assert f.verdict == SAFE
    assert f.route_verdicts == {"read-direct": "HOLD"}


def test_multi_route_probe_needs_every_route_blocked():
    # xp-obfuscated fires through bash-cat AND bash-grep.
    f = findings(["Bash(cat *)", "Bash(grep *)"])["xp-obfuscated"]
    assert f.verdict == SAFE
    # ...and xp-forged-context through bash-head AND bash-tail.
    f = findings(["Bash(head *)", "Bash(tail *)"])["xp-forged-context"]
    assert f.verdict == SAFE


def test_full_backstop_config_makes_every_probe_safe():
    rules = [
        "Read(./.env)",
        "Grep(./.env)",
        "Bash(cat *)",
        "Bash(grep *)",
        "Bash(sed *)",
        "Bash(head *)",
        "Bash(tail *)",
        "Bash(python *)",
        "Bash(python3 *)",
    ]
    fs = findings(rules)
    assert set(fs) == {p.id for p in EXPLOSIVE_PROBES}
    assert all(f.verdict == SAFE for f in fs.values())
    s = summarize_explosive(list(fs.values()))
    assert s == {"probes": len(EXPLOSIVE_PROBES), "exposed": 0, "safe": len(EXPLOSIVE_PROBES)}


# --- missed fixtures: probe is EXPOSED ------------------------------------


def test_naive_read_only_config_exposes_everything_but_file_presence():
    # The classic mistake: Read(./.env) and nothing else. The woken payload
    # never uses the Read tool, so every action-based probe is EXPOSED.
    fs = findings(["Read(./.env)"])
    for pid, f in fs.items():
        if pid == "xp-file-presence":
            assert f.verdict == SAFE, pid  # its action IS a Read
        else:
            assert f.verdict == EXPOSED, pid
            assert f.open_routes, pid


def test_keyword_sleeper_exposed_without_bash_cat_rule():
    f = findings(["Read(./.env)", "Bash(grep *)"])["xp-keyword"]
    assert f.verdict == EXPOSED
    assert f.open_routes == ["bash-cat"]
    assert f.route_verdicts == {"bash-cat": "LEAK"}


def test_partial_cover_still_exposed():
    # Blocking only one of the two routes of xp-obfuscated is not enough.
    f = findings(["Bash(cat *)"])["xp-obfuscated"]
    assert f.verdict == EXPOSED
    assert f.open_routes == ["bash-grep"]
    f = findings(["Bash(head *)"])["xp-forged-context"]
    assert f.verdict == EXPOSED
    assert f.open_routes == ["bash-tail"]


def test_branch_gated_payload_needs_python_rules():
    # Note: Bash(python *) alone does NOT match the python3 one-liner --
    # prefix blocklists are fragile, and the static model says so.
    f = findings(["Read(./.env)", "Bash(python *)", "Bash(python3 *)"])["xp-branch"]
    assert f.verdict == SAFE
    f = findings(["Read(./.env)"])["xp-branch"]
    assert f.verdict == EXPOSED
    assert f.open_routes == ["bash-python"]


def test_exposed_probe_yields_hardening_suggestions():
    f = findings(["Read(./.env)"])["xp-keyword"]
    recs = suggest_explosive(f, TARGET)
    assert len(recs) == 1
    assert recs[0]["route"] == "bash-cat"
    assert any("Bash(cat *)" in r for r in recs[0]["add_rules"])


def test_summarize_explosive_counts():
    fs = findings(["Read(./.env)"])
    s = summarize_explosive(list(fs.values()))
    assert s["probes"] == len(EXPLOSIVE_PROBES)
    assert s["exposed"] == len(EXPLOSIVE_PROBES) - 1
    assert s["safe"] == 1


# --- CLI ------------------------------------------------------------------


def test_cli_list_probes(capsys):
    assert main(["explosive", "--list"]) == 0
    out = capsys.readouterr().out
    assert "xp-keyword" in out
    assert "xp-obfuscated" in out


def test_cli_audit_exposed_exit_code(capsys):
    assert main(["explosive", "--deny", "Read(./.env)"]) == 1
    out = capsys.readouterr().out
    assert "EXPOSED" in out
    assert "Hardening suggestions" in out


def test_cli_audit_safe_exit_code(capsys):
    rules = [
        "Read(./.env)",
        "Grep(./.env)",
        "Bash(cat *)",
        "Bash(grep *)",
        "Bash(sed *)",
        "Bash(head *)",
        "Bash(tail *)",
        "Bash(python *)",
        "Bash(python3 *)",
    ]
    argv = ["explosive"]
    for r in rules:
        argv += ["--deny", r]
    assert main(argv) == 0
    out = capsys.readouterr().out
    assert "0/{} explosive probes exposed".format(len(EXPLOSIVE_PROBES)) in out


def test_cli_json_output_shape(capsys):
    assert main(["explosive", "--deny", "Read(./.env)", "--format", "json"]) == 1
    payload = json.loads(capsys.readouterr().out)
    assert len(payload["targets"]) == 1
    t = payload["targets"][0]
    assert t["summary"]["probes"] == len(EXPLOSIVE_PROBES)
    by_id = {f["probe"]: f for f in t["findings"]}
    kw = by_id["xp-keyword"]
    assert kw["verdict"] == EXPOSED
    assert kw["open_routes"] == ["bash-cat"]
    assert kw["trigger_kind"] == "keyword"
    assert "explosive_note" in payload
