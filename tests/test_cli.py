"""CLI end-to-end tests (static paths only; never invokes `claude`)."""

import json

import pytest

from deny_probe.cli import load_rules_from_settings, main


def test_audit_json_reports_leaks_and_exit_1(capsys):
    code = main(["audit", "--deny", "Read(./.env)", "--format", "json"])
    assert code == 1
    payload = json.loads(capsys.readouterr().out)
    t0 = payload["targets"][0]
    assert t0["target"] == "./.env"
    assert t0["summary"]["leak"] == 10
    by_route = {f["route"]: f for f in t0["findings"]}
    assert by_route["read-direct"]["verdict"] == "HOLD"
    assert by_route["bash-python"]["verdict"] == "LEAK"
    assert by_route["bash-python"]["blocking_rules"] == []
    assert t0["recommendations"], "leaks should come with suggestions"


def test_audit_hardened_exits_0(capsys):
    rules = [
        "Read(./.env)", "Grep(./.env)", "Glob(./.env)",
        "Bash(cat *)", "Bash(grep *)", "Bash(sed *)", "Bash(awk *)",
        "Bash(head *)", "Bash(tail *)", "Bash(python *)", "Bash(python3 *)",
        "Bash(perl *)", "Read(./CLAUDE.md)", "Read(./**/CLAUDE.md)",
    ]
    argv = ["audit", "--format", "json"]
    for r in rules:
        argv += ["--deny", r]
    assert main(argv) == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["targets"][0]["summary"] == {
        "routes": 12, "leak": 0, "hold": 12, "meta": 0,
    }


def test_audit_table_output(capsys):
    code = main(["audit", "--deny", "Read(./.env)"])
    assert code == 1
    out = capsys.readouterr().out
    assert "read-direct" in out and "HOLD" in out
    assert "bash-cat" in out and "LEAK" in out
    assert "Hardening suggestions" in out


def test_audit_no_rules_exits_2(capsys):
    assert main(["audit"]) == 2
    assert "no deny rules" in capsys.readouterr().err


def test_audit_malformed_rule_exits_2(capsys):
    assert main(["audit", "--deny", "not-a-rule"]) == 2


def test_routes_lists_library(capsys):
    assert main(["routes", "--format", "json"]) == 0
    data = json.loads(capsys.readouterr().out)
    assert len(data) == 12
    assert {d["id"] for d in data} >= {"read-direct", "bash-python", "claude-md-import"}


def test_load_rules_from_settings_json(tmp_path):
    settings = tmp_path / "settings.json"
    settings.write_text(json.dumps({"permissions": {"deny": ["Read(./.env)"]}}))
    assert load_rules_from_settings(str(settings)) == ["Read(./.env)"]


def test_load_rules_from_bare_list(tmp_path):
    settings = tmp_path / "rules.json"
    settings.write_text(json.dumps(["Read(./.env)"]))
    assert load_rules_from_settings(str(settings)) == ["Read(./.env)"]


def test_audit_with_settings_file(tmp_path, capsys):
    settings = tmp_path / "settings.json"
    settings.write_text(json.dumps({"permissions": {"deny": ["Read(./.env)"]}}))
    code = main(["audit", "--settings", str(settings), "--target", ".env", "--format", "json"])
    assert code == 1
    payload = json.loads(capsys.readouterr().out)
    # target normalization adds ./ prefix
    assert payload["targets"][0]["target"] == "./.env"


def test_live_unknown_route_exits_2(capsys):
    assert main(["live", "--route", "nope", "--runs", "1"]) == 2
