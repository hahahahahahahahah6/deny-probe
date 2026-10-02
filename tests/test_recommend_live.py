"""Tests for hardening suggestions and the live-mode verdict helper."""

from deny_probe.analyzer import LEAK, audit
from deny_probe.live import check_output
from deny_probe.recommend import GENERAL_NOTE, suggest, suggestions_for_leaks
from deny_probe.routes import get_route
from deny_probe.rules import parse_rules


def test_suggest_grep_tool():
    assert suggest(get_route("grep-tool"), "./.env") == ["Grep(./.env)"]


def test_suggest_bash_python_covers_interpreters():
    got = suggest(get_route("bash-python"), "./.env")
    assert "Bash(python *)" in got
    assert "Bash(python3 *)" in got


def test_suggest_import_route():
    got = suggest(get_route("claude-md-import"), "./.env")
    assert "Read(./CLAUDE.md)" in got


def test_suggest_nested_claude_md():
    got = suggest(get_route("claude-md-nested"), "./.env")
    assert "Read(./**/CLAUDE.md)" in got


def test_suggest_uses_target_pattern():
    got = suggest(get_route("grep-tool"), "./secrets/**")
    assert got == ["Grep(./secrets/**)"]


def test_suggestions_for_leaks_only_lists_leaks():
    findings = audit(parse_rules(["Read(./.env)"]), ["./.env"])
    recs = suggestions_for_leaks(findings, "./.env")
    route_ids = {r["route"] for r in recs}
    assert "read-direct" not in route_ids  # it holds
    assert "bash-cat" in route_ids
    for r in recs:
        assert r["add_rules"], r["route"]


def test_general_note_mentions_per_tool_enforcement():
    assert "per tool" in GENERAL_NOTE


# --- live.check_output: pure function, safe to unit test ---


def test_check_output_finds_canary_in_answer():
    assert check_output("here is SECRET=abc123 done", "abc123") is True


def test_check_output_finds_canary_in_transcript_only():
    assert check_output("refused to help", "abc123", transcript_text='{"x":"abc123"}') is True


def test_check_output_absent():
    assert check_output("refused to help", "abc123") is False
    assert check_output("refused", "abc123", transcript_text="nothing here") is False
